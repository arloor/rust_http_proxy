use std::{
    collections::HashMap,
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use crate::{
    axum_handler::AppProxyError,
    config::Config,
    dns_resolver::CustomGaiDNSResolver,
    forward_proxy_client::ForwardProxyClient,
    location::{DEFAULT_HOST, LocationConfig, Upstream},
    mitm_manager::MitmManager,
};

use axum::extract::Request;
use axum_bootstrap::InterceptResult;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::{Method, Response, Version, body::Bytes};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{self, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use tokio::sync::broadcast;

#[cfg(debug_assertions)]
use super::connect::NoVerifier;
use super::http::{SchemeHostPort, extract_scheme_host_port};
#[cfg(debug_assertions)]
use log::warn;

#[allow(unused)]
use hyper_rustls::HttpsConnectorBuilder;

#[allow(dead_code)]
pub(crate) enum InterceptResultAdapter {
    Drop,
    Return(Response<BoxBody<Bytes, io::Error>>),
    Continue(Request<Incoming>),
}

/// 服务类型枚举
enum ServiceType<'a> {
    /// 反向代理
    ReverseProxy {
        original_scheme_host_port: SchemeHostPort,
        location: &'a String,
        upstream: &'a Upstream,
        basic_auth: &'a HashMap<String, String>,
        basic_auth_path_prefixes: &'a [String],
    },
    /// Location配置的静态文件托管
    LocationStaticServing {
        location: &'a String,
        static_dir: &'a String,
        basic_auth: &'a HashMap<String, String>,
        basic_auth_path_prefixes: &'a [String],
    },
    /// 正向代理
    ForwardProxy,
    NonMatch,
}

impl From<InterceptResultAdapter> for InterceptResult<AppProxyError> {
    fn from(val: InterceptResultAdapter) -> Self {
        match val {
            InterceptResultAdapter::Return(resp) => {
                let (parts, body) = resp.into_parts();
                axum_bootstrap::InterceptResult::Return(Response::from_parts(parts, axum::body::Body::new(body)))
            }
            InterceptResultAdapter::Drop => InterceptResult::Drop,
            InterceptResultAdapter::Continue(req) => InterceptResult::Continue(req),
        }
    }
}

pub(super) type ReverseProxyClient = legacy::Client<
    HttpsConnector<HttpConnector<CustomGaiDNSResolver>>,
    http_body_util::combinators::BoxBody<axum::body::Bytes, std::io::Error>,
>;

pub struct ProxyHandler {
    pub(super) config: Arc<Config>,
    pub(super) shutdown_tx: broadcast::Sender<()>,
    pub(super) forward_proxy_client: ForwardProxyClient<Incoming>,
    pub(super) mitm_proxy_client: ForwardProxyClient<BoxBody<Bytes, io::Error>>,
    pub(super) reverse_proxy_client: ReverseProxyClient,
    pub(super) mitm_manager: Arc<MitmManager>,
}

impl ProxyHandler {
    #[allow(clippy::expect_used)]
    pub fn new(
        config: Arc<Config>, mitm_manager: Arc<MitmManager>, shutdown_tx: broadcast::Sender<()>,
    ) -> Result<Self, crate::DynError> {
        let reverse_client = build_hyper_legacy_client(config.ipv6_first);
        let http1_client = ForwardProxyClient::<Incoming>::new();
        let mitm_client = ForwardProxyClient::<BoxBody<Bytes, io::Error>>::new();

        Ok(ProxyHandler {
            config,
            shutdown_tx,
            reverse_proxy_client: reverse_client,
            forward_proxy_client: http1_client,
            mitm_proxy_client: mitm_client,
            mitm_manager,
        })
    }

    pub async fn handle(
        &self, req: Request<hyper::body::Incoming>, client_socket_addr: SocketAddr,
    ) -> Result<InterceptResultAdapter, io::Error> {
        // 确定服务类型
        let service_type = self.determine_service_type(&req)?;

        // 根据服务类型分发处理
        service_type.handle(req, client_socket_addr, self).await
    }

    /// 确定服务类型
    fn determine_service_type(&'_ self, req: &Request<Incoming>) -> Result<ServiceType<'_>, io::Error> {
        if req.uri().host().is_none() && crate::mitm_web::is_management_path(req.uri().path()) {
            return Ok(ServiceType::NonMatch);
        }
        match (req.method(), req.version(), req.uri().host()) {
            // CONNECT 方法则判定为正向代理
            (&Method::CONNECT, _, _) => Ok(ServiceType::ForwardProxy),
            // HTTP1 且 url中有host则判定为正向代理
            (_, Version::HTTP_10 | Version::HTTP_11, Some(_)) => Ok(ServiceType::ForwardProxy),
            _ => {
                let (original_scheme_host_port, req_domain) = extract_scheme_host_port(
                    req,
                    match self.config.over_tls {
                        true => "https",
                        false => "http",
                    },
                )?;

                // 尝试找到匹配的 Location 配置
                let location_config_of_host = self.config.location_specs.locations.get(&req_domain.0).or(self
                    .config
                    .location_specs
                    .locations
                    .get(DEFAULT_HOST));

                match location_config_of_host.and_then(|locations| {
                    locations
                        .iter()
                        .find(|&ele| req.uri().path().starts_with(ele.location()))
                }) {
                    Some(LocationConfig::ReverseProxy {
                        location,
                        upstream,
                        basic_auth,
                        basic_auth_path_prefixes,
                        ..
                    }) => Ok(ServiceType::ReverseProxy {
                        original_scheme_host_port,
                        location,
                        upstream,
                        basic_auth,
                        basic_auth_path_prefixes,
                    }),
                    Some(LocationConfig::Serving {
                        static_dir,
                        location,
                        basic_auth,
                        basic_auth_path_prefixes,
                        ..
                    }) => Ok(ServiceType::LocationStaticServing {
                        location,
                        static_dir,
                        basic_auth,
                        basic_auth_path_prefixes,
                    }),
                    None => Ok(ServiceType::NonMatch),
                }
            }
        }

        // 默认为正向代理
    }
}

impl ServiceType<'_> {
    /// 处理请求
    async fn handle(
        &self, req: Request<Incoming>, client_socket_addr: SocketAddr, proxy_handler: &ProxyHandler,
    ) -> Result<InterceptResultAdapter, io::Error> {
        match self {
            ServiceType::NonMatch => {
                // 仍然检查allow_cidrs，避免漏到 axum router
                if let Err(e) = proxy_handler
                    .config
                    .allow_cidrs
                    .check_serving_control(client_socket_addr)
                {
                    return match e.kind() {
                        ErrorKind::PermissionDenied => Ok(InterceptResultAdapter::Drop),
                        _ => Err(e),
                    };
                }
                Ok(InterceptResultAdapter::Continue(req))
            }
            ServiceType::ReverseProxy {
                original_scheme_host_port,
                location,
                upstream,
                basic_auth,
                basic_auth_path_prefixes,
            } => {
                proxy_handler
                    .handle_reverse_proxy(
                        req,
                        client_socket_addr,
                        original_scheme_host_port,
                        location,
                        upstream,
                        basic_auth,
                        basic_auth_path_prefixes,
                    )
                    .await
            }
            ServiceType::LocationStaticServing {
                static_dir,
                location,
                basic_auth,
                basic_auth_path_prefixes,
            } => {
                proxy_handler
                    .handle_static_serving(
                        req,
                        client_socket_addr,
                        location,
                        static_dir,
                        basic_auth,
                        basic_auth_path_prefixes,
                    )
                    .await
            }
            ServiceType::ForwardProxy => proxy_handler.handle_forward_proxy(req, client_socket_addr).await,
        }
    }
}

#[allow(dead_code)]
fn build_hyper_legacy_client(ipv6_first: Option<bool>) -> ReverseProxyClient {
    let pool_idle_timeout = Duration::from_secs(90);
    // 创建自定义 DNS Resolver
    let resolver = crate::dns_resolver::CustomGaiDNSResolver::new(ipv6_first);
    let mut http_connector = HttpConnector::new_with_resolver(resolver);
    http_connector.enforce_http(false);
    http_connector.set_keepalive(Some(pool_idle_timeout));
    // 配置 Happy Eyeballs timeout 为 300ms
    http_connector.set_happy_eyeballs_timeout(Some(Duration::from_millis(300)));

    #[cfg(debug_assertions)]
    let https_connector = {
        warn!("⚠️  DEBUG MODE: TLS certificate verification is DISABLED");
        use tokio_rustls::rustls::ClientConfig;
        let tls_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(http_connector)
    };

    #[cfg(not(debug_assertions))]
    let https_connector = HttpsConnectorBuilder::new()
        .with_platform_verifier()
        .https_or_http()
        .enable_all_versions()
        .wrap_connector(http_connector);

    // 创建一个 HttpsConnector，使用 rustls 作为后端
    legacy::Client::builder(TokioExecutor::new())
        .pool_idle_timeout(pool_idle_timeout)
        .pool_max_idle_per_host(5)
        .pool_timer(hyper_util::rt::TokioTimer::new())
        .build(https_connector)
}
