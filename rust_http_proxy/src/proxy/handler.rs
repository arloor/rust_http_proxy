use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
};

use crate::{
    axum_handler::AppProxyError,
    config::Config,
    forward_proxy_client::ForwardProxyClient,
    location::{DEFAULT_HOST, LocationAuth, LocationConfig, Upstream},
    mitm_manager::MitmManager,
    reverse_proxy_client::ReverseProxyClient,
};

use axum::extract::Request;
use axum_bootstrap::InterceptResult;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::{Method, Response, Version, body::Bytes};
use tokio::sync::broadcast;

use super::http::{SchemeHostPort, extract_scheme_host_port};

pub(crate) enum InterceptResultAdapter {
    Drop,
    Return(Response<BoxBody<Bytes, io::Error>>),
    Continue(Request<Incoming>),
}

impl InterceptResultAdapter {
    pub(super) fn from_gate_error(error: io::Error) -> Result<Self, io::Error> {
        match error.kind() {
            ErrorKind::PermissionDenied => Ok(Self::Drop),
            _ => Err(error),
        }
    }
}

/// 服务类型枚举
enum ServiceType<'a> {
    /// 反向代理
    ReverseProxy {
        original_scheme_host_port: SchemeHostPort,
        location: &'a String,
        upstream: &'a Upstream,
        auth: &'a LocationAuth,
    },
    /// Location配置的静态文件托管
    LocationStaticServing {
        location: &'a String,
        static_dir: &'a String,
        auth: &'a LocationAuth,
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

pub struct ProxyHandler {
    pub(super) config: Arc<Config>,
    pub(super) shutdown_tx: broadcast::Sender<()>,
    pub(super) forward_proxy_client: ForwardProxyClient<Incoming>,
    pub(super) mitm_proxy_client: ForwardProxyClient<BoxBody<Bytes, io::Error>>,
    pub(super) reverse_proxy_http2_client: ReverseProxyClient<BoxBody<Bytes, io::Error>>,
    pub(super) reverse_proxy_http1_client: ReverseProxyClient<BoxBody<Bytes, io::Error>>,
    pub(super) mitm_manager: Arc<MitmManager>,
}

impl ProxyHandler {
    #[allow(clippy::expect_used)]
    pub fn new(
        config: Arc<Config>, mitm_manager: Arc<MitmManager>, shutdown_tx: broadcast::Sender<()>,
    ) -> Result<Self, crate::DynError> {
        let reverse_http2_client = ReverseProxyClient::new();
        let reverse_http1_client = ReverseProxyClient::new();
        let http1_client = ForwardProxyClient::<Incoming>::new();
        let mitm_client = ForwardProxyClient::<BoxBody<Bytes, io::Error>>::new();

        Ok(ProxyHandler {
            config,
            shutdown_tx,
            reverse_proxy_http2_client: reverse_http2_client,
            reverse_proxy_http1_client: reverse_http1_client,
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
                        auth,
                    }) => Ok(ServiceType::ReverseProxy {
                        original_scheme_host_port,
                        location,
                        upstream,
                        auth,
                    }),
                    Some(LocationConfig::Serving {
                        static_dir,
                        location,
                        auth,
                    }) => Ok(ServiceType::LocationStaticServing {
                        location,
                        static_dir,
                        auth,
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
                if let Err(error) = proxy_handler
                    .config
                    .allow_cidrs
                    .check_serving_control(client_socket_addr)
                {
                    return InterceptResultAdapter::from_gate_error(error);
                }
                Ok(InterceptResultAdapter::Continue(req))
            }
            ServiceType::ReverseProxy {
                original_scheme_host_port,
                location,
                upstream,
                auth,
            } => {
                proxy_handler
                    .handle_reverse_proxy(req, client_socket_addr, original_scheme_host_port, location, upstream, auth)
                    .await
            }
            ServiceType::LocationStaticServing {
                static_dir,
                location,
                auth,
            } => {
                proxy_handler
                    .handle_static_serving(req, client_socket_addr, location, static_dir, auth)
                    .await
            }
            ServiceType::ForwardProxy => proxy_handler.handle_forward_proxy(req, client_socket_addr).await,
        }
    }
}
