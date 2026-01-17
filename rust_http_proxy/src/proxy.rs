use std::{
    fmt::{Display, Formatter},
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::LazyLock,
    time::Duration,
};

use crate::{
    METRICS,
    address::host_addr,
    axum_handler::{self, AppProxyError},
    config::{Config, ForwardBypassConfig},
    dns_resolver::CustomGaiDNSResolver,
    forward_proxy_client::ForwardProxyClient,
    ip_x::local_ip,
    location::{DEFAULT_HOST, LocationConfig, RequestSpec, Upstream},
};
use {io_x::CounterIO, io_x::TimeoutIO, prom_label::LabelImpl};

use axum::extract::Request;
use axum_bootstrap::InterceptResult;
use http::{Uri, header::HOST};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::{Method, Response, Version, body::Bytes, header::HeaderValue, http, upgrade::Upgraded};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{self, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use log::{debug, info, warn};
use prometheus_client::encoding::EncodeLabelSet;
use rand::Rng;
use std::sync::Arc;

use tokio::{net::TcpStream, pin};
use tokio_rustls::TlsConnector;
use tokio_rustls::{client::TlsStream, rustls::pki_types};

static LOCAL_IP: LazyLock<String> = LazyLock::new(|| local_ip().unwrap_or("0.0.0.0".to_string()));

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
    },
    /// Location配置的静态文件托管
    LocationStaticServing {
        location: &'a String,
        static_dir: &'a String,
    },
    /// 正向代理
    ForwardProxy,
    NonMatch,
}

impl<'a> ServiceType<'a> {
    /// 处理请求
    async fn handle(
        &self, req: Request<Incoming>, client_socket_addr: SocketAddr, proxy_handler: &ProxyHandler, config: &Config,
    ) -> Result<InterceptResultAdapter, io::Error> {
        match self {
            ServiceType::NonMatch => Ok(InterceptResultAdapter::Continue(req)),
            ServiceType::ReverseProxy {
                original_scheme_host_port,
                location,
                upstream,
            } => {
                let res = RequestSpec::ForReverseProxy {
                    request: Box::new(req),
                    client_socket_addr,
                    original_scheme_host_port,
                    location,
                    upstream,
                    reverse_client: &proxy_handler.reverse_proxy_client,
                    config,
                }
                .handle()
                .await;
                match res {
                    Ok(resp) => Ok(InterceptResultAdapter::Return(resp)),
                    Err(e) => match e.kind() {
                        ErrorKind::PermissionDenied => Ok(InterceptResultAdapter::Drop),
                        _ => Err(e),
                    },
                }
            }
            ServiceType::LocationStaticServing { static_dir, location } => {
                let res = RequestSpec::ForServing {
                    request: &req,
                    client_socket_addr,
                    location,
                    static_dir,
                    config,
                }
                .handle()
                .await;
                match res {
                    Ok(resp) => {
                        if resp.status() == http::StatusCode::NOT_FOUND {
                            Ok(InterceptResultAdapter::Continue(req))
                        } else {
                            Ok(InterceptResultAdapter::Return(resp))
                        }
                    }
                    Err(e) => match e.kind() {
                        ErrorKind::PermissionDenied => Ok(InterceptResultAdapter::Drop),
                        _ => Err(e),
                    },
                }
            }
            ServiceType::ForwardProxy => {
                let config_basic_auth = &config.basic_auth;
                let never_ask_for_auth = config.never_ask_for_auth;

                match axum_handler::check_auth(req.headers(), http::header::PROXY_AUTHORIZATION, config_basic_auth) {
                    Ok(username_option) => {
                        let username = username_option.unwrap_or("unknown".to_owned());
                        info!(
                            "{:>29} {:<5} {:^8} {:^7} {:?} {:?} {} {}",
                            "https://ip.im/".to_owned() + &client_socket_addr.ip().to_canonical().to_string(),
                            client_socket_addr.port(),
                            username,
                            req.method().as_str(),
                            req.uri(),
                            req.version(),
                            req.headers()
                                .get("X-Forwarded-For")
                                .map(|v| {
                                    // 取 X-Forwarded-For 中以逗号分隔的第一个 IP，并去除空白
                                    let first_ip = v
                                        .to_str()
                                        .unwrap_or("invalid utf8")
                                        .split(',')
                                        .next()
                                        .unwrap_or("invalid utf8")
                                        .trim();
                                    format!("X-Forwarded-For: https://ip.im/{}", first_ip)
                                })
                                .unwrap_or_default(),
                            match &config.forward_bypass {
                                Some(bypass) => {
                                    format!("bypass: {}", bypass)
                                }
                                None => "".to_owned(),
                            }
                        );

                        match *req.method() {
                            Method::CONNECT => match config.forward_bypass.as_ref() {
                                Some(forward_bypass_config) => {
                                    let result = proxy_handler
                                        .tunnel_proxy_bypass(req, client_socket_addr, username, forward_bypass_config)
                                        .await;
                                    result.map(InterceptResultAdapter::Return)
                                }
                                None => proxy_handler
                                    .tunnel_proxy(req, client_socket_addr, username)
                                    .map(InterceptResultAdapter::Return),
                            },
                            _ => match config.forward_bypass.as_ref() {
                                Some(forward_bypass_config) => {
                                    let result = proxy_handler
                                        .simple_proxy_bypass(req, client_socket_addr, username, forward_bypass_config)
                                        .await;
                                    result.map(InterceptResultAdapter::Return)
                                }
                                None => proxy_handler
                                    .simple_proxy(req, client_socket_addr, username)
                                    .await
                                    .map(InterceptResultAdapter::Return),
                            },
                        }
                    }
                    Err(e) => {
                        warn!("auth check from {} error: {}", { client_socket_addr }, e);
                        if never_ask_for_auth {
                            Err(io::Error::new(ErrorKind::PermissionDenied, "wrong basic auth, closing socket..."))
                        } else {
                            Ok(InterceptResultAdapter::Return(build_authenticate_resp(true)))
                        }
                    }
                }
            }
        }
    }
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
    config: Arc<Config>,
    forward_proxy_client: ForwardProxyClient<Incoming>,
    reverse_proxy_client: legacy::Client<
        HttpsConnector<HttpConnector<CustomGaiDNSResolver>>,
        http_body_util::combinators::BoxBody<axum::body::Bytes, std::io::Error>,
    >,
}

#[allow(unused)]
use hyper_rustls::HttpsConnectorBuilder;
#[allow(unused)]
fn reverse_proxy_label_fn(uri: &Uri) -> prom_label::LabelImpl<AccessLabel> {
    prom_label::LabelImpl::new(AccessLabel {
        client: "reverse_proxy".to_owned(),
        target: uri.authority().map(|a| a.to_string()).unwrap_or_default(),
        username: "reverse_proxy".to_owned(),
        relay_over_tls: None,
    })
}

impl ProxyHandler {
    #[allow(clippy::expect_used)]
    pub fn new(config: Arc<Config>) -> Result<Self, crate::DynError> {
        let reverse_client = build_hyper_legacy_client(config.ipv6_first);
        let http1_client = ForwardProxyClient::<Incoming>::new();

        Ok(ProxyHandler {
            config,
            reverse_proxy_client: reverse_client,
            forward_proxy_client: http1_client,
        })
    }
    pub async fn handle(
        &self, req: Request<hyper::body::Incoming>, client_socket_addr: SocketAddr,
    ) -> Result<InterceptResultAdapter, io::Error> {
        // 确定服务类型
        let service_type = self.determine_service_type(&req)?;

        // 根据服务类型分发处理
        service_type.handle(req, client_socket_addr, self, &self.config).await
    }

    /// 确定服务类型
    fn determine_service_type(&'_ self, req: &Request<Incoming>) -> Result<ServiceType<'_>, io::Error> {
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
                    Some(LocationConfig::ReverseProxy { location, upstream }) => Ok(ServiceType::ReverseProxy {
                        original_scheme_host_port,
                        location,
                        upstream,
                    }),
                    Some(LocationConfig::Serving { static_dir, location }) => {
                        Ok(ServiceType::LocationStaticServing { location, static_dir })
                    }
                    None => Ok(ServiceType::NonMatch),
                }
            }
        }

        // 默认为正向代理
    }

    /// 处理 WebSocket 升级请求（正向代理场景）
    async fn handle_websocket_upgrade_forward(
        &self, mut req: Request<Incoming>, traffic_label: AccessLabel,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        info!("[forward] WebSocket upgrade request to {}", &traffic_label.target);

        // 在消费 request 之前先获取客户端的 upgrade future
        let client_upgrade = hyper::upgrade::on(&mut req);

        // 使用 send_request_no_cache 发送请求
        let mut upstream_response = self
            .forward_proxy_client
            .send_request_no_cache(
                req,
                &traffic_label,
                self.config.ipv6_first,
                |stream: EitherTlsStream, access_label: AccessLabel| {
                    CounterIO::new(stream, METRICS.proxy_traffic.clone(), LabelImpl::new(access_label))
                },
            )
            .await?;

        // 检查响应状态码
        if upstream_response.status() != http::StatusCode::SWITCHING_PROTOCOLS {
            warn!("[forward] WebSocket upgrade failed, upstream returned: {}", upstream_response.status());
            return Err(io::Error::other(format!("WebSocket upgrade failed: {}", upstream_response.status())));
        }

        info!("[forward] WebSocket upgrade successful, status: {}", upstream_response.status());

        // 获取上游的 upgrade future
        let upstream_upgrade = hyper::upgrade::on(&mut upstream_response);

        // 构造 101 响应给客户端，复制上游返回的响应头
        let mut response_builder = Response::builder().status(http::StatusCode::SWITCHING_PROTOCOLS);
        for (name, value) in upstream_response.headers() {
            response_builder = response_builder.header(name, value);
        }

        let client_response = response_builder
            .body(http_body_util::Empty::<Bytes>::new().map_err(|e| match e {}).boxed())
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;

        // 启动异步任务进行双向数据转发
        tokio::spawn(async move {
            match client_upgrade.await {
                Ok(client_upgraded) => match upstream_upgrade.await {
                    Ok(upstream_upgraded) => {
                        if let Err(e) =
                            Self::tunnel_websocket_forward_upgraded(client_upgraded, upstream_upgraded).await
                        {
                            warn!("[forward] WebSocket tunnel error: {e:?}");
                        }
                    }
                    Err(e) => {
                        warn!("[forward] WebSocket upstream upgrade error: {e:?}");
                    }
                },
                Err(e) => {
                    warn!("[forward] WebSocket client upgrade error: {e:?}");
                }
            }
        });

        Ok(client_response)
    }

    /// WebSocket 双向数据转发（正向代理场景）- Upgraded 版本
    async fn tunnel_websocket_forward_upgraded(client: Upgraded, upstream: Upgraded) -> io::Result<()> {
        let mut client_io = TokioIo::new(client);
        let mut upstream_io = TokioIo::new(upstream);

        // 双向数据转发
        let _ = tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await?;

        Ok(())
    }

    /// 代理普通请求
    /// HTTP/1.1 GET/POST/PUT/DELETE/HEAD
    async fn simple_proxy(
        &self, mut req: Request<Incoming>, client_socket_addr: SocketAddr, username: String,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        let addr = host_addr(req.uri())
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, format!("URI missing host: {}", req.uri())))?;
        let access_label = AccessLabel {
            client: client_socket_addr.ip().to_canonical().to_string(),
            target: addr.to_string(),
            username,
            relay_over_tls: None,
        };

        // 先检测是否是 WebSocket 升级请求（在 request 被消费之前）
        let is_websocket = req
            .headers()
            .get(http::header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);

        mod_http1_proxy_req(&mut req)?;
        if is_websocket {
            info!(
                "[forward] WebSocket upgrade request: {:^35} ==> {} {:?}",
                client_socket_addr.to_string(),
                req.method(),
                req.uri(),
            );

            return self.handle_websocket_upgrade_forward(req, access_label).await;
        }

        match self
            .forward_proxy_client
            .send_request(
                req,
                &access_label,
                self.config.ipv6_first,
                |stream: EitherTlsStream, access_label: AccessLabel| {
                    CounterIO::new(stream, METRICS.proxy_traffic.clone(), LabelImpl::new(access_label))
                },
            )
            .await
        {
            Ok(resp) => Ok(resp.map(|body| {
                body.map_err(|e| {
                    let e = e;
                    io::Error::new(ErrorKind::InvalidData, e)
                })
                .boxed()
            })),
            Err(e) => Err(e),
        }
    }

    async fn simple_proxy_bypass(
        &self, mut req: Request<Incoming>, client_socket_addr: SocketAddr, username: String,
        forward_bypass_config: &ForwardBypassConfig,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        let host = format!("{}:{}", forward_bypass_config.host, forward_bypass_config.port);
        let access_label = AccessLabel {
            client: client_socket_addr.ip().to_canonical().to_string(),
            target: host.clone(),
            username,
            relay_over_tls: Some(forward_bypass_config.is_https),
        };

        // 先检测是否是 WebSocket 升级请求（在 request 被消费之前）
        let is_websocket = req
            .headers()
            .get(http::header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);

        // 如果配置了 username 和 password，添加 Proxy-Authorization 头
        if let (Some(username), Some(password)) = (&forward_bypass_config.username, &forward_bypass_config.password) {
            let credentials = format!("{}:{}", username, password);
            let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, credentials.as_bytes());
            if let Some(original) = req.headers_mut().insert(
                http::header::PROXY_AUTHORIZATION,
                HeaderValue::from_str(format!("Basic {}", encoded).as_str())
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
            ) {
                info!("change Proxy-Authorization header: {original:?} -> \"Basic {}\"", encoded);
            };
        }
        // 替换host头
        let host_header = HeaderValue::from_str(&host).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        let origin = req.headers_mut().insert(HOST, host_header.clone());
        if Some(host_header.clone()) != origin {
            info!("change host header: {origin:?} -> {host_header:?}");
        }

        if is_websocket {
            info!(
                "[forward_bypass] WebSocket upgrade request: {:^35} ==> {} {:?}",
                client_socket_addr.to_string(),
                req.method(),
                req.uri(),
            );

            return self.handle_websocket_upgrade_forward(req, access_label).await;
        }

        warn!("bypass {:?} {} {}", req.version(), req.method(), req.uri());

        match self
            .forward_proxy_client
            .send_request(
                req,
                &access_label,
                forward_bypass_config.ipv6_first,
                |stream: EitherTlsStream, access_label: AccessLabel| {
                    CounterIO::new(stream, METRICS.proxy_traffic.clone(), LabelImpl::new(access_label))
                },
            )
            .await
        {
            Ok(resp) => Ok(resp.map(|body| {
                body.map_err(|e| {
                    let e = e;
                    io::Error::new(ErrorKind::InvalidData, e)
                })
                .boxed()
            })),
            Err(e) => {
                warn!("[forward_bypass simple_proxy error] [{}]: [{}] {} ", access_label, e.kind(), e);
                Err(e)
            }
        }
    }

    async fn tunnel_proxy_bypass(
        &self, req: Request<Incoming>, client_socket_addr: SocketAddr, username: String,
        forward_bypass_config: &ForwardBypassConfig,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        // 开始计时
        let start_time = std::time::Instant::now();
        let proxy_traffic = METRICS.proxy_traffic.clone();

        match host_addr(req.uri()) {
            None => {
                warn!("CONNECT host is not socket addr: {:?}", req.uri());
                let mut resp = Response::new(full_body("CONNECT must be to a socket address"));
                *resp.status_mut() = http::StatusCode::BAD_REQUEST;
                Ok(resp)
            }
            Some(addr) => {
                let bypass_host = format!("{}:{}", forward_bypass_config.host, forward_bypass_config.port);
                let access_label = AccessLabel {
                    client: client_socket_addr.ip().to_canonical().to_string(),
                    target: bypass_host.clone(),
                    username,
                    relay_over_tls: Some(forward_bypass_config.is_https),
                };

                // 首先建立 TCP 连接
                let tcp_stream = match connect_with_preference(&bypass_host, forward_bypass_config.ipv6_first).await {
                    Ok(stream) => {
                        // 记录从接收请求到完成bypass握手的耗时
                        let duration = start_time.elapsed();
                        METRICS
                            .tunnel_bypass_setup_duration
                            .get_or_create(&LabelImpl::new(TunnelHandshakeLabel {
                                target: access_label.target.clone(),
                            }))
                            .observe(duration.as_millis() as f64);
                        stream
                    }
                    Err(e) => {
                        warn!("[forward_bypass tunnel establish error] [{}]: [{}] {} ", access_label, e.kind(), e);
                        let mut resp = Response::new(full_body("Failed to connect to bypass server"));
                        *resp.status_mut() = http::StatusCode::BAD_GATEWAY;
                        return Ok(resp);
                    }
                };

                debug!(
                    "[forward_bypass tunnel {}], [true path: {} -> {}]",
                    access_label,
                    client_socket_addr.ip().to_canonical().to_string() + ":" + &client_socket_addr.port().to_string(),
                    tcp_stream
                        .peer_addr()
                        .map(|addr| addr.ip().to_canonical().to_string() + ":" + &addr.port().to_string())
                        .unwrap_or("failed".to_owned())
                );
                let access_tag = access_label.to_string();

                // 根据 is_https 决定是否建立 TLS 连接，然后统一处理
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

                let stream = if forward_bypass_config.is_https {
                    // 建立 TLS 连接
                    let connector = build_tls_connector();
                    // 需要 clone host 以避免生命周期问题
                    let host = forward_bypass_config.host.clone();
                    let server_name = pki_types::ServerName::try_from(host.as_str())
                        .map_err(|e| io::Error::new(ErrorKind::InvalidInput, format!("Invalid DNS name: {}", e)))?
                        .to_owned();

                    match connector.connect(server_name, tcp_stream).await {
                        Ok(tls_stream) => EitherTlsStream::Tls { stream: tls_stream },
                        Err(e) => {
                            warn!("[forward_bypass TLS handshake error] [{}]: {}", access_tag, e);
                            let mut resp =
                                Response::new(full_body("Failed to establish TLS connection to bypass server"));
                            *resp.status_mut() = http::StatusCode::BAD_GATEWAY;
                            return Ok(resp);
                        }
                    }
                } else {
                    // 使用普通 TCP 连接
                    EitherTlsStream::Tcp { stream: tcp_stream }
                };

                // 统一处理流
                let dst_stream = CounterIO::new(stream, proxy_traffic.clone(), LabelImpl::new(access_label.clone()));
                let mut reader = tokio::io::BufReader::new(dst_stream);

                // 向bypass服务器发送CONNECT请求
                let client_ip = get_client_ip(&req, client_socket_addr);
                let mut connect_request =
                    format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\nX-Forwarded-For: {}\r\n", addr, addr, client_ip);

                // 如果配置了 username 和 password，添加 Proxy-Authorization 头
                if let (Some(username), Some(password)) =
                    (&forward_bypass_config.username, &forward_bypass_config.password)
                {
                    let credentials = format!("{}:{}", username, password);
                    let encoded =
                        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, credentials.as_bytes());
                    connect_request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
                }

                connect_request.push_str("\r\n");

                if let Err(e) = reader.get_mut().write_all(connect_request.as_bytes()).await {
                    warn!("[forward_bypass write CONNECT error] [{}]: {}", access_tag, e);
                    return Err(io::Error::other(e));
                }

                // 读取bypass服务器的响应（应该是200 OK）
                let mut response_line = String::new();
                if let Err(e) = reader.read_line(&mut response_line).await {
                    warn!("[forward_bypass read response error] [{}]: {}", access_tag, e);
                    return Err(io::Error::other(e));
                }

                // 检查响应是否是200
                let status_code = response_line.split_whitespace().nth(1).unwrap_or("");
                if status_code != "200" {
                    warn!("[forward_bypass unexpected response] [{}]: {}", access_tag, response_line);
                    return Err(io::Error::other("unexpected response from bypass server"));
                }

                // 读取并丢弃响应头直到空行
                loop {
                    let mut header_line = String::new();
                    if let Err(e) = reader.read_line(&mut header_line).await {
                        warn!("[forward_bypass read header error] [{}]: {}", access_tag, e);
                        return Err(io::Error::other("unexpected response from bypass server"));
                    }
                    if header_line == "\r\n" || header_line == "\n" {
                        break;
                    }
                }

                // 从BufReader中取回原始stream
                let dst_stream = reader.into_inner();

                tokio::task::spawn(async move {
                    let src_upgraded = match hyper::upgrade::on(req).await {
                        Ok(src_upgraded) => src_upgraded,
                        Err(e) => {
                            warn!("[forward_bypass upgrade error] [{}]: {}", access_tag, e);
                            return Err(io::Error::other(e));
                        }
                    };

                    if let Err(e) = tunnel(src_upgraded, dst_stream).await {
                        warn!("[forward_bypass tunnel io error] [{}]: [{}] {} ", access_tag, e.kind(), e);
                    };
                    Ok(())
                });
                let mut response = Response::new(empty_body());
                // 添加随机长度的padding
                let max_num = 2048 / LOCAL_IP.len();
                let count = rand::rng().random_range(1..max_num);
                for _ in 0..count {
                    response
                        .headers_mut()
                        .append(http::header::SERVER, HeaderValue::from_static(&LOCAL_IP));
                }
                Ok(response)
            }
        }
    }

    /// 代理CONNECT请求
    /// HTTP/1.1 CONNECT    
    fn tunnel_proxy(
        &self, req: Request<Incoming>, client_socket_addr: SocketAddr, username: String,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        // 开始计时
        let start_time = std::time::Instant::now();
        // Received an HTTP request like:
        // ```
        // CONNECT www.domain.com:443 HTTP/1.1
        // Host: www.domain.com:443
        // Proxy-Connection: Keep-Alive
        // ```
        //
        // When HTTP method is CONNECT we should return an empty body
        // then we can eventually upgrade the connection and talk a new protocol.
        //
        // Note: only after client received an empty body with STATUS_OK can the
        // connection be upgraded, so we can't return a response inside
        // `on_upgrade` future.
        if let Some(addr) = host_addr(req.uri()) {
            let proxy_traffic = METRICS.proxy_traffic.clone();
            let ipv6_first = self.config.ipv6_first;
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(src_upgraded) => {
                        let access_label = AccessLabel {
                            client: client_socket_addr.ip().to_canonical().to_string(),
                            target: addr.clone().to_string(),
                            username,
                            relay_over_tls: None,
                        };
                        // Connect to remote server
                        match connect_with_preference(&addr.to_string(), ipv6_first).await {
                            Ok(target_stream) => {
                                // 记录从接收请求到成功建立连接的耗时
                                let duration = start_time.elapsed();
                                METRICS
                                    .tunnel_bypass_setup_duration
                                    .get_or_create(&LabelImpl::new(TunnelHandshakeLabel {
                                        target: access_label.target.clone(),
                                    }))
                                    .observe(duration.as_millis() as f64);

                                // if the DST server did not respond the FIN(shutdown) from the SRC client, then you will see a pair of FIN-WAIT-2 and CLOSE_WAIT in the proxy server
                                // which two socketAddrs are in the true path.
                                // use this command to check:
                                // netstat -ntp|grep -E "CLOSE_WAIT|FIN_WAIT"|sort
                                // The DST server should answer for this problem, becasue it ignores the FIN
                                // Dont worry, after the FIN_WAIT_2 timeout, the CLOSE_WAIT connection will close.
                                debug!(
                                    "[tunnel {}], [true path: {} -> {}]",
                                    access_label,
                                    client_socket_addr.ip().to_canonical().to_string()
                                        + ":"
                                        + &client_socket_addr.port().to_string(),
                                    target_stream
                                        .peer_addr()
                                        .map(|addr| addr.ip().to_canonical().to_string()
                                            + ":"
                                            + &addr.port().to_string())
                                        .unwrap_or("failed".to_owned())
                                );
                                let access_tag = access_label.to_string();
                                let dst_stream =
                                    CounterIO::new(target_stream, proxy_traffic, LabelImpl::new(access_label));
                                if let Err(e) = tunnel(src_upgraded, dst_stream).await {
                                    warn!("[tunnel io error] [{}]: [{}] {} ", access_tag, e.kind(), e);
                                };
                            }
                            Err(e) => {
                                warn!("[tunnel establish error] [{}]: [{}] {} ", access_label, e.kind(), e)
                            }
                        }
                    }
                    Err(e) => warn!("upgrade error: {e}"),
                }
            });
            let mut response = Response::new(empty_body());
            // 针对connect请求中，在响应中增加随机长度的padding，防止每次建连时tcp数据长度特征过于敏感
            let max_num = 2048 / LOCAL_IP.len();
            let count = rand::rng().random_range(1..max_num);
            for _ in 0..count {
                response
                    .headers_mut()
                    .append(http::header::SERVER, HeaderValue::from_static(&LOCAL_IP));
            }
            Ok(response)
        } else {
            warn!("CONNECT host is not socket addr: {:?}", req.uri());
            let mut resp = Response::new(full_body("CONNECT must be to a socket address"));
            *resp.status_mut() = http::StatusCode::BAD_REQUEST;

            Ok(resp)
        }
    }
}

fn mod_http1_proxy_req(req: &mut Request<Incoming>) -> io::Result<()> {
    // 删除代理特有的请求头
    req.headers_mut().remove(http::header::PROXY_AUTHORIZATION.to_string());
    req.headers_mut().remove("Proxy-Connection");
    // set host header
    let uri = req.uri().clone();
    let hostname = uri
        .host()
        .ok_or(io::Error::new(ErrorKind::InvalidData, "host is absent in HTTP/1.1"))?;
    let host_header = if let Some(port) = match (uri.port().map(|p| p.as_u16()), is_schema_secure(&uri)) {
        (Some(443), true) => None,
        (Some(80), false) => None,
        _ => uri.port(),
    } {
        let s = format!("{hostname}:{port}");
        HeaderValue::from_str(&s)
    } else {
        HeaderValue::from_str(hostname)
    }
    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    let origin = req.headers_mut().insert(HOST, host_header.clone());
    if Some(host_header.clone()) != origin {
        info!("change host header: {origin:?} -> {host_header:?}");
    }
    // change absoulte uri to relative uri
    origin_form(req.uri_mut())?;
    Ok(())
}

pub(crate) struct SchemeHostPort {
    pub(crate) scheme: String,
    pub(crate) host: String,
    pub(crate) port: Option<u16>,
}

impl Display for SchemeHostPort {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.port {
            Some(port) => write!(f, "{}://{}:{}", self.scheme, self.host, port),
            None => write!(f, "{}://{}", self.scheme, self.host),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct RequestDomain(String);

fn extract_scheme_host_port(
    req: &Request<Incoming>, default_scheme: &str,
) -> io::Result<(SchemeHostPort, RequestDomain)> {
    let uri = req.uri();
    let scheme = uri.scheme_str().unwrap_or(default_scheme);
    if req.version() == Version::HTTP_2 {
        //H2，信息全在uri中
        let host_in_url = uri
            .host()
            .ok_or(io::Error::new(ErrorKind::InvalidData, "authority is absent in HTTP/2"))?
            .to_string();
        let host_in_header = req
            .headers()
            .get(http::header::HOST)
            .and_then(|host| host.to_str().ok())
            .and_then(|host_str| host_str.split(':').next())
            .map(str::to_string);
        Ok((
            SchemeHostPort {
                scheme: scheme.to_owned(),
                host: host_in_url.clone(),
                port: uri.port_u16(),
            },
            RequestDomain(match host_in_header {
                Some(host) => host,  // 优先使用H2协议的Host头
                None => host_in_url, // 其次使用H2协议的uri中的host
            }),
        ))
    } else {
        let mut split = req
            .headers()
            .get(http::header::HOST)
            .ok_or(io::Error::new(ErrorKind::InvalidData, "Host Header is absent in HTTP/1.1"))?
            .to_str()
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?
            .split(':');
        let host = split
            .next()
            .ok_or(io::Error::new(ErrorKind::InvalidData, "host not in header"))?
            .to_string();
        let port = match split.next() {
            Some(port) => Some(
                port.parse::<u16>()
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
            ),
            None => None,
        };
        Ok((
            SchemeHostPort {
                scheme: scheme.to_owned(),
                host: host.clone(),
                port,
            },
            RequestDomain(host),
        ))
    }
}

fn is_schema_secure(uri: &Uri) -> bool {
    uri.scheme_str()
        .map(|scheme_str| matches!(scheme_str, "wss" | "https"))
        .unwrap_or_default()
}

#[allow(dead_code)]
fn build_hyper_legacy_client(
    ipv6_first: Option<bool>,
) -> legacy::Client<
    hyper_rustls::HttpsConnector<HttpConnector<CustomGaiDNSResolver>>,
    http_body_util::combinators::BoxBody<axum::body::Bytes, std::io::Error>,
> {
    let pool_idle_timeout = Duration::from_secs(90);
    // 创建自定义 DNS Resolver
    let resolver = CustomGaiDNSResolver::new(ipv6_first);
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
    let client: legacy::Client<
        hyper_rustls::HttpsConnector<HttpConnector<CustomGaiDNSResolver>>,
        http_body_util::combinators::BoxBody<axum::body::Bytes, std::io::Error>,
    > = legacy::Client::builder(TokioExecutor::new())
        .pool_idle_timeout(pool_idle_timeout)
        .pool_max_idle_per_host(5)
        .pool_timer(hyper_util::rt::TokioTimer::new())
        .build(https_connector);
    client
}

/// 实现 Happy Eyeballs 算法的TCP连接（RFC 6555, RFC 8305）
/// 首先尝试解析所有地址，根据 ipv6_first 参数决定优先级，但会并发尝试以提高连接速度
/// ipv6_first: None 表示使用系统默认顺序，Some(true) 表示 IPv6 优先，Some(false) 表示 IPv4 优先
pub(crate) async fn connect_with_preference(addr: &str, ipv6_first: Option<bool>) -> io::Result<TcpStream> {
    use std::time::Duration;
    use tokio::net::lookup_host;

    // 解析所有地址
    let addrs: Vec<SocketAddr> = lookup_host(addr).await?.collect();

    if addrs.is_empty() {
        return Err(io::Error::new(ErrorKind::InvalidInput, "No addresses found"));
    }

    // 分离IPv4和IPv6地址
    let mut v4_addrs = Vec::new();
    let mut v6_addrs = Vec::new();

    for addr in addrs {
        match addr {
            SocketAddr::V4(_) => v4_addrs.push(addr),
            SocketAddr::V6(_) => v6_addrs.push(addr),
        }
    }

    let has_v4 = !v4_addrs.is_empty();
    let has_v6 = !v6_addrs.is_empty();

    // Happy Eyeballs: RFC6555 gives an example that Chrome and Firefox uses 300ms
    const FIXED_DELAY: Duration = Duration::from_millis(300);

    let connect_v4 = async {
        let mut result = None;

        for resolved_addr in v4_addrs {
            debug!("Trying to connect via IPv4: {}", resolved_addr);

            match TcpStream::connect(resolved_addr).await {
                Ok(stream) => {
                    debug!("Connected via IPv4: {}", resolved_addr);
                    result = Some(Ok(stream));
                    break;
                }
                Err(err) => {
                    debug!("Failed to connect to IPv4 address {}: {}", resolved_addr, err);
                    result = Some(Err(err));
                }
            }
        }
        #[allow(clippy::expect_used)]
        result.expect("impossible: v4_addrs is empty")
    };

    let connect_v6 = async {
        let mut result = None;

        for resolved_addr in v6_addrs {
            debug!("Trying to connect via IPv6: {}", resolved_addr);

            match TcpStream::connect(resolved_addr).await {
                Ok(stream) => {
                    debug!("Connected via IPv6: {}", resolved_addr);
                    result = Some(Ok(stream));
                    break;
                }
                Err(err) => {
                    debug!("Failed to connect to IPv6 address {}: {}", resolved_addr, err);
                    result = Some(Err(err));
                }
            }
        }
        #[allow(clippy::expect_used)]
        result.expect("impossible: v6_addrs is empty")
    };

    if has_v4 && !has_v6 {
        connect_v4.await
    } else if !has_v4 && has_v6 {
        connect_v6.await
    } else {
        // 根据 ipv6_first 参数决定优先级
        use futures::future::{self, Either};

        match ipv6_first {
            Some(true) => {
                // IPv6 优先：先启动 IPv6，300ms 后并发启动 IPv4
                let v4_fut = async move {
                    tokio::time::sleep(FIXED_DELAY).await;
                    connect_v4.await
                };
                let v6_fut = connect_v6;

                tokio::pin!(v4_fut);
                tokio::pin!(v6_fut);

                match future::select(v4_fut, v6_fut).await {
                    Either::Left((v4_res, v6_fut)) => match v4_res {
                        Ok(stream) => Ok(stream),
                        Err(_v4_err) => v6_fut.await,
                    },
                    Either::Right((v6_res, v4_fut)) => match v6_res {
                        Ok(stream) => Ok(stream),
                        Err(_v6_err) => v4_fut.await,
                    },
                }
            }
            Some(false) => {
                // IPv4 优先：先启动 IPv4，300ms 后并发启动 IPv6
                let v6_fut = async move {
                    tokio::time::sleep(FIXED_DELAY).await;
                    connect_v6.await
                };
                let v4_fut = connect_v4;

                tokio::pin!(v4_fut);
                tokio::pin!(v6_fut);

                match future::select(v4_fut, v6_fut).await {
                    Either::Left((v4_res, v6_fut)) => match v4_res {
                        Ok(stream) => Ok(stream),
                        Err(_v4_err) => v6_fut.await,
                    },
                    Either::Right((v6_res, v4_fut)) => match v6_res {
                        Ok(stream) => Ok(stream),
                        Err(_v6_err) => v4_fut.await,
                    },
                }
            }
            None => {
                // 不指定优先级：保持 DNS 返回的顺序，同时并发尝试所有地址
                // 这使用标准的 Happy Eyeballs 算法，按 DNS 返回顺序但并发尝试
                let v4_fut = async move {
                    tokio::time::sleep(FIXED_DELAY).await;
                    connect_v4.await
                };
                let v6_fut = connect_v6;

                tokio::pin!(v4_fut);
                tokio::pin!(v6_fut);

                match future::select(v4_fut, v6_fut).await {
                    Either::Left((v4_res, v6_fut)) => match v4_res {
                        Ok(stream) => Ok(stream),
                        Err(_v4_err) => v6_fut.await,
                    },
                    Either::Right((v6_res, v4_fut)) => match v6_res {
                        Ok(stream) => Ok(stream),
                        Err(_v6_err) => v4_fut.await,
                    },
                }
            }
        }
    }
}

/// Debug 模式：不验证证书（方便测试）
/// Release 模式：使用平台证书验证器
pub(crate) fn build_tls_connector() -> TlsConnector {
    #[cfg(debug_assertions)]
    {
        use tokio_rustls::rustls::ClientConfig;

        warn!("⚠️  DEBUG MODE: TLS certificate verification is DISABLED");
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    }

    #[cfg(not(debug_assertions))]
    {
        use hyper_rustls::ConfigBuilderExt;
        #[allow(clippy::expect_used)]
        let config = tokio_rustls::rustls::ClientConfig::builder()
            .try_with_platform_verifier()
            .expect("Failed to create platform verifier")
            .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    }
}

use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{DigitallySignedStruct, SignatureScheme};

#[allow(dead_code)]
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], server_name: &ServerName<'_>,
        _ocsp_response: &[u8], _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        // 解析并打印证书信息
        use x509_cert::Certificate;
        use x509_cert::der::Decode;
        if let Ok(cert) = Certificate::from_der(end_entity.as_ref()) {
            let tbs = &cert.tbs_certificate;
            info!("🔐 TLS Certificate Info:");
            info!("  Server Name: {:?}", server_name);
            info!("  Subject: {}", tbs.subject);
            info!("  Issuer: {}", tbs.issuer);
            info!("  Serial: {:?}", tbs.serial_number);
            info!("  Valid from: {:?}", tbs.validity.not_before);
            info!("  Valid until: {:?}", tbs.validity.not_after);

            // 打印 Subject Alternative Names
            if let Some(extensions) = &tbs.extensions {
                for ext in extensions.iter() {
                    if ext.extn_id.to_string() == "2.5.29.17" {
                        // SAN OID
                        debug!("  SAN extension found: {} bytes", ext.extn_value.len());
                    }
                }
            }

            info!("  Intermediate certs: {}", intermediates.len());
        } else {
            warn!("Failed to parse certificate for {:?}", server_name);
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

/// 获取客户端 IP 地址
/// 优先从 x-forwarded-for 请求头获取（取第一个 IP），否则使用 socket 地址
fn get_client_ip(req: &Request<Incoming>, client_socket_addr: SocketAddr) -> String {
    req.headers()
        .get("x-forwarded-for")
        .and_then(|forwarded_for| {
            forwarded_for
                .to_str()
                .ok()
                .and_then(|s| s.split(',').next())
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| client_socket_addr.ip().to_canonical().to_string())
}

fn origin_form(uri: &mut Uri) -> io::Result<()> {
    let path = match uri.path_and_query() {
        Some(path) if path.as_str() != "/" => {
            let mut parts = ::http::uri::Parts::default();
            parts.path_and_query = Some(path.clone());
            Uri::from_parts(parts).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?
        }
        _none_or_just_slash => {
            debug_assert!(Uri::default() == "/");
            Uri::default()
        }
    };
    *uri = path;
    Ok(())
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel<T>(upgraded: Upgraded, target_io: CounterIO<T, LabelImpl<AccessLabel>>) -> io::Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut upgraded = TokioIo::new(upgraded);
    let timed_target_io = TimeoutIO::new(target_io, crate::IDLE_TIMEOUT);
    pin!(timed_target_io);
    // https://github.com/sfackler/tokio-io-timeout/issues/12
    // timed_target_io.as_mut() // 一定要as_mut()，否则会move所有权
    // ._set_timeout_pinned(Duration::from_secs(crate::IDLE_SECONDS));
    let (_from_client, _from_server) = tokio::io::copy_bidirectional(&mut upgraded, &mut timed_target_io).await?;
    Ok(())
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ReqLabels {
    // Use your own enum types to represent label values.
    pub referer: String,
    // Or just a plain string.
    pub path: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet, PartialOrd, Ord)]
pub struct AccessLabel {
    pub client: String,
    pub relay_over_tls: Option<bool>, // 只有bypass时，该字段才为Some
    pub target: String,
    pub username: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet, PartialOrd, Ord)]
pub struct TunnelHandshakeLabel {
    pub target: String,
    // pub final_target: Option<String>, // 是否是通过bypass中继的
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet, PartialOrd, Ord)]
pub struct ReverseProxyReqLabel {
    pub client: String,
    pub origin: String,
    pub upstream: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct NetDirectionLabel {
    pub direction: &'static str,
}

impl Display for AccessLabel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.client, self.target)
    }
}

pub(crate) fn build_authenticate_resp(for_proxy: bool) -> Response<BoxBody<Bytes, io::Error>> {
    let mut resp = Response::new(full_body("auth need"));
    resp.headers_mut().append(
        if for_proxy {
            http::header::PROXY_AUTHENTICATE
        } else {
            http::header::WWW_AUTHENTICATE
        },
        HeaderValue::from_static("Basic realm=\"are you kidding me\""),
    );
    if for_proxy {
        *resp.status_mut() = http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
    } else {
        *resp.status_mut() = http::StatusCode::UNAUTHORIZED;
    }
    resp
}

pub fn empty_body() -> BoxBody<Bytes, io::Error> {
    Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}

pub fn full_body<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, io::Error> {
    Full::new(chunk.into()).map_err(|never| match never {}).boxed()
}

// 用于 forward_bypass 的流枚举，支持 TCP 和 TLS
pin_project_lite::pin_project! {
    #[project = EitherTlsStreamProj]
    pub(crate) enum EitherTlsStream {
        Tcp { #[pin] stream: TcpStream },
        Tls { #[pin] stream: TlsStream<TcpStream> },
    }
}

impl tokio::io::AsyncRead for EitherTlsStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.project() {
            EitherTlsStreamProj::Tcp { stream } => stream.poll_read(cx, buf),
            EitherTlsStreamProj::Tls { stream } => stream.poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for EitherTlsStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.project() {
            EitherTlsStreamProj::Tcp { stream } => stream.poll_write(cx, buf),
            EitherTlsStreamProj::Tls { stream } => stream.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        match self.project() {
            EitherTlsStreamProj::Tcp { stream } => stream.poll_flush(cx),
            EitherTlsStreamProj::Tls { stream } => stream.poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.project() {
            EitherTlsStreamProj::Tcp { stream } => stream.poll_shutdown(cx),
            EitherTlsStreamProj::Tls { stream } => stream.poll_shutdown(cx),
        }
    }
}
