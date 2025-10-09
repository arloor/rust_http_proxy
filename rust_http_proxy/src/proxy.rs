use std::{
    fmt::{Display, Formatter},
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::LazyLock,
    time::Duration,
};

use crate::{
    address::host_addr,
    axum_handler::{self, AppProxyError},
    config::ForwardBypassConfig,
    forward_proxy_client::ForwardProxyClient,
    ip_x::local_ip,
    location::{LocationConfig, RequestSpec, Upstream, DEFAULT_HOST},
    CONFIG, METRICS,
};
use {io_x::CounterIO, io_x::TimeoutIO, prom_label::LabelImpl};

use axum::extract::Request;
use axum_bootstrap::InterceptResult;
use http::{header::HOST, Uri};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::{body::Bytes, header::HeaderValue, http, upgrade::Upgraded, Method, Response, Version};
use hyper_util::client::legacy::{self, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use log::{debug, info, warn};
use prometheus_client::encoding::EncodeLabelSet;
use rand::Rng;
use std::sync::Arc;
use tokio::{net::TcpStream, pin};
use tokio_rustls::rustls::pki_types;
use tokio_rustls::TlsConnector;

static LOCAL_IP: LazyLock<String> = LazyLock::new(|| local_ip().unwrap_or("0.0.0.0".to_string()));
pub struct ProxyHandler {
    forwad_proxy_client: ForwardProxyClient<Incoming>,
    reverse_proxy_client: legacy::Client<hyper_rustls::HttpsConnector<HttpConnector>, Incoming>,
}

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
}

impl<'a> ServiceType<'a> {
    /// 处理请求
    async fn handle(
        &self, req: Request<Incoming>, client_socket_addr: SocketAddr, proxy_handler: &ProxyHandler,
    ) -> Result<InterceptResultAdapter, io::Error> {
        match self {
            ServiceType::ReverseProxy {
                ref original_scheme_host_port,
                location,
                upstream,
            } => RequestSpec::ForReverseProxy {
                request: Box::new(req),
                client_socket_addr,
                original_scheme_host_port,
                location,
                upstream,
                reverse_client: &proxy_handler.reverse_proxy_client,
            }
            .handle()
            .await
            .map(InterceptResultAdapter::Return),
            ServiceType::LocationStaticServing { static_dir, location } => {
                let res = RequestSpec::ForServing {
                    request: &req,
                    client_socket_addr,
                    location,
                    static_dir,
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
                    Err(e) => Err(e),
                }
            }
            ServiceType::ForwardProxy => {
                let config_basic_auth = &crate::CONFIG.basic_auth;
                let never_ask_for_auth = crate::CONFIG.never_ask_for_auth;

                match axum_handler::check_auth(req.headers(), http::header::PROXY_AUTHORIZATION, config_basic_auth) {
                    Ok(username_option) => {
                        let username = username_option.unwrap_or("unknown".to_owned());
                        info!(
                            "{:>29} {:<5} {:^8} {:^7} {:?} {:?} X-Forwarded-For: {} ",
                            "https://ip.im/".to_owned() + &client_socket_addr.ip().to_canonical().to_string(),
                            client_socket_addr.port(),
                            username,
                            req.method().as_str(),
                            req.uri(),
                            req.version(),
                            req.headers()
                                .get("X-Forwarded-For")
                                .map(|v| v.to_str().unwrap_or("invalid utf8"))
                                .unwrap_or(""),
                        );

                        match *req.method() {
                            Method::CONNECT => match CONFIG.forward_bypass.as_ref() {
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
                            _ => match CONFIG.forward_bypass.as_ref() {
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

#[allow(unused)]
use hyper_rustls::HttpsConnectorBuilder;
impl ProxyHandler {
    #[allow(clippy::expect_used)]
    pub fn new() -> Result<Self, crate::DynError> {
        let reverse_client = build_hyper_legacy_client();
        let http1_client = ForwardProxyClient::<Incoming>::new();

        Ok(ProxyHandler {
            reverse_proxy_client: reverse_client,
            forwad_proxy_client: http1_client,
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
        // 对于非CONNECT请求，检查是否需要反向代理或静态文件托管
        if Method::CONNECT != req.method() {
            // HTTP1 且 url中有host则判定为simple proxy
            if (req.version() == Version::HTTP_10 || req.version() == Version::HTTP_11) && req.uri().host().is_some() {
                return Ok(ServiceType::ForwardProxy);
            }

            let (original_scheme_host_port, req_domain) = extract_scheme_host_port(
                req,
                match crate::CONFIG.over_tls {
                    true => "https",
                    false => "http",
                },
            )?;

            // 尝试找到匹配的 Location 配置
            let location_config_of_host = crate::CONFIG
                .reverse_proxy_config
                .locations
                .get(&req_domain.0)
                .or(crate::CONFIG.reverse_proxy_config.locations.get(DEFAULT_HOST));

            if let Some(locations) = location_config_of_host {
                if let Some(location_config) = locations
                    .iter()
                    .find(|&ele| req.uri().path().starts_with(ele.location()))
                {
                    match location_config {
                        LocationConfig::ReverseProxy { location, upstream } => {
                            return Ok(ServiceType::ReverseProxy {
                                original_scheme_host_port,
                                location,
                                upstream,
                            });
                        }
                        LocationConfig::Serving { static_dir, location } => {
                            return Ok(ServiceType::LocationStaticServing { location, static_dir });
                        }
                    }
                }
            }
        }

        // 默认为正向代理
        Ok(ServiceType::ForwardProxy)
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
            is_https: None,
        };
        mod_http1_proxy_req(&mut req)?;
        match self
            .forwad_proxy_client
            .send_request(req, &access_label, |stream: BypassStream, access_label: AccessLabel| {
                CounterIO::new(stream, METRICS.proxy_traffic.clone(), LabelImpl::new(access_label))
            })
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
            is_https: Some(forward_bypass_config.is_https),
        };
        // 删除代理特有的请求头
        req.headers_mut().remove(http::header::PROXY_AUTHORIZATION.to_string());
        // 如果配置了 username 和 password，添加 Proxy-Authorization 头
        if let (Some(username), Some(password)) = (&forward_bypass_config.username, &forward_bypass_config.password) {
            let credentials = format!("{}:{}", username, password);
            let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, credentials.as_bytes());
            req.headers_mut().insert(
                http::header::PROXY_AUTHORIZATION,
                HeaderValue::from_str(format!("Basic {}", encoded).as_str())
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
            );
        }
        // 替换host头
        let host_header = HeaderValue::from_str(&host).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        let origin = req.headers_mut().insert(HOST, host_header.clone());
        if Some(host_header.clone()) != origin {
            info!("change host header: {origin:?} -> {host_header:?}");
        }

        warn!("bypass {:?} {} {}", req.version(), req.method(), req.uri());

        match self
            .forwad_proxy_client
            .send_request(req, &access_label, |stream: BypassStream, access_label: AccessLabel| {
                CounterIO::new(stream, METRICS.proxy_traffic.clone(), LabelImpl::new(access_label))
            })
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
                    is_https: Some(forward_bypass_config.is_https),
                };

                // 首先建立 TCP 连接
                let tcp_stream = match TcpStream::connect(bypass_host).await {
                    Ok(stream) => stream,
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
                        Ok(tls_stream) => BypassStream::Tls { stream: tls_stream },
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
                    BypassStream::Tcp { stream: tcp_stream }
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
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(src_upgraded) => {
                        let access_label = AccessLabel {
                            client: client_socket_addr.ip().to_canonical().to_string(),
                            target: addr.clone().to_string(),
                            username,
                            is_https: None,
                        };
                        // Connect to remote server
                        match TcpStream::connect(addr.to_string()).await {
                            Ok(target_stream) => {
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
            RequestDomain(if let Some(host_in_header) = host_in_header {
                host_in_header
            } else {
                host_in_url
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

fn build_hyper_legacy_client() -> legacy::Client<hyper_rustls::HttpsConnector<HttpConnector>, Incoming> {
    let pool_idle_timeout = Duration::from_secs(90);
    // 创建一个 HttpConnector
    let mut http_connector = HttpConnector::new();
    http_connector.enforce_http(false);
    http_connector.set_keepalive(Some(pool_idle_timeout));

    let https_connector = HttpsConnectorBuilder::new()
        .with_platform_verifier()
        .https_or_http()
        .enable_all_versions()
        .wrap_connector(http_connector);
    // 创建一个 HttpsConnector，使用 rustls 作为后端
    let client: legacy::Client<hyper_rustls::HttpsConnector<HttpConnector>, Incoming> =
        legacy::Client::builder(TokioExecutor::new())
            .pool_idle_timeout(pool_idle_timeout)
            .pool_max_idle_per_host(5)
            .pool_timer(hyper_util::rt::TokioTimer::new())
            .build(https_connector);
    client
}

/// 创建 TLS 连接器
/// Debug 模式：不验证证书（方便测试）
/// Release 模式：使用平台证书验证器
pub(crate) fn build_tls_connector() -> TlsConnector {
    #[cfg(debug_assertions)]
    {
        use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
        use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

        #[derive(Debug)]
        struct NoVerifier;

        impl ServerCertVerifier for NoVerifier {
            fn verify_server_cert(
                &self, _end_entity: &CertificateDer<'_>, _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>, _ocsp_response: &[u8], _now: UnixTime,
            ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
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
    pub is_https: Option<bool>, // 只有bypass时，该字段才为Some
    pub target: String,
    pub username: String,
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
    #[project = BypassStreamProj]
    pub(crate) enum BypassStream {
        Tcp { #[pin] stream: TcpStream },
        Tls { #[pin] stream: tokio_rustls::client::TlsStream<TcpStream> },
    }
}

impl tokio::io::AsyncRead for BypassStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.project() {
            BypassStreamProj::Tcp { stream } => stream.poll_read(cx, buf),
            BypassStreamProj::Tls { stream } => stream.poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for BypassStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.project() {
            BypassStreamProj::Tcp { stream } => stream.poll_write(cx, buf),
            BypassStreamProj::Tls { stream } => stream.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        match self.project() {
            BypassStreamProj::Tcp { stream } => stream.poll_flush(cx),
            BypassStreamProj::Tls { stream } => stream.poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.project() {
            BypassStreamProj::Tcp { stream } => stream.poll_shutdown(cx),
            BypassStreamProj::Tls { stream } => stream.poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_aa() {
        let host = "www.arloor.com";
        assert_eq!(host.split(':').next().unwrap_or("").to_string(), host);
    }
}
