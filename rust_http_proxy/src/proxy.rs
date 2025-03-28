use std::{
    borrow::Cow,
    collections::HashMap,
    fmt::{Display, Formatter},
    io::{self, ErrorKind},
    net::SocketAddr,
    str::FromStr,
    sync::LazyLock,
    time::Duration,
};

use crate::{
    address::host_addr,
    config,
    http1_client::HttpClient,
    ip_x::{local_ip, SocketAddrFormat},
    reverse::{self, LocationConfig, Upstream},
    web_func, Config, Metrics, METRICS,
};
use {io_x::CounterIO, io_x::TimeoutIO, prom_label::LabelImpl};

use axum::extract::Request;
use axum_bootstrap::InterceptResult;
use http::{
    header::{HOST, LOCATION},
    Uri,
};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{
    body::Bytes,
    header::{self, HeaderValue},
    http,
    upgrade::Upgraded,
    Method, Response, Version,
};
use hyper::{
    body::{Body, Incoming},
    header::HeaderName,
};
use hyper_util::client::legacy::{self, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use log::{debug, info, warn};
use percent_encoding::percent_decode_str;
use prometheus_client::encoding::EncodeLabelSet;
use rand::Rng;
use tokio::{net::TcpStream, pin};
static LOCAL_IP: LazyLock<String> = LazyLock::new(|| local_ip().unwrap_or("0.0.0.0".to_string()));
pub struct ProxyHandler {
    pub(crate) config: Config,
    #[cfg(target_os = "linux")]
    pub(crate) linux_monitor: crate::linux_monitor::NetMonitor,
    http1_client: HttpClient<Incoming>,
    reverse_client: legacy::Client<hyper_rustls::HttpsConnector<HttpConnector>, Incoming>,
}

pub(crate) enum InterceptResultAdapter {
    Return(Response<BoxBody<Bytes, io::Error>>),
    Continue(Request<Incoming>),
}

impl From<InterceptResultAdapter> for InterceptResult {
    fn from(val: InterceptResultAdapter) -> Self {
        match val {
            InterceptResultAdapter::Return(resp) => {
                let (parts, body) = resp.into_parts();
                axum_bootstrap::InterceptResult::Return(Response::from_parts(parts, axum::body::Body::new(body)))
            }
            InterceptResultAdapter::Continue(req) => InterceptResult::Continue(req),
        }
    }
}

#[allow(unused)]
use hyper_rustls::HttpsConnectorBuilder;
impl ProxyHandler {
    #[allow(clippy::expect_used)]
    pub fn new(config: Config) -> Result<Self, crate::DynError> {
        let reverse_client = build_hyper_legacy_client();
        let http1_client = HttpClient::<Incoming>::new();

        #[cfg(target_os = "linux")]
        let monitor = crate::linux_monitor::NetMonitor::new()?;
        #[cfg(target_os = "linux")]
        monitor.start();

        Ok(ProxyHandler {
            #[cfg(target_os = "linux")]
            linux_monitor: monitor,
            reverse_client,
            http1_client,
            config,
        })
    }
    pub async fn proxy(
        &self, req: Request<hyper::body::Incoming>, client_socket_addr: SocketAddr,
    ) -> Result<InterceptResultAdapter, io::Error> {
        let config_basic_auth = &self.config.basic_auth;
        let never_ask_for_auth = self.config.never_ask_for_auth;

        // 对于非CONNECT请求，检查是否需要反向代理或服务
        if Method::CONNECT != req.method() {
            let origin_scheme_host_port = extract_requst_basic_info(
                &req,
                match self.config.over_tls {
                    true => "https",
                    false => "http",
                },
            )?;

            // 尝试找到匹配的反向代理配置
            let host_locations = self
                .config
                .reverse_proxy_config
                .locations
                .get(&origin_scheme_host_port.host)
                .or(self.config.reverse_proxy_config.locations.get(config::DEFAULT_HOST));

            if let Some(locations) = host_locations {
                if let Some(location_config) = pick_location(req.uri().path(), locations) {
                    return self
                        .reverse_proxy(req, location_config, client_socket_addr, &origin_scheme_host_port)
                        .await
                        .map(InterceptResultAdapter::Return);
                }
            }

            // 对于HTTP/2请求或URI中不包含host的请求，处理为普通服务请求
            if req.version() == Version::HTTP_2 || req.uri().host().is_none() {
                match self
                    .serve_request(&req, config_basic_auth, never_ask_for_auth, client_socket_addr)
                    .await
                {
                    Ok(res) => {
                        if res.status() == http::StatusCode::NOT_FOUND {
                            return Ok(InterceptResultAdapter::Continue(req));
                        } else {
                            return Ok(InterceptResultAdapter::Return(res));
                        }
                    }
                    Err(err) => return Err(err),
                }
            }
        }

        // 2. proxy stage
        let (username, authed) =
            check_auth(config_basic_auth, &req, &client_socket_addr, http::header::PROXY_AUTHORIZATION);
        info!(
            "{:>29} {:<5} {:^8} {:^7} {:?} {:?} ",
            "https://ip.im/".to_owned() + &client_socket_addr.ip().to_canonical().to_string(),
            client_socket_addr.port(),
            username,
            req.method().as_str(),
            req.uri(),
            req.version(),
        );
        if !authed {
            return if never_ask_for_auth {
                Err(io::Error::new(ErrorKind::PermissionDenied, "wrong basic auth, closing socket..."))
            } else {
                Ok(InterceptResultAdapter::Return(build_authenticate_resp(true)))
            };
        }
        if Method::CONNECT == req.method() {
            self.tunnel_proxy(req, client_socket_addr, username)
                .map(InterceptResultAdapter::Return)
        } else {
            self.simple_proxy(req, client_socket_addr, username)
                .await
                .map(InterceptResultAdapter::Return)
        }
    }

    /// 代理普通请求
    /// HTTP/1.1 GET/POST/PUT/DELETE/HEAD
    async fn simple_proxy(
        &self, mut req: Request<Incoming>, client_socket_addr: SocketAddr, username: String,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        let access_label = self.build_access_label(&req, client_socket_addr, username)?;
        mod_http1_proxy_req(&mut req)?;
        match self
            .http1_client
            .send_request(req, &access_label, |stream: TcpStream, access_label: AccessLabel| {
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

    fn build_access_label(
        &self, req: &Request<Incoming>, client_socket_addr: SocketAddr, username: String,
    ) -> Result<AccessLabel, io::Error> {
        let addr = host_addr(req.uri())
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, format!("URI missing host: {}", req.uri())))?;
        let access_label = AccessLabel {
            client: client_socket_addr.ip().to_canonical().to_string(),
            target: addr.to_string(),
            username,
        };
        Ok(access_label)
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
                    Err(e) => warn!("upgrade error: {}", e),
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

    async fn serve_request(
        &self, req: &Request<Incoming>, config_basic_auth: &HashMap<String, String>, never_ask_for_auth: bool,
        client_socket_addr: SocketAddr,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        let raw_path = req.uri().path();
        let path = percent_decode_str(raw_path)
            .decode_utf8()
            .unwrap_or(Cow::from(raw_path));
        let path = path.as_ref();
        if !config_basic_auth.is_empty() && !never_ask_for_auth {
            // 存在嗅探风险时，不伪装成http服务
            return Err(io::Error::new(
                ErrorKind::PermissionDenied,
                "reject http GET/POST when ask_for_auth and basic_auth not empty",
            ));
        }
        web_func::serve_http_request(self, req, client_socket_addr, path)
            .await
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
    }

    async fn reverse_proxy(
        &self, req: Request<hyper::body::Incoming>, location_config: &LocationConfig, client_socket_addr: SocketAddr,
        origin_scheme_host_port: &SchemeHostPort,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        let upstream_req = build_upstream_req(req, location_config)?;
        info!(
            "[reverse proxy] {:^35} => {}{}** ==> [{}] {:?} [{:?}]",
            SocketAddrFormat(&client_socket_addr).to_string(),
            origin_scheme_host_port,
            location_config.location,
            upstream_req.method(),
            &upstream_req.uri(),
            upstream_req.version(),
        );
        METRICS
            .reverse_proxy_req
            .get_or_create(&LabelImpl::new(ReverseProxyReqLabel {
                client: client_socket_addr.ip().to_canonical().to_string(),
                origin: origin_scheme_host_port.to_string() + location_config.location.as_str(),
                upstream: location_config.upstream.url_base.clone(),
            }))
            .inc();
        METRICS.reverse_proxy_req.get_or_create(&ALL_REVERSE_PROXY_REQ).inc();
        let context = ReverseReqContext {
            upstream: &location_config.upstream,
            origin_scheme_host_port,
        };
        match self.reverse_client.request(upstream_req).await {
            Ok(mut resp) => {
                if resp.status().is_redirection() && resp.headers().contains_key(LOCATION) {
                    let headers = resp.headers_mut();
                    let redirect_location = headers
                        .get_mut(LOCATION)
                        .ok_or(io::Error::new(ErrorKind::InvalidData, "LOCATION absent when 30x"))?;

                    let absolute_redirect_location = ensure_absolute(redirect_location, &context)?;
                    if let Some(replacement) = lookup_replacement(
                        context.origin_scheme_host_port,
                        absolute_redirect_location,
                        &self.config.reverse_proxy_config.redirect_bachpaths,
                    ) {
                        let origin = headers.insert(
                            LOCATION,
                            HeaderValue::from_str(replacement.as_str())
                                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
                        );
                        info!("redirect to [{}], origin is [{:?}]", replacement, origin);
                    }
                }
                Ok(resp.map(|body| {
                    body.map_err(|e| {
                        let e = e;
                        io::Error::new(ErrorKind::InvalidData, e)
                    })
                    .boxed()
                }))
            }
            Err(e) => {
                warn!("reverse_proxy error: {:?}", e);
                Err(io::Error::new(ErrorKind::InvalidData, e))
            }
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
    let host_header = if let Some(port) = get_non_default_port(&uri) {
        let s = format!("{}:{}", hostname, port);
        HeaderValue::from_str(&s)
    } else {
        HeaderValue::from_str(hostname)
    }
    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    let origin = req.headers_mut().insert(HOST, host_header.clone());
    if Some(host_header.clone()) != origin {
        info!("change host header: {:?} -> {:?}", origin, host_header);
    }
    // change absoulte uri to relative uri
    origin_form(req.uri_mut())?;
    Ok(())
}

fn build_upstream_req(req: Request<Incoming>, location_config: &LocationConfig) -> io::Result<Request<Incoming>> {
    let method = req.method().clone();
    let path_and_query = match req.uri().path_and_query() {
        Some(path_and_query) => path_and_query.as_str(),
        None => "",
    };
    let url = location_config.upstream.url_base.clone() + &path_and_query[location_config.location.len()..];

    let mut builder = Request::builder().method(method).uri(url).version(
        if !location_config.upstream.url_base.starts_with("https:") {
            match location_config.upstream.version {
                reverse::Version::H1 => Version::HTTP_11,
                reverse::Version::H2 => Version::HTTP_2,
                reverse::Version::Auto => Version::HTTP_11,
            }
        } else {
            match location_config.upstream.version {
                reverse::Version::H1 => Version::HTTP_11,
                reverse::Version::H2 => Version::HTTP_2,
                reverse::Version::Auto => req.version(),
            }
        },
    );
    let header_map = match builder.headers_mut() {
        Some(header_map) => header_map,
        None => {
            return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "new_req.headers_mut() is None, which means error occurs in new request build. Check URL, method, version...",
                    ));
        }
    };
    for ele in req.headers() {
        if ele.0 != header::HOST {
            header_map.append(ele.0.clone(), ele.1.clone());
        } else {
            info!("skip host header: {:?}", ele.1);
        }
    }
    builder
        .body(req.into_body())
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
}

struct SchemeHostPort {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl Display for SchemeHostPort {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.port {
            Some(port) => write!(f, "{}://{}:{}", self.scheme, self.host, port),
            None => write!(f, "{}://{}", self.scheme, self.host),
        }
    }
}

fn extract_requst_basic_info(req: &Request<Incoming>, default_scheme: &str) -> io::Result<SchemeHostPort> {
    let uri = req.uri();
    let scheme = uri.scheme_str().unwrap_or(default_scheme);
    if req.version() == Version::HTTP_2 {
        //H2，信息全在uri中
        Ok(SchemeHostPort {
            scheme: scheme.to_owned(),
            host: uri
                .host()
                .ok_or(io::Error::new(ErrorKind::InvalidData, "authority is absent in HTTP/2"))?
                .to_string(),
            port: uri.port_u16(),
        })
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
        Ok(SchemeHostPort {
            scheme: scheme.to_owned(),
            host,
            port,
        })
    }
}

fn get_non_default_port(uri: &Uri) -> Option<http::uri::Port<&str>> {
    match (uri.port().map(|p| p.as_u16()), is_schema_secure(uri)) {
        (Some(443), true) => None,
        (Some(80), false) => None,
        _ => uri.port(),
    }
}

fn is_schema_secure(uri: &Uri) -> bool {
    uri.scheme_str()
        .map(|scheme_str| matches!(scheme_str, "wss" | "https"))
        .unwrap_or_default()
}

struct ReverseReqContext<'a> {
    upstream: &'a Upstream,
    origin_scheme_host_port: &'a SchemeHostPort,
}

fn lookup_replacement(
    origin_scheme_host_port: &SchemeHostPort, absolute_redirect_location: String,
    redirect_bachpaths: &[config::RedirectBackpaths],
) -> Option<String> {
    for ele in redirect_bachpaths.iter() {
        if absolute_redirect_location.starts_with(ele.redirect_url.as_str()) {
            info!("redirect back path for {}** is http(s)://{}:port{}**", ele.redirect_url, ele.host, ele.location,);
            let host = match ele.host.as_str() {
                config::DEFAULT_HOST => &origin_scheme_host_port.host, // 如果是default_host，就用当前host
                other => other,
            };
            let port_part = if let Some(port) = origin_scheme_host_port.port {
                format!(":{}", port)
            } else {
                String::new()
            };
            return Some(
                origin_scheme_host_port.scheme.to_owned() // use raw request's scheme
                + "://"
                + host // if it's default_host, use raw request's host
                + &port_part // use raw request's port if available
                + &ele.location
                + &absolute_redirect_location[ele.redirect_url.len()..],
            );
        }
    }
    None
}

fn ensure_absolute(location_header: &mut HeaderValue, context: &ReverseReqContext<'_>) -> io::Result<String> {
    let location = location_header
        .to_str()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    let redirect_url = location
        .parse::<Uri>()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    if redirect_url.scheme_str().is_none() {
        let url_base =
            Uri::from_str(&context.upstream.url_base).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        let base = if url_base.path().ends_with("/") && location.starts_with("/") {
            let mut base = url_base.to_string();
            base.truncate(url_base.to_string().len() - 1);
            base
        } else {
            url_base.to_string()
        };
        let absolute_url = format!("{}{}", base, location);
        Ok(absolute_url)
    } else {
        Ok(location.to_string())
    }
}

fn pick_location<'b>(path: &str, locations: &'b [LocationConfig]) -> Option<&'b LocationConfig> {
    // let path = match path {
    //     "" => "/",
    //     path => path,
    // };
    locations.iter().find(|&ele| path.starts_with(&ele.location))
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

pub(crate) fn check_auth(
    config_basic_auth: &HashMap<String, String>, req: &Request<impl Body>, client_socket_addr: &SocketAddr,
    header_name: HeaderName,
) -> (String, bool) {
    let mut username = "unkonwn".to_string();
    let mut authed: bool = true;
    if !config_basic_auth.is_empty() {
        //需要检验鉴权
        authed = false;
        let header_name_clone = header_name.clone();
        let header_name_str = header_name_clone.as_str();
        match req.headers().get(header_name) {
            None => warn!("no {} from {}", header_name_str, SocketAddrFormat(client_socket_addr)),
            Some(header) => match header.to_str() {
                Err(e) => warn!("解header失败，{:?} {:?}", header, e),
                Ok(request_auth) => match config_basic_auth.get(request_auth) {
                    Some(_username) => {
                        authed = true;
                        username = _username.to_string();
                    }
                    None => warn!(
                        "wrong {} from {}, wrong:{:?},right:{:?}",
                        header_name_str,
                        SocketAddrFormat(client_socket_addr),
                        request_auth,
                        config_basic_auth
                    ),
                },
            },
        }
    }
    (username, authed)
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
async fn tunnel(upgraded: Upgraded, target_io: CounterIO<TcpStream, LabelImpl<AccessLabel>>) -> io::Result<()> {
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
    pub target: String,
    pub username: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet, PartialOrd, Ord)]
pub struct ReverseProxyReqLabel {
    pub client: String,
    pub origin: String,
    pub upstream: String,
}

static ALL_REVERSE_PROXY_REQ: LazyLock<prom_label::LabelImpl<ReverseProxyReqLabel>> = LazyLock::new(|| {
    LabelImpl::new(ReverseProxyReqLabel {
        client: "all".to_string(),
        origin: "all".to_string(),
        upstream: "all".to_string(),
    })
});

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

#[cfg(all(target_os = "linux", feature = "bpf"))]
pub(crate) fn snapshot_metrics(metrics: &Metrics) {
    use crate::ebpf;
    {
        metrics
            .net_bytes
            .get_or_create(&LabelImpl::new(NetDirectionLabel { direction: "egress" }))
            .inner()
            .store(ebpf::get_egress(), std::sync::atomic::Ordering::Relaxed);
        metrics
            .net_bytes
            .get_or_create(&LabelImpl::new(NetDirectionLabel { direction: "ingress" }))
            .inner()
            .store(ebpf::get_ingress(), std::sync::atomic::Ordering::Relaxed);

        metrics
            .cgroup_bytes
            .get_or_create(&LabelImpl::new(NetDirectionLabel { direction: "egress" }))
            .inner()
            .store(ebpf::get_cgroup_egress(), std::sync::atomic::Ordering::Relaxed);
        metrics
            .cgroup_bytes
            .get_or_create(&LabelImpl::new(NetDirectionLabel { direction: "ingress" }))
            .inner()
            .store(ebpf::get_cgroup_ingress(), std::sync::atomic::Ordering::Relaxed);
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
