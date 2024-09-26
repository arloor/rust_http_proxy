use std::{
    borrow::Cow,
    collections::HashMap,
    fmt::{Display, Formatter},
    io::{self, ErrorKind},
    net::SocketAddr,
    time::Duration,
};

use crate::{
    address::host_addr,
    http1_client::HttpClient,
    ip_x::SocketAddrFormat,
    net_monitor::NetMonitor,
    reverse::{self, LocationConfig},
    web_func, Config, LOCAL_IP,
};
use {io_x::CounterIO, io_x::TimeoutIO, prom_label::LabelImpl};

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
    Method, Request, Response, Version,
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
use prom_label::Label;
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family},
    registry::Registry,
};
use rand::Rng;
use tokio::{net::TcpStream, pin};

pub struct ProxyHandler {
    pub(crate) config: Config,
    prom_registry: Registry,
    metrics: Metrics,
    net_monitor: NetMonitor,
    http1_client: HttpClient<Incoming>,
    reverse_client: legacy::Client<hyper_rustls::HttpsConnector<HttpConnector>, Incoming>,
    redirect_bachpaths: Vec<RedirectBackpaths>,
}

pub(crate) struct Metrics {
    pub(crate) http_req_counter: Family<LabelImpl<ReqLabels>, Counter>,
    pub(crate) proxy_traffic: Family<LabelImpl<AccessLabel>, Counter>,
    pub(crate) net_bytes: Family<LabelImpl<NetDirectionLabel>, Counter>,
    #[cfg(feature = "bpf")]
    pub(crate) cgroup_bytes: Family<LabelImpl<NetDirectionLabel>, Counter>,
}
const DEFAULT_HOST: &str = "default_host";
#[allow(unused)]
use hyper_rustls::HttpsConnectorBuilder;
impl ProxyHandler {
    #[allow(clippy::expect_used)]
    pub fn new(config: Config) -> Result<Self, crate::DynError> {
        let mut registry = Registry::default();
        let metrics = register_metrics(&mut registry);

        let reverse_client = build_hyper_legacy_client();
        let http1_client = HttpClient::<Incoming>::new();

        let mut redirect_bachpaths = Vec::<RedirectBackpaths>::new();
        for (host, locations) in &config.reverse_proxy_config {
            for location in locations {
                redirect_bachpaths.push(RedirectBackpaths {
                    redirect_url: location.upstream.scheme_and_authority.clone()
                        + location.upstream.replacement.as_str(),
                    host: host.clone(),
                    location: location.location.clone(),
                });
            }
        }
        redirect_bachpaths.sort_by(|a, b| a.redirect_url.cmp(&b.redirect_url).reverse());
        for ele in redirect_bachpaths.iter() {
            debug!("find redirect back path for: {}**", ele.redirect_url);
        }

        let monitor: NetMonitor = NetMonitor::new()?;
        monitor.start();

        Ok(ProxyHandler {
            prom_registry: registry,
            metrics,
            net_monitor: monitor,
            reverse_client,
            http1_client,
            config,
            redirect_bachpaths,
        })
    }
    pub async fn proxy(
        &self,
        req: Request<hyper::body::Incoming>,
        client_socket_addr: SocketAddr,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        let config_basic_auth = &self.config.basic_auth;
        let never_ask_for_auth = self.config.never_ask_for_auth;
        // 1. serve stage (static files|reverse proxy)
        if Method::CONNECT != req.method() {
            let req_basic = extract_requst_basic_info(
                &req,
                match self.config.over_tls {
                    true => "https",
                    false => "http",
                },
            )?;
            if let Some(locations) = self
                .config
                .reverse_proxy_config
                .get(&req_basic.host)
                .or(self.config.reverse_proxy_config.get(DEFAULT_HOST))
            {
                if let Some(location_config) = pick_location(req.uri().path(), locations) {
                    let upstream_req = build_upstream_req(req, location_config)?;
                    info!(
                        "[reverse proxy] {:^35} => {}{}** ==> [{}] {:?} [{:?}]",
                        SocketAddrFormat(&client_socket_addr).to_string(),
                        req_basic,
                        location_config.location,
                        upstream_req.method(),
                        &upstream_req.uri(),
                        upstream_req.version(),
                    );
                    return self
                        .reverse_proxy(
                            upstream_req,
                            &location_config.upstream.scheme_and_authority,
                            &req_basic,
                        )
                        .await;
                }
            }
            if req.version() == Version::HTTP_2 || req.uri().host().is_none() {
                // http2.0肯定是over tls的，所以不是普通GET/POST代理请求。
                // URL中不包含host（GET / HTTP/1.1）也不是普通GET/POST代理请求。
                return self
                    .serve_static(
                        &req,
                        config_basic_auth,
                        never_ask_for_auth,
                        client_socket_addr,
                    )
                    .await;
            }
        }

        // 2. proxy stage
        let (username, authed) = check_auth(
            config_basic_auth,
            &req,
            &client_socket_addr,
            http::header::PROXY_AUTHORIZATION,
        );
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
                Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "wrong basic auth, closing socket...",
                ))
            } else {
                Ok(build_authenticate_resp(true))
            };
        }
        if Method::CONNECT == req.method() {
            self.tunnel_proxy(req, client_socket_addr, username)
        } else {
            self.simple_proxy(req, client_socket_addr, username).await
        }
    }

    /// 代理普通请求
    /// HTTP/1.1 GET/POST/PUT/DELETE/HEAD
    async fn simple_proxy(
        &self,
        mut req: Request<Incoming>,
        client_socket_addr: SocketAddr,
        username: String,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        let access_label = self.build_access_label(&req, client_socket_addr, username)?;
        mod_http1_proxy_req(&mut req)?;
        match self
            .http1_client
            .send_request(
                req,
                &access_label,
                |stream: TcpStream, access_label: AccessLabel| {
                    CounterIO::new(
                        stream,
                        self.metrics.proxy_traffic.clone(),
                        LabelImpl::new(access_label),
                    )
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

    fn build_access_label(
        &self,
        req: &Request<Incoming>,
        client_socket_addr: SocketAddr,
        username: String,
    ) -> Result<AccessLabel, io::Error> {
        let addr = host_addr(req.uri()).ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("URI missing host: {}", req.uri()),
            )
        })?;
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
        &self,
        req: Request<Incoming>,
        client_socket_addr: SocketAddr,
        username: String,
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
            let proxy_traffic = self.metrics.proxy_traffic.clone();
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        let access_label = AccessLabel {
                            client: client_socket_addr.ip().to_canonical().to_string(),
                            target: addr.clone().to_string(),
                            username,
                        };
                        // Connect to remote server
                        match TcpStream::connect(addr.to_string()).await {
                            Ok(target_stream) => {
                                let access_tag = access_label.to_string();
                                let target_stream = CounterIO::new(
                                    target_stream,
                                    proxy_traffic,
                                    LabelImpl::new(access_label),
                                );
                                if let Err(e) = tunnel(upgraded, target_stream).await {
                                    warn!(
                                        "[tunnel io error] [{}]: [{}] {} ",
                                        access_tag,
                                        e.kind(),
                                        e
                                    );
                                };
                            }
                            Err(e) => {
                                warn!(
                                    "[tunnel establish error] [{}]: [{}] {} ",
                                    access_label,
                                    e.kind(),
                                    e
                                )
                            }
                        }
                    }
                    Err(e) => warn!("upgrade error: {}", e),
                }
            });
            let mut response = Response::new(empty_body());
            // 针对connect请求中，在响应中增加随机长度的padding，防止每次建连时tcp数据长度特征过于敏感
            let max_num = 2048 / LOCAL_IP.len();
            let count = rand::thread_rng().gen_range(1..max_num);
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

    async fn serve_static(
        &self,
        req: &Request<Incoming>,
        config_basic_auth: &HashMap<String, String>,
        never_ask_for_auth: bool,
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
        web_func::serve_http_request(
            req,
            client_socket_addr,
            &self.config,
            path,
            &self.net_monitor,
            &self.metrics,
            &self.prom_registry,
        )
        .await
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
    }

    async fn reverse_proxy(
        &self,
        upstream_req: Request<Incoming>,
        upstream_scheme_and_authority: &String,
        origin_req_basic: &ReqBasic,
    ) -> io::Result<Response<BoxBody<Bytes, io::Error>>> {
        debug_assert!(upstream_req
            .uri()
            .to_string()
            .starts_with(upstream_scheme_and_authority));
        match self.reverse_client.request(upstream_req).await {
            Ok(mut resp) => {
                if resp.status().is_redirection() && resp.headers().contains_key(LOCATION) {
                    let headers = resp.headers_mut();
                    let redirect_location = headers.get_mut(LOCATION).ok_or(io::Error::new(
                        ErrorKind::InvalidData,
                        "LOCATION absent when 30x",
                    ))?;

                    let absolute_redirect_location =
                        ensure_absolute(redirect_location, upstream_scheme_and_authority)?;
                    if let Some(replacement) = lookup_replacement(
                        origin_req_basic,
                        absolute_redirect_location,
                        &self.redirect_bachpaths,
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
    req.headers_mut()
        .remove(http::header::PROXY_AUTHORIZATION.to_string());
    req.headers_mut().remove("Proxy-Connection");
    // set host header
    let uri = req.uri().clone();
    let hostname = uri.host().ok_or(io::Error::new(
        ErrorKind::InvalidData,
        "host is absent in HTTP/1.1",
    ))?;
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

fn build_upstream_req(
    req: Request<Incoming>,
    location_config: &LocationConfig,
) -> io::Result<Request<Incoming>> {
    let method = req.method().clone();
    let path_and_query = match req.uri().path_and_query() {
        Some(path_and_query) => path_and_query.as_str(),
        None => "",
    };
    let path_and_query = location_config.upstream.replacement.clone()
        + &path_and_query[location_config.location.len()..];
    let url = format!(
        "{}{}",
        location_config.upstream.scheme_and_authority.clone(),
        path_and_query
    );

    let mut builder = Request::builder().method(method).uri(url).version(
        if !location_config
            .upstream
            .scheme_and_authority
            .starts_with("https:")
        {
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

struct ReqBasic {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl Display for ReqBasic {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.port {
            Some(port) => write!(f, "{}://{}:{}", self.scheme, self.host, port),
            None => write!(f, "{}://{}", self.scheme, self.host),
        }
    }
}

fn extract_requst_basic_info(
    req: &Request<Incoming>,
    default_scheme: &str,
) -> io::Result<ReqBasic> {
    let uri = req.uri();
    let scheme = uri.scheme_str().unwrap_or(default_scheme);
    if req.version() == Version::HTTP_2 {
        //H2，信息全在uri中
        Ok(ReqBasic {
            scheme: scheme.to_owned(),
            host: uri
                .host()
                .ok_or(io::Error::new(
                    ErrorKind::InvalidData,
                    "authority is absent in HTTP/2",
                ))?
                .to_string(),
            port: uri.port_u16(),
        })
    } else {
        let mut split = req
            .headers()
            .get(http::header::HOST)
            .ok_or(io::Error::new(
                ErrorKind::InvalidData,
                "Host Header is absent in HTTP/1.1",
            ))?
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
        Ok(ReqBasic {
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

struct RedirectBackpaths {
    redirect_url: String,
    host: String,
    location: String,
}

fn lookup_replacement(
    req_basic: &ReqBasic,
    absolute_redirect_location: String,
    redirect_bachpaths: &[RedirectBackpaths],
) -> Option<String> {
    for ele in redirect_bachpaths.iter() {
        if absolute_redirect_location.starts_with(ele.redirect_url.as_str()) {
            info!(
                "redirect back path for {}** is {}",
                ele.redirect_url,
                format!("*://{}:*{}**", ele.host, ele.location),
            );
            let host = match ele.host.as_str() {
                DEFAULT_HOST => &req_basic.host, // 如果是default_host，就用当前host
                other => other,
            };
            let port_part = if let Some(port) = req_basic.port {
                format!(":{}", port)
            } else {
                String::new()
            };
            return Some(
                req_basic.scheme.to_owned() // use raw request's scheme
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

fn ensure_absolute(
    location_header: &mut HeaderValue,
    upstream_scheme_and_authority: &String,
) -> io::Result<String> {
    let location = location_header
        .to_str()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    let redirect_url = location
        .parse::<Uri>()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    if redirect_url.scheme_str().is_none() {
        Ok(format!("{}{}", upstream_scheme_and_authority, location))
    } else {
        Ok(location.to_string())
    }
}

fn pick_location<'b>(path: &str, locations: &'b [LocationConfig]) -> Option<&'b LocationConfig> {
    // let path = match path {
    //     "" => "/",
    //     path => path,
    // };
    locations
        .iter()
        .find(|&ele| path.starts_with(&ele.location))
}

fn build_hyper_legacy_client(
) -> legacy::Client<hyper_rustls::HttpsConnector<HttpConnector>, Incoming> {
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

fn register_metrics(registry: &mut Registry) -> Metrics {
    let http_req_counter = Family::<LabelImpl<ReqLabels>, Counter>::default();
    registry.register(
        "req_from_out",
        "Number of HTTP requests received",
        http_req_counter.clone(),
    );
    let proxy_traffic = Family::<LabelImpl<AccessLabel>, Counter>::default();
    registry.register("proxy_traffic", "num proxy_traffic", proxy_traffic.clone());
    let net_bytes = Family::<LabelImpl<NetDirectionLabel>, Counter>::default();
    registry.register("net_bytes", "num net_bytes", net_bytes.clone());

    #[cfg(feature = "bpf")]
    let cgroup_bytes = Family::<LabelImpl<NetDirectionLabel>, Counter>::default();
    #[cfg(feature = "bpf")]
    registry.register("cgroup_bytes", "num cgroup_bytes", cgroup_bytes.clone());

    register_metric_cleaner(proxy_traffic.clone(), "proxy_traffic".to_owned(), 24);
    // register_metric_cleaner(http_req_counter.clone(), 7 * 24);

    Metrics {
        http_req_counter,
        proxy_traffic,
        net_bytes,
        #[cfg(feature = "bpf")]
        cgroup_bytes,
    }
}

// 每两小时清空一次，否则一直累积，光是exporter的流量就很大，观察到每天需要3.7GB。不用担心rate函数不准，promql查询会自动处理reset（数据突降）的数据。
// 不过，虽然能够处理reset，但increase会用最后一个出现的值-第一个出现的值。在我们清空的实现下，reset后第一个出现的值肯定不是0，所以increase的算出来的值会稍少（少第一次出现的值）
// 因此对于准确性要求较高的http_req_counter，这里的清空间隔就放大一点
fn register_metric_cleaner<T: Label + Send + Sync>(
    counter: Family<T, Counter>,
    name: String,
    interval_in_hour: u64,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(interval_in_hour * 60 * 60)).await;
            info!("cleaning prometheus metric labels for {}", name);
            counter.clear();
        }
    });
}

pub(crate) fn check_auth(
    config_basic_auth: &HashMap<String, String>,
    req: &Request<impl Body>,
    client_socket_addr: &SocketAddr,
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
            None => warn!(
                "no {} from {}",
                header_name_str,
                SocketAddrFormat(client_socket_addr)
            ),
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
async fn tunnel(
    upgraded: Upgraded,
    target_io: CounterIO<TcpStream, LabelImpl<AccessLabel>>,
) -> io::Result<()> {
    let mut upgraded = TokioIo::new(upgraded);
    let timed_target_io = TimeoutIO::new(target_io, crate::IDLE_TIMEOUT);
    pin!(timed_target_io);
    // https://github.com/sfackler/tokio-io-timeout/issues/12
    // timed_target_io.as_mut() // 一定要as_mut()，否则会move所有权
    // ._set_timeout_pinned(Duration::from_secs(crate::IDLE_SECONDS));
    let (_from_client, _from_server) =
        tokio::io::copy_bidirectional(&mut upgraded, &mut timed_target_io).await?;
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
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

pub fn full_body<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, io::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

#[cfg(test)]
mod test {
    #[test]
    fn test_aa() {
        let host = "www.arloor.com";
        assert_eq!(host.split(':').next().unwrap_or("").to_string(), host);
    }
}
