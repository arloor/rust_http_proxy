use std::{
    borrow::Cow,
    fmt::{Display, Formatter},
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use crate::{
    counter_io::CounterIO, net_monitor::NetMonitor, prom_label::LabelImpl, timeout_io::TimeoutIO,
    web_func, Config, LOCAL_IP,
};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::client::conn::http1::Builder;
use hyper::{
    body::Bytes, header::HeaderValue, http, upgrade::Upgraded, Method, Request, Response, Version,
};
use hyper_util::rt::TokioIo;
use log::{info, warn};
use percent_encoding::percent_decode_str;
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family},
    registry::Registry,
};
use rand::Rng;
use tokio::{net::TcpStream, pin};

#[derive(Clone)]
pub struct ProxyHandler {
    prom_registry: Arc<Registry>,
    http_req_counter: Family<LabelImpl<ReqLabels>, Counter>,
    proxy_traffic: Family<LabelImpl<AccessLabel>, Counter>,
    net_monitor: NetMonitor,
}

impl ProxyHandler {
    pub fn new() -> ProxyHandler {
        let monitor: NetMonitor = NetMonitor::new();
        monitor.start();
        let mut registry = <Registry>::default();
        let http_requests = Family::<LabelImpl<ReqLabels>, Counter>::default();
        registry.register(
            "req_from_out",
            "Number of HTTP requests received",
            http_requests.clone(),
        );
        let proxy_traffic = Family::<LabelImpl<AccessLabel>, Counter>::default();
        registry.register("proxy_traffic", "num proxy_traffic", proxy_traffic.clone());
        ProxyHandler {
            prom_registry: Arc::new(registry),
            http_req_counter: http_requests,
            proxy_traffic,
            net_monitor: monitor,
        }
    }
    pub async fn proxy(
        &self,
        mut req: Request<hyper::body::Incoming>,
        proxy_config: &'static Config,
        client_socket_addr: SocketAddr,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        let basic_auth = &proxy_config.basic_auth;
        let never_ask_for_auth = proxy_config.never_ask_for_auth;
        if Method::CONNECT != req.method() {
            if req.version() == Version::HTTP_2 || req.uri().host().is_none() {
                let raw_path = req.uri().path();
                let path = percent_decode_str(raw_path)
                    .decode_utf8()
                    .unwrap_or(Cow::from(raw_path));
                let path = path.as_ref();
                if !basic_auth.is_empty() && !never_ask_for_auth {
                    // 存在嗅探风险时，不伪装成http服务
                    return Err(io::Error::new(
                        ErrorKind::PermissionDenied,
                        "reject http GET/POST when ask_for_auth and basic_auth not empty",
                    ));
                }
                return web_func::serve_http_request(
                    &req,
                    client_socket_addr,
                    proxy_config,
                    path,
                    self.net_monitor.clone(),
                    self.http_req_counter.clone(),
                    self.prom_registry.clone(),
                )
                .await
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e));
            }
            if let Some(host) = req.uri().host() {
                let host = host.to_string();
                info!(
                    "{:>21?} {:^7} {:?} {:?} Host: {:?} User-Agent: {:?}",
                    client_socket_addr,
                    req.method().as_str(),
                    req.uri(),
                    req.version(),
                    req.headers()
                        .get(http::header::HOST)
                        .map_or("", |h| h.to_str().unwrap_or(host.as_str())),
                    req.headers()
                        .get(http::header::USER_AGENT)
                        .map_or("", |h| h.to_str().unwrap_or("")),
                );
            };
        }

        let mut username = "unkonwn".to_string();
        let mut authed: bool = true;
        if !basic_auth.is_empty() {
            //需要检验鉴权
            authed = false;
            match req.headers().get(http::header::PROXY_AUTHORIZATION) {
                None => warn!("no PROXY_AUTHORIZATION from {:?}", client_socket_addr),
                Some(header) => match header.to_str() {
                    Err(e) => warn!("解header失败，{:?} {:?}", header, e),
                    Ok(request_auth) => match basic_auth.get(request_auth) {
                        Some(_username) => {
                            authed = true;
                            username = _username.to_string();
                        }
                        None => warn!(
                            "wrong PROXY_AUTHORIZATION from {:?}, wrong:{:?},right:{:?}",
                            client_socket_addr, request_auth, basic_auth
                        ),
                    },
                },
            }
        }
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
                Ok(build_proxy_authenticate_resp())
            };
        }
        if Method::CONNECT == req.method() {
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
                let proxy_traffic = self.proxy_traffic.clone();
                tokio::task::spawn(async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            let access_label = AccessLabel {
                                client: client_socket_addr.ip().to_canonical().to_string(),
                                target: addr.clone(),
                                username,
                            };
                            // Connect to remote server
                            match TcpStream::connect(addr.clone()).await {
                                Ok(target_stream) => {
                                    let access_tag = access_label.to_string();
                                    let target_stream = CounterIO::new(
                                        target_stream,
                                        proxy_traffic,
                                        LabelImpl::from(access_label),
                                    );
                                    if let Err(e) = tunnel(upgraded, target_stream).await {
                                        // if e.kind() != ErrorKind::TimedOut {
                                        warn!("[tunnel io error] [{}] : {} ", access_tag, e);
                                        // }
                                    };
                                }
                                Err(e) => {
                                    warn!("[tunnel establish error] [{}] : {} ", access_label, e)
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
        } else {
            // 删除代理特有的请求头
            req.headers_mut()
                .remove(http::header::PROXY_AUTHORIZATION.to_string());
            req.headers_mut().remove("Proxy-Connection");
            let host = req.uri().host().expect("uri has no host");
            let port = req.uri().port_u16().unwrap_or(80);
            let stream = TcpStream::connect((host, port)).await?;
            let server_mod: CounterIO<TcpStream, LabelImpl<AccessLabel>> = CounterIO::new(
                stream,
                self.proxy_traffic.clone(),
                LabelImpl::from(AccessLabel {
                    client: client_socket_addr.ip().to_canonical().to_string(),
                    target: format!("{}:{}", host, port),
                    username,
                }),
            );
            let io = TokioIo::new(server_mod);
            match Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .handshake(io)
                .await
            {
                Ok((mut sender, conn)) => {
                    tokio::task::spawn(async move {
                        if let Err(err) = conn.await {
                            println!("Connection failed: {:?}", err);
                        }
                    });

                    if let Ok(resp) = sender.send_request(req).await {
                        Ok(resp.map(|b| {
                            b.map_err(|e| {
                                let e = e;
                                io::Error::new(ErrorKind::InvalidData, e)
                            })
                            .boxed()
                        }))
                    } else {
                        Err(io::Error::new(ErrorKind::ConnectionAborted, "连接失败"))
                    }
                }
                Err(e) => Err(io::Error::new(ErrorKind::ConnectionAborted, e)),
            }
        }
    }
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(
    upgraded: Upgraded,
    target_io: CounterIO<TcpStream, LabelImpl<AccessLabel>>,
) -> io::Result<()> {
    let mut upgraded = TokioIo::new(upgraded);
    let timed_target_io = TimeoutIO::new(target_io, Duration::from_secs(crate::IDLE_SECONDS));
    pin!(timed_target_io);
    let (_from_client, _from_server) =
        tokio::io::copy_bidirectional(&mut upgraded, &mut timed_target_io).await?;
    Ok(())
}
/// Returns the host and port of the given URI.
fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().map(|authority| authority.to_string())
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ReqLabels {
    // Use your own enum types to represent label values.
    pub referer: String,
    // Or just a plain string.
    pub path: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct AccessLabel {
    pub client: String,
    pub target: String,
    pub username: String,
}

impl Display for AccessLabel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.client, self.target)
    }
}

fn build_proxy_authenticate_resp() -> Response<BoxBody<Bytes, io::Error>> {
    let mut resp = Response::new(full_body("auth need"));
    resp.headers_mut().append(
        http::header::PROXY_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"are you kidding me\""),
    );
    *resp.status_mut() = http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
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
