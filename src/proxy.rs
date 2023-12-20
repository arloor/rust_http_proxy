use std::{sync::Arc, net::SocketAddr, io::{self, ErrorKind}, borrow::Cow};

use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::{upgrade::Upgraded, Request, http, Response, body::Bytes, Method, Version, header::HeaderValue};
use hyper_util::rt::TokioIo;
use log::{debug, info, warn};
use percent_encoding::percent_decode_str;
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family},
    registry::Registry,
};
use rand::Rng;
use tokio::{sync::RwLock, net::TcpStream};
use hyper::client::conn::http1::Builder;

use crate::{StaticConfig, monitor::Monitor, web_func, build_proxy_authenticate_resp, empty, full};

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
}

#[derive(Clone)]
pub struct Proxy {
    registry: Arc<RwLock<Registry>>,
    http_requests: Family<ReqLabels, Counter, fn() -> Counter>,
    access: Family<AccessLabel, Counter, fn() -> Counter>,
    monitor: Monitor,
}

impl Proxy {
    pub async fn new() -> Proxy {
        let monitor:  Monitor = Monitor::new();
        monitor.start();
        let registry = <Registry>::default();
        let registry = Arc::new(RwLock::new(registry));
        let http_requests = Family::<ReqLabels, Counter>::default();
        registry.write().await.register(
            // With the metric name.
            "req_from_out",
            // And the metric help text.
            "Number of HTTP requests received",
            http_requests.clone(),
        );
        let access = Family::<AccessLabel, Counter>::default();
        registry.write().await.register(
            // With the metric name.
            "proxy_access",
            // And the metric help text.
            "num proxy_access",
            access.clone(),
        );
        Proxy {
            registry: registry.clone(),
            http_requests,
            access,
            monitor,
        }
    }
    pub async fn proxy(
        &self,
        mut req: Request<hyper::body::Incoming>,
        config: &'static StaticConfig,
        client_socket_addr: SocketAddr,
    ) -> Result<Response<BoxBody<Bytes, std::io::Error>>, io::Error> {
        let basic_auth = config.basic_auth;
        let ask_for_auth = config.ask_for_auth;
        if Method::CONNECT == req.method() {
            info!(
                "{:>21?} {:^7} {:?} {:?}",
                client_socket_addr,
                req.method().as_str(),
                req.uri(),req.version()
            );
        } else {
            if req.version() == Version::HTTP_2 || None == req.uri().host() {
                let raw_path = req.uri().path();
                let path = percent_decode_str(raw_path)
                    .decode_utf8()
                    .unwrap_or(Cow::from(raw_path));
                let path = path.as_ref();
                if basic_auth.len() != 0 && ask_for_auth { // 存在嗅探风险时，不伪装成http服务
                    return Err(io::Error::new(ErrorKind::PermissionDenied, "reject http GET/POST when ask_for_auth and basic_auth not empty"));
                }
                return Ok(web_func::serve_http_request(
                            &req,
                            client_socket_addr,
                            config,
                            path,
                            self.monitor.get_data().clone(),
                            self.http_requests.clone(),
                            self.registry.clone(),
                            ).await
                        );
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
                        .unwrap_or(&HeaderValue::from_str(host.as_str()).unwrap()),
                    req.headers()
                        .get(http::header::USER_AGENT)
                        .unwrap_or(&HeaderValue::from_str("None").unwrap())
                );
            };
        }

        if basic_auth.len() != 0 {
            //需要检验鉴权
            let mut authed: bool = false;
            match req.headers().get(http::header::PROXY_AUTHORIZATION) {
                None => warn!("no PROXY_AUTHORIZATION from {:?}", client_socket_addr),
                Some(header) => match header.to_str() {
                    Err(e) => warn!("解header失败，{:?} {:?}", header, e),
                    Ok(request_auth) => {
                        if request_auth == *basic_auth {
                            authed = true;
                        } else {
                            warn!(
                                "wrong PROXY_AUTHORIZATION from {:?}, wrong:{:?},right:{:?}",
                                client_socket_addr, request_auth, basic_auth
                            )
                        }
                    }
                },
            }
            if !authed {
                return if ask_for_auth {
                    Ok(build_proxy_authenticate_resp())
                } else {
                    Err(io::Error::new(ErrorKind::PermissionDenied, "wrong basic auth, closing socket..."))
                };
            }
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
                let access = self.access.clone();
                tokio::task::spawn(async move {
                    match hyper::upgrade::on(req).await {
                        Ok(upgraded) => {
                            let access_label = AccessLabel { client: client_socket_addr.ip().to_string(), target: addr.clone() };
                            if let Err(e) = tunnel(upgraded, addr, access, access_label).await {
                                warn!("server io error: {}", e);
                            };
                        }
                        Err(e) => warn!("upgrade error: {}", e),
                    }
                });
                let mut response = Response::new(empty());
                // 针对connect请求中，在响应中增加随机长度的padding，防止每次建连时tcp数据长度特征过于敏感
                let count = rand::thread_rng().gen_range(1..150);
                for _ in 0..count {
                    response.headers_mut().append(
                        http::header::SERVER,
                        HeaderValue::from_static("rust_http_proxy"),
                    );
                }
                Ok(response)
            } else {
                warn!("CONNECT host is not socket addr: {:?}", req.uri());
                let mut resp = Response::new(full("CONNECT must be to a socket address"));
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
            self.access.get_or_create(
                &AccessLabel { client: "all".to_string(), target: "all".to_string() }
            ).inc();
            self.access.get_or_create(
                &AccessLabel { client: client_socket_addr.ip().to_string(), target: format!("{}:{}", host, port) }
            ).inc();
            let io = TokioIo::new(stream);
            match Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .handshake(io).await
            {
                Ok((mut sender, conn)) => {
                    tokio::task::spawn(async move {
                        if let Err(err) = conn.await {
                            println!("Connection failed: {:?}", err);
                        }
                    });

                    if let Ok(resp) = sender.send_request(req).await {
                        return Ok(
                            resp.map(|b| b.map_err(|e| match e { e => io::Error::new(ErrorKind::InvalidData, e), })
                                .boxed()
                            )
                        );
                    } else {
                        return Err(io::Error::new(ErrorKind::ConnectionAborted, "连接失败"));
                    }
                }
                Err(e) => {
                    return Err(io::Error::new(ErrorKind::ConnectionAborted, e));
                }
            }
        }
    }
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(upgraded: Upgraded, addr: String, access: Family<AccessLabel, Counter, fn() -> Counter>, access_label: AccessLabel) -> std::io::Result<()> {
    // Connect to remote server
    let mut server = TcpStream::connect(addr.clone()).await?;
    access.get_or_create(
        &AccessLabel { client: "all".to_string(), target: "all".to_string() }
    ).inc();
    access.get_or_create(
        &access_label,
    ).inc();
    let mut upgraded = TokioIo::new(upgraded);

    // Proxying data
    let (from_client, from_server) =
        tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;

    // Print message when done
    debug!(
        "client wrote {} bytes and received {} bytes",
        from_client, from_server
    );

    Ok(())
}

fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().and_then(|auth| Some(auth.to_string()))
}
