#![deny(warnings)]

mod logx;
mod monitor;
mod tls_helper;
mod web_func;

use crate::logx::init_log;
use crate::tls_helper::rust_tls_acceptor;
use hyper::client::HttpConnector;
use hyper::http::HeaderValue;
use hyper::server::conn::AddrIncoming;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{http, Body, Client, Method, Request, Response, Version, Error};
use log::{debug, info, warn};
use monitor::Monitor;
use monitor::Point;
use percent_encoding::percent_decode_str;
use rand::Rng;
use std::borrow::Cow;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::{env, io};
use std::io::ErrorKind;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

type HttpClient = Client<hyper::client::HttpConnector>;

const TRUE: &str = "true";
const REFRESH_TIME: u64 = 24 * 60 * 60;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    config_log();
    let port = env::var("port")
        .unwrap_or("3128".to_string())
        .parse::<u16>()
        .unwrap_or(444);
    let cert = env::var("cert").unwrap_or("cert.pem".to_string());
    let raw_key =
        env::var("raw_key").unwrap_or(env::var("key").unwrap_or("privkey.pem".to_string()));
    let basic_auth: &'static String =
        Box::leak(Box::new(env::var("basic_auth").unwrap_or("".to_string())));
    let web_content_path: &'static String = Box::leak(Box::new(
        env::var("web_content_path").unwrap_or("/usr/share/nginx/html".to_string()),
    )); //默认为工作目录下
    let ask_for_auth = TRUE == env::var("ask_for_auth").unwrap_or("true".to_string());
    let over_tls = TRUE == env::var("over_tls").unwrap_or("false".to_string());
    let hostname: &'static String = Box::leak(Box::new(
        env::var("HOSTNAME").unwrap_or(local_ip().unwrap_or("未知".to_string())),
    ));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let client: &'static Client<HttpConnector> = Box::leak(Box::new(
        Client::builder()
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .build_http(),
    ));
    info!("hostname seems to be {}", hostname);
    if basic_auth.len() != 0 && ask_for_auth {
        warn!("do not serve web content to avoid being detected!");
    } else {
        info!("serve web content of \"{}\"", web_content_path);
    }
    info!("basic auth is \"{}\"", basic_auth);
    if basic_auth.contains("\"") || basic_auth.contains("\'"){
        warn!("basic_auth contains quotation marks, please check if it is a mistake!")
    }
    let monitor: &'static Monitor = Box::leak(Box::new(Monitor::new()));
    monitor.start();
    if over_tls {
        info!(
            "Listening on https://{}:{}",
            local_ip().unwrap_or("0.0.0.0".to_string()),
            addr.port()
        );
        let mut listener = tls_listener::builder(rust_tls_acceptor(&raw_key, &cert)?)
            .max_handshakes(10)
            .listen(AddrIncoming::bind(&addr).unwrap());
        let (tx, mut rx) = mpsc::channel::<tokio_rustls::TlsAcceptor>(1);
        let http = Http::new();
        let mut last_refresh_time = SystemTime::now();
        loop {
            tokio::select! {
                conn = listener.accept() => {
                    match conn.expect("Tls listener stream should be infinite") {
                        Ok(conn) => {
                            let now = SystemTime::now();
                            if now.duration_since(last_refresh_time).unwrap_or(Duration::from_secs(0)) > Duration::from_secs(REFRESH_TIME) {
                                last_refresh_time = now;
                                if let Ok(new_acceptor)=rust_tls_acceptor(&raw_key, &cert){
                                    info!("Rotating certificate triggered...");
                                    tx.try_send(new_acceptor).ok(); // 防止阻塞
                                    // tx.send(new_acceptor).await.ok();
                                }
                            }
                            let mut http = http.clone();
                            tokio::spawn(async move {
                                let client_socket_addr = conn.get_ref().0.remote_addr();
                                let connection = http
                                    .http1_title_case_headers(true)
                                    .http1_header_read_timeout(Duration::from_secs(30))
                                    .http2_keep_alive_interval(Duration::from_secs(15))
                                    .http2_keep_alive_timeout(Duration::from_secs(15))
                                    .serve_connection(conn, service_fn(move |req| {
                                        proxy(client, req, basic_auth, ask_for_auth, web_content_path, hostname, client_socket_addr, monitor.get_buffer().clone())
                                    }))
                                    .with_upgrades();
                                if let Err(err) = connection.await {
                                     handle_hyper_error(client_socket_addr,err);
                                }
                            });
                        }
                        Err(err) => {
                            warn!("Error accepting connection: {}", err);
                        }
                    }
                },
                message = rx.recv() => {
                    let acceptor = message.expect("Channel should not be closed");
                    info!("Rotating certificate...");
                    listener.replace_acceptor(acceptor);
                }
            }
        }
    } else {
        info!(
            "Listening on http://{}:{}",
            local_ip().unwrap_or("0.0.0.0".to_string()),
            addr.port()
        );
        let tcp_listener = TcpListener::bind(addr).await?;
        loop {
            let (tcp_stream, _) = tcp_listener.accept().await?;
            let client_socket_addr = tcp_stream.peer_addr()?;
            tokio::task::spawn(async move {
                let connection = Http::new()
                    .http1_only(true)
                    .http1_keep_alive(true)
                    .serve_connection(
                        tcp_stream,
                        service_fn(move |req| {
                            proxy(
                                client,
                                req,
                                basic_auth,
                                ask_for_auth,
                                web_content_path,
                                hostname,
                                client_socket_addr,
                                monitor.get_buffer().clone(),
                            )
                        }),
                    )
                    .with_upgrades();
                if let Err(http_err) = connection.await {
                    handle_hyper_error(client_socket_addr, http_err);
                }
            });
        }
    }
}

fn handle_hyper_error(client_socket_addr: SocketAddr, http_err: Error) {
    if http_err.is_user() {
        warn!("{} from {}",http_err,client_socket_addr);
    } else {
        debug!("hyper error: {}",http_err);
    }
}

fn config_log() {
    let log_dir = env::var("log_dir").unwrap_or("/tmp".to_string());
    let log_file = env::var("log_file").unwrap_or("proxy.log".to_string());
    init_log(&log_dir, &log_file);
    info!("log is output to {}/{}", &log_dir, &log_file);
}

async fn proxy(
    client: &HttpClient,
    mut req: Request<Body>,
    basic_auth: &String,
    ask_for_auth: bool,
    web_content_path: &String,
    hostname: &String,
    client_socket_addr: SocketAddr,
    buffer: Arc<RwLock<VecDeque<Point>>>,
) -> Result<Response<Body>, io::Error> {
    if Method::CONNECT == req.method() {
        info!(
            "{:>21?} {:^7} {:?}",
            client_socket_addr,
            req.method().as_str(),
            req.uri()
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
                web_content_path,
                hostname,
                path,
                buffer,
            )
                .await);
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
                Err(io::Error::new(ErrorKind::PermissionDenied, "close connection because of wrong basic auth"))
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
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(upgraded, addr).await {
                            warn!("server io error: {}", e);
                        };
                    }
                    Err(e) => warn!("upgrade error: {}", e),
                }
            });
            let mut response = Response::new(Body::empty());
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
            let mut resp = Response::new(Body::from("CONNECT must be to a socket address"));
            *resp.status_mut() = http::StatusCode::BAD_REQUEST;

            Ok(resp)
        }
    } else {
        // 删除代理特有的请求头
        req.headers_mut()
            .remove(http::header::PROXY_AUTHORIZATION.to_string());
        req.headers_mut().remove("Proxy-Connection");
        client.request(req).await.map_err(|e| io::Error::new(ErrorKind::Other, e))
    }
}

fn build_proxy_authenticate_resp() -> Response<Body> {
    let mut resp = Response::new(Body::from("auth need"));
    resp.headers_mut().append(
        http::header::PROXY_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"are you kidding me\""),
    );
    *resp.status_mut() = http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
    resp
}

fn _build_500_resp() -> Response<Body> {
    let mut resp = Response::new(Body::from("Internal Server Error"));
    *resp.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
    resp
}

fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().and_then(|auth| Some(auth.to_string()))
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(mut upgraded: Upgraded, addr: String) -> std::io::Result<()> {
    // Connect to remote server
    let mut server = TcpStream::connect(addr).await?;

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

use std::net::UdpSocket;
use tokio::sync::RwLock;

pub fn local_ip() -> io::Result<String> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    return socket
        .local_addr()
        .map(|local_addr| local_addr.ip().to_string());
}
