#![deny(warnings)]

mod logx;
mod monitor;
mod tls_helper;
mod web_func;

use hyper_util::server::conn::auto;
use hyper::client::conn::http1::Builder;
use crate::logx::init_log;
use crate::tls_helper::rust_tls_acceptor;
use hyper::http::HeaderValue;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper::{Error, http, Method, Request, Response, Version};
use log::{debug, info, warn};
use hyper_util::rt::tokio::TokioIo;
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
use std::error::Error as stdError;
use std::io::ErrorKind;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use std::net::UdpSocket;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Bytes;
use tls_listener::TlsListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::RwLock;


const TRUE: &str = "true";
const REFRESH_TIME: u64 = 24 * 60 * 60;

pub struct StaticConfig {
    log_dir: &'static String,
    log_file: &'static String,
    port: u16,
    cert: &'static String,
    raw_key: &'static String,
    basic_auth: &'static String,
    web_content_path: &'static String,
    refer: &'static String,
    ask_for_auth: bool,
    over_tls: bool,
    hostname: &'static String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config_from_env();
    let config: &'static StaticConfig = Box::leak(Box::new(config));
    info(config);
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let monitor: &'static Monitor = Box::leak(Box::new(Monitor::new()));
    monitor.start();
    let mut terminate_signal = signal(SignalKind::terminate())?;
    if config.over_tls {
        let mut listener = TlsListener::new(rust_tls_acceptor(&config.raw_key, &config.cert)?, TcpListener::bind(addr).await?);
        let (tx, mut rx) = mpsc::channel::<tokio_rustls::TlsAcceptor>(1);

        let mut last_refresh_time = SystemTime::now();
        loop {
            tokio::select! {
                _=terminate_signal.recv()=>{
                    info!("rust_http_proxy is shutdowning");
                    std::process::exit(0); // 并不优雅关闭
                },
                conn = listener.accept() => {
                    match conn {
                        Ok((conn,client_socket_addr)) => {
                            let io = TokioIo::new(conn);
                            let now = SystemTime::now();
                            if now.duration_since(last_refresh_time).unwrap_or(Duration::from_secs(0)) > Duration::from_secs(REFRESH_TIME) {
                                last_refresh_time = now;
                                if let Ok(new_acceptor)=rust_tls_acceptor(&config.raw_key, &config.cert){
                                    info!("Rotating certificate triggered...");
                                    tx.try_send(new_acceptor).ok(); // 防止阻塞
                                    // tx.send(new_acceptor).await.ok();
                                }
                            }
                            tokio::spawn(async move {
                                let binding =auto::Builder::new(hyper_util::rt::tokio::TokioExecutor::new());// http2 but no with_upgrades support
                                let connection =
                                    binding.serve_connection_with_upgrades(io, service_fn(move |req| {
                                        proxy(req, config, client_socket_addr, monitor.get_data().clone())
                                    }));
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
        let tcp_listener = TcpListener::bind(addr).await?;
        loop {
            tokio::select! {
                _=terminate_signal.recv()=>{
                    info!("rust_http_proxy is shutdowning");
                    std::process::exit(0); // 并不优雅关闭
                },
                conn=tcp_listener.accept()=>{
                    if let Ok((tcp_stream, client_socket_addr)) =conn{
                                    let io = TokioIo::new(tcp_stream);
            tokio::task::spawn(async move {
                let connection = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req| {
                            proxy(
                                req,
                                config,
                                client_socket_addr,
                                monitor.get_data().clone(),
                            )
                        }),
                    )
                    .with_upgrades();
                if let Err(http_err) = connection.await {
                    handle_hyper_error(client_socket_addr, Box::new(http_err));
                }
            });
                    }
                }
            }
        }
    }
}

fn info(config: &StaticConfig) {
    info!("log is output to {}/{}", config.log_dir, config.log_file);
    info!("hostname seems to be {}", config.hostname);
    if config.basic_auth.len() != 0 && config.ask_for_auth {
        warn!("do not serve web content to avoid being detected!");
    } else {
        info!("serve web content of \"{}\"", config.web_content_path);
        if config.refer.len() != 0 {
            info!("Referer header to images must contain \"{}\"",config.refer);
        }
    }
    info!("basic auth is \"{}\"", config.basic_auth);
    if config.basic_auth.contains("\"") || config.basic_auth.contains("\'") {
        warn!("basic_auth contains quotation marks, please check if it is a mistake!")
    }
    info!(
            "Listening on http{}://{}:{}",
            match config.over_tls{
                true=>"s",
                false=>"",
            },
            local_ip().unwrap_or("0.0.0.0".to_string()),
            config.port
        );
}

fn handle_hyper_error(client_socket_addr: SocketAddr, http_err: Box<dyn std::error::Error>) {
    if let Some(http_err) = http_err.downcast_ref::<Error>() {
        let cause = match http_err.source() {
            None => { http_err }
            Some(e) => { e } // 解析cause
        };
        if http_err.is_user() {
            warn!("[hyper user error]: {:?} [client:{}]",
                cause,
                client_socket_addr
            );
        } else {
            debug!("[hyper system error]: {:?} [client:{}]",
                cause,
                client_socket_addr
            )
        }
    } else {
        warn!(
            "[hyper other error]: {} [client:{}]",
            http_err,
            client_socket_addr
        );
    }
}

fn load_config_from_env() -> StaticConfig {
    let config = StaticConfig {
        log_dir: Box::leak(Box::new(env::var("log_dir").unwrap_or("/tmp".to_string()))),
        log_file: Box::leak(Box::new(env::var("log_file").unwrap_or("proxy.log".to_string()))),
        port: env::var("port").unwrap_or("3128".to_string()).parse::<u16>().unwrap_or(444),
        cert: Box::leak(Box::new(env::var("cert").unwrap_or("cert.pem".to_string()))),
        raw_key: Box::leak(Box::new(env::var("raw_key").unwrap_or(env::var("key").unwrap_or("privkey.pem".to_string())))),
        basic_auth: Box::leak(Box::new(env::var("basic_auth").unwrap_or("".to_string()))),
        web_content_path: Box::leak(Box::new(env::var("web_content_path").unwrap_or("/usr/share/nginx/html".to_string()))),
        refer: Box::leak(Box::new(env::var("refer").unwrap_or("".to_string()))),
        ask_for_auth: TRUE == env::var("ask_for_auth").unwrap_or("true".to_string()),
        over_tls: TRUE == env::var("over_tls").unwrap_or("false".to_string()),
        hostname: Box::leak(Box::new(env::var("HOSTNAME").unwrap_or(local_ip().unwrap_or("未知".to_string())))),
    };
    init_log(config.log_dir, config.log_file);
    return config;
}

async fn proxy(
    mut req: Request<hyper::body::Incoming>,
    config: &'static StaticConfig,
    client_socket_addr: SocketAddr,
    buffer: Arc<RwLock<VecDeque<Point>>>,
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

        let stream = TcpStream::connect((host, port)).await.unwrap();
        let io = TokioIo::new(stream);
        match Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(io)
            .await {
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

fn build_proxy_authenticate_resp() -> Response<BoxBody<Bytes, std::io::Error>> {
    let mut resp = Response::new(full("auth need"));
    resp.headers_mut().append(
        http::header::PROXY_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"are you kidding me\""),
    );
    *resp.status_mut() = http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
    resp
}

fn _build_500_resp() -> Response<BoxBody<Bytes, std::io::Error>> {
    let mut resp = Response::new(full("Internal Server Error"));
    *resp.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
    resp
}

fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().and_then(|auth| Some(auth.to_string()))
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(upgraded: Upgraded, addr: String) -> std::io::Result<()> {
    // Connect to remote server
    let mut server = TcpStream::connect(addr).await?;
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

pub fn local_ip() -> io::Result<String> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    return socket
        .local_addr()
        .map(|local_addr| local_addr.ip().to_string());
}

fn empty() -> BoxBody<Bytes, std::io::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, std::io::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}
