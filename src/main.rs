#![deny(warnings)]

mod log_x;
mod net_monitor;
mod tls_helper;
mod web_func;
mod proxy;


use hyper_util::server::conn::auto;
use proxy::Proxy;
use crate::log_x::init_log;
use crate::tls_helper::rust_tls_acceptor;
use hyper::http::HeaderValue;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Error, http, Request, Response};
use log::{debug, info, warn};
use hyper_util::rt::tokio::TokioIo;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
use std::{env, io};
use std::error::Error as stdError;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use std::net::UdpSocket;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Bytes;
use tls_listener::TlsListener;
use tokio::signal::unix::{signal, SignalKind};


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
    let proxy_handler = Proxy::new().await;
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let mut terminate_signal = signal(SignalKind::terminate())?;
    if config.over_tls {
        let mut listener = TlsListener::new(rust_tls_acceptor(&config.raw_key, &config.cert)?, TcpListener::bind(addr).await?);
        let (tx, mut rx) = mpsc::channel::<tokio_rustls::TlsAcceptor>(1);

        let mut last_refresh_time = SystemTime::now();
        loop {
            tokio::select! {
                _ = terminate_signal.recv()=>{
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
                            let proxy_handler=proxy_handler.clone();
                            tokio::spawn(async move {
                                let binding =auto::Builder::new(hyper_util::rt::tokio::TokioExecutor::new());// http2 but no with_upgrades support
                                let connection =
                                    binding.serve_connection_with_upgrades(io, service_fn(move |req| {
                                        proxy(
                                            req,
                                            config,
                                            client_socket_addr,
                                            proxy_handler.clone()
                                        )
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
                _ = terminate_signal.recv()=>{
                    info!("rust_http_proxy is shutdowning");
                    std::process::exit(0); // 并不优雅关闭
                },
                conn = tcp_listener.accept()=>{
                    if let Ok((tcp_stream, client_socket_addr)) =conn{
                        let io = TokioIo::new(tcp_stream);
                        let proxy_handler=proxy_handler.clone();
                        tokio::task::spawn(async move {
                            let connection = http1::Builder::new()
                                .serve_connection(
                                    io,
                                    service_fn(move |req| {
                                        proxy(
                                            req,
                                            config,
                                            client_socket_addr,
                                            proxy_handler.clone()
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

async fn proxy(req: Request<hyper::body::Incoming>,
               config: &'static StaticConfig,
               client_socket_addr: SocketAddr,
               proxy_handler: Proxy,
) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
    proxy_handler.proxy(req, config, client_socket_addr).await
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
