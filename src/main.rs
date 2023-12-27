// #![deny(warnings)]
#[allow(dead_code)]

mod log_x;
mod net_monitor;
mod proxy;
mod tls_helper;
mod web_func;
mod acceptor;

use crate::log_x::init_log;
use crate::tls_helper::rust_tls_acceptor;
use acceptor::TlsAcceptor;
use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Error, Request, Response};
use hyper_util::rt::tokio::TokioIo;
use hyper_util::server::conn::auto;
use log::{debug, info, warn};
use proxy::ProxyHandler;
use tokio_rustls::rustls::ServerConfig;
use std::error::Error as stdError;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::sync::Arc;
use std::time::Duration;
use std::{env, io};
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tokio::time;

const TRUE: &str = "true";
const REFRESH_SECONDS: u64 = 24 * 60 * 60; // 1 day

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proxy_config: &'static ProxyConfig = load_config_from_env();
    serve(proxy_config).await?;
    Ok(())
}

async fn serve(config: &'static ProxyConfig) -> Result<(), Box<dyn std::error::Error>> {
    let proxy_handler = ProxyHandler::new().await;
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let mut terminate_signal = signal(SignalKind::terminate())?;
    if config.over_tls {
        info!("featured mine TlsAcceptor");
        let mut acceptor = TlsAcceptor::new(tls_helper::tls_config(&config.raw_key, &config.cert)?,
        TcpListener::bind(addr).await?);
        let mut rx = init_listener_config_refresh_task(config);
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("ctrl_c => shutdowning");
                    std::process::exit(0); // 并不优雅关闭
                },
                _ = terminate_signal.recv()=>{
                    info!("rust_http_proxy is shutdowning");
                    std::process::exit(0); // 并不优雅关闭
                },
                conn = acceptor.accept() => {
                    match conn {
                        Ok((conn,client_socket_addr)) => {
                            let io = TokioIo::new(conn);
                            let proxy_handler=proxy_handler.clone();
                            tokio::spawn(async move {
                                let binding =auto::Builder::new(hyper_util::rt::tokio::TokioExecutor::new());
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
                    let new_config = message.expect("Channel should not be closed");
                    info!("tls config is updated");
                    // Replace the acceptor with the new one
                    acceptor.replace_config(new_config);
                }
            }
        }
    } else {
        let tcp_listener = TcpListener::bind(addr).await?;
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("ctrl_c => shutdowning");
                    std::process::exit(0); // 并不优雅关闭
                },
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

/// 代理请求
/// # Arguments
/// * `req` - hyper::Request
/// * `config` - 全局配置
/// * `client_socket_addr` - 客户端socket地址
/// * `proxy_handler` - 代理处理器
/// # Returns
/// * `Result<Response<BoxBody<Bytes, io::Error>>, io::Error>` - hyper::Response
async fn proxy(
    req: Request<hyper::body::Incoming>,
    config: &'static ProxyConfig,
    client_socket_addr: SocketAddr,
    proxy_handler: ProxyHandler,
) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
    proxy_handler.proxy(req, config, client_socket_addr).await
}

fn log_config(config: &ProxyConfig) {
    info!("log is output to {}/{}", config.log_dir, config.log_file);
    info!("hostname seems to be {}", config.hostname);
    if config.basic_auth.len() != 0 && config.ask_for_auth {
        warn!("do not serve web content to avoid being detected!");
    } else {
        info!("serve web content of \"{}\"", config.web_content_path);
        if config.refer.len() != 0 {
            info!("Referer header to images must contain \"{}\"", config.refer);
        }
    }
    info!("basic auth is \"{}\"", config.basic_auth);
    if config.basic_auth.contains("\"") || config.basic_auth.contains("\'") {
        warn!("basic_auth contains quotation marks, please check if it is a mistake!")
    }
    info!(
        "Listening on http{}://{}:{}",
        match config.over_tls {
            true => "s",
            false => "",
        },
        local_ip().unwrap_or("0.0.0.0".to_string()),
        config.port
    );
}

/// 处理hyper错误
/// # Arguments
/// * `client_socket_addr` - 客户端socket地址
/// * `http_err` - hyper错误
/// # Returns
/// * `()` - 无返回值
fn handle_hyper_error(client_socket_addr: SocketAddr, http_err: Box<dyn std::error::Error>) {
    if let Some(http_err) = http_err.downcast_ref::<Error>() {
        // 转换为hyper::Error
        let cause = match http_err.source() {
            None => http_err,
            Some(e) => e, // 解析cause
        };
        if http_err.is_user() {
            // 判断是否是用户错误
            warn!(
                "[hyper user error]: {:?} [client:{}]",
                cause, client_socket_addr
            );
        } else {
            // 系统错误
            debug!(
                "[hyper system error]: {:?} [client:{}]",
                cause, client_socket_addr
            )
        }
    } else {
        warn!(
            "[hyper other error]: {} [client:{}]",
            http_err, client_socket_addr
        );
    }
}

fn load_config_from_env() -> &'static ProxyConfig {
    let config = ProxyConfig {
        log_dir: Box::leak(Box::new(env::var("log_dir").unwrap_or("/tmp".to_string()))),
        log_file: Box::leak(Box::new(
            env::var("log_file").unwrap_or("proxy.log".to_string()),
        )),
        port: env::var("port")
            .unwrap_or("3128".to_string())
            .parse::<u16>()
            .unwrap_or(444),
        cert: Box::leak(Box::new(env::var("cert").unwrap_or("cert.pem".to_string()))),
        raw_key: Box::leak(Box::new(
            env::var("raw_key").unwrap_or(env::var("key").unwrap_or("privkey.pem".to_string())),
        )),
        basic_auth: Box::leak(Box::new(env::var("basic_auth").unwrap_or("".to_string()))),
        web_content_path: Box::leak(Box::new(
            env::var("web_content_path").unwrap_or("/usr/share/nginx/html".to_string()),
        )),
        refer: Box::leak(Box::new(env::var("refer").unwrap_or("".to_string()))),
        ask_for_auth: TRUE == env::var("ask_for_auth").unwrap_or("true".to_string()),
        over_tls: TRUE == env::var("over_tls").unwrap_or("false".to_string()),
        hostname: Box::leak(Box::new(
            env::var("HOSTNAME").unwrap_or(local_ip().unwrap_or("未知".to_string())),
        )),
    };
    if let Err(log_init_error) = init_log(config.log_dir, config.log_file) {
        println!("init log error:{}", log_init_error);
        std::process::exit(1);
    }
    log_config(&config);
    return Box::leak(Box::new(config));
}

pub fn local_ip() -> io::Result<String> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    return socket
        .local_addr()
        .map(|local_addr| local_addr.ip().to_string());
}

fn init_listener_config_refresh_task(
    config: &'static ProxyConfig,
) -> mpsc::Receiver<Arc<ServerConfig>> {
    let (tx, rx) = mpsc::channel::<Arc<ServerConfig>>(1);
    tokio::spawn(async move {
        info!("update tls config every {} seconds", REFRESH_SECONDS);
        loop {
            time::sleep(Duration::from_secs(REFRESH_SECONDS)).await;
            if let Ok(new_acceptor) = tls_helper::tls_config(&config.raw_key, &config.cert) {
                info!("update tls config");
                tx.try_send(new_acceptor).ok(); // 防止阻塞
            }
        }
    });
    return rx;
}

/// Represents the global configuration for the HTTP proxy server.
pub struct ProxyConfig {
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
