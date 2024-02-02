#![deny(warnings)]
mod acceptor;
mod counter_io;
mod log_x;
mod net_monitor;
mod prom_label;
mod proxy;
mod tls_helper;
mod web_func;
#[macro_use]
mod macros;
mod config;
mod context;

use crate::config::Config;

use crate::tls_helper::tls_config;
use acceptor::TlsAcceptor;

use config::load_config;
use futures_util::future::select_all;
use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
// use hyper::server::conn::http1;
use context::Context;
use hyper::service::service_fn;
use hyper::{Error, Request, Response};
use hyper_util::rt::tokio::TokioIo;
use hyper_util::server::conn::auto;
use lazy_static::lazy_static;
use log::{debug, info, warn};
use proxy::ProxyHandler;
use std::error::Error as stdError;
use std::io;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};

const REFRESH_SECONDS: u64 = 60 * 60; // 1 hour
const IDLE_SECONDS: u64 = if !cfg!(debug_assertions) { 120 } else { 5 }; // 3 minutes

type DynError = Box<dyn stdError>; // wrapper for dyn Error

lazy_static! {
    static ref PROXY_HANDLER: ProxyHandler = ProxyHandler::new();
    static ref LOCAL_IP: String = local_ip().unwrap_or("0.0.0.0".to_string());
}

#[tokio::main]
async fn main() -> Result<(), DynError> {
    debug!("");
    let proxy_config: &'static Config = load_config();
    if let Err(e) = handle_signal() {
        warn!("handle signal error:{}", e);
        Err(e)?
    }

    let futures = proxy_config
        .port
        .iter()
        .map(|port| {
            let proxy_handler = PROXY_HANDLER.clone();
            async move { bootstrap(proxy_config, *port, proxy_handler).await }
        })
        .map(Box::pin)
        .collect::<Vec<_>>();
    let select_result = select_all(futures.into_iter()).await;
    if let Err(e) = select_result.0 {
        warn!("serve error:{}", e);
        Err(e)?
    }
    Ok(())
}

async fn bootstrap(
    config: &'static Config,
    port: u16,
    proxy_handler: ProxyHandler,
) -> Result<(), DynError> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!(
        "Listening on http{}://{}:{}",
        match config.over_tls {
            true => "s",
            false => "",
        },
        *LOCAL_IP,
        port
    );
    if config.over_tls {
        let mut acceptor = TlsAcceptor::new(
            tls_config(&config.key, &config.cert)?,
            TcpListener::bind(addr).await?,
        );

        let mut rx = match &config.tls_config_broadcast {
            Some(tls_config_broadcast) => tls_config_broadcast.subscribe(),
            None => {
                warn!("no tls config broadcast channel");
                return Err("no tls config broadcast channel".into());
            }
        };
        loop {
            tokio::select! {
                message = rx.recv() => {
                    let new_config = message.expect("Channel should not be closed");
                    info!("tls config is updated for port:{}",port);
                    // Replace the acceptor with the new one
                    acceptor.replace_config(new_config);
                }
                conn = acceptor.accept() => {
                    match conn {
                        Ok((conn,client_socket_addr)) => {
                            let io = TokioIo::new(conn);
                            let proxy_handler=proxy_handler.clone();
                            tokio::spawn(async move {
                                serve(io, proxy_handler, config, client_socket_addr).await;
                            });
                        }
                        Err(err) => {
                            warn!("Error accepting connection: {}", err);
                        }
                    }
                }
            }
        }
    } else {
        let tcp_listener = TcpListener::bind(addr).await?;
        loop {
            if let Ok((tcp_stream, client_socket_addr)) = tcp_listener.accept().await {
                let io = TokioIo::new(tcp_stream);
                let proxy_handler = proxy_handler.clone();
                tokio::task::spawn(async move {
                    serve(io, proxy_handler, config, client_socket_addr).await;
                });
            }
        }
    }
}

async fn serve<T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static>(
    io: TokioIo<T>,
    proxy_handler: ProxyHandler,
    config: &'static Config,
    client_socket_addr: SocketAddr,
) {
    let binding = auto::Builder::new(hyper_util::rt::tokio::TokioExecutor::new());
    let context = Arc::new(RwLock::new(Context::default()));
    let context_c = context.clone();
    let connection = binding.serve_connection_with_upgrades(
        io,
        service_fn(move |req| {
            proxy(
                req,
                config,
                client_socket_addr,
                proxy_handler.clone(),
                context.clone(),
            )
        }),
    );
    tokio::pin!(connection);
    loop {
        let (last_instant, upgraded) = context_c.read().unwrap().snapshot();
        if upgraded {
            tokio::select! {
                res = connection.as_mut() => {
                    if let Err(err)=res{
                        handle_hyper_error(client_socket_addr,err);
                    }
                    break;
                }
            }
        } else {
            tokio::select! {
                res = connection.as_mut() => {
                    if let Err(err)=res{
                        handle_hyper_error(client_socket_addr,err);
                    }
                    break;
                }
                _ = tokio::time::sleep_until(last_instant+Duration::from_secs(IDLE_SECONDS)) => {
                    let (instant,upgraded) = context_c.read().unwrap().snapshot();
                    if upgraded {
                        info!("upgraded from {}",client_socket_addr);
                        continue;
                    }else if instant <= last_instant {
                        info!("idle for {} seconds, graceful shutdown [{}]",IDLE_SECONDS,client_socket_addr);
                        connection.as_mut().graceful_shutdown();
                        break;
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
    config: &'static Config,
    client_socket_addr: SocketAddr,
    proxy_handler: ProxyHandler,
    context: Arc<RwLock<Context>>,
) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
    proxy_handler
        .proxy(req, config, client_socket_addr, context)
        .await
}

/// 处理hyper错误
/// # Arguments
/// * `client_socket_addr` - 客户端socket地址
/// * `http_err` - hyper错误
/// # Returns
/// * `()` - 无返回值
fn handle_hyper_error(client_socket_addr: SocketAddr, http_err: DynError) {
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
            #[cfg(debug_assertions)]
            {
                // 在 debug 模式下执行
                warn!(
                    "[hyper system error]: {:?} [client:{}]",
                    cause, client_socket_addr
                );
            }
            #[cfg(not(debug_assertions))]
            {
                // 在 release 模式下执行
                debug!(
                    "[hyper system error]: {:?} [client:{}]",
                    cause, client_socket_addr
                );
            }
        }
    } else {
        warn!(
            "[hyper other error]: {} [client:{}]",
            http_err, client_socket_addr
        );
    }
}

fn handle_signal() -> io::Result<()> {
    let mut terminate_signal = signal(SignalKind::terminate())?;
    tokio::spawn(async move {
        tokio::select! {
            _ = terminate_signal.recv() => {
                info!("receive terminate signal, exit");
                std::process::exit(0);
            },
            _ = tokio::signal::ctrl_c() => {
                info!("ctrl_c => shutdowning");
                std::process::exit(0); // 并不优雅关闭
            },
        };
    });
    Ok(())
}

pub fn local_ip() -> io::Result<String> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    socket
        .local_addr()
        .map(|local_addr| local_addr.ip().to_string())
}
