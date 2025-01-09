#![deny(warnings)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
mod acceptor;
mod address;
mod config;
#[cfg(all(target_os = "linux", feature = "bpf"))]
mod ebpf;
mod http1_client;
mod ip_x;
#[cfg(target_os = "linux")]
mod linux_monitor;
mod proxy;
mod reverse;
mod tls_helper;
mod web_func;

use crate::config::Config;

use crate::ip_x::local_ip;
use crate::tls_helper::tls_config;
use acceptor::TlsAcceptor;
use config::load_config;
use futures_util::future::select_all;
use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use io_x::TimeoutIO;
use ip_x::SocketAddrFormat;
// use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Error, Request, Response};
use hyper_util::rt::tokio::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use log::{info, warn};
use proxy::ProxyHandler;
use std::error::Error as stdError;
use std::io;
use std::net::SocketAddr;

use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

const REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60); // 24 hour
pub(crate) const IDLE_TIMEOUT: Duration =
    Duration::from_secs(if !cfg!(debug_assertions) { 600 } else { 10 }); // 3 minutes

type DynError = Box<dyn stdError>; // wrapper for dyn Error

// 使用jemalloc作为全局内存分配器
#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

static LOCAL_IP: LazyLock<String> = LazyLock::new(|| local_ip().unwrap_or("0.0.0.0".to_string()));

#[tokio::main]
async fn main() -> Result<(), DynError> {
    let proxy_config: Config = load_config()?;
    let ports = proxy_config.port.clone();
    let proxy_handler = Arc::new(ProxyHandler::new(proxy_config)?);
    #[cfg(feature = "jemalloc")]
    info!("jemalloc is enabled");
    handle_signal()?;
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    crate::ebpf::init_once();
    let futures = ports
        .iter()
        .map(|port| {
            let proxy_handler = proxy_handler.clone();
            async move { bootstrap(*port, proxy_handler).await }
        })
        .map(Box::pin)
        .collect::<Vec<_>>();
    select_all(futures.into_iter()).await.0?;
    Ok(())
}
use socket2::{Domain, Protocol, Socket, Type};
async fn create_dual_stack_listener(port: u16) -> io::Result<TcpListener> {
    // 创建一个IPv6的socket
    let domain = Domain::IPV6;
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?; // 设置reuse_address以支持快速重启

    // 支持ipv4 + ipv6双栈
    socket.set_only_v6(false)?;
    // 绑定socket到地址和端口
    let addr = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port));
    socket.bind(&addr.into())?;
    socket.listen(1024)?; // 监听，1024为backlog的大小

    // 将socket2::Socket转换为std::net::TcpListener
    let std_listener = std::net::TcpListener::from(socket);
    std_listener.set_nonblocking(true)?;

    TcpListener::from_std(std_listener)
}

async fn bootstrap(port: u16, proxy_handler: Arc<ProxyHandler>) -> Result<(), DynError> {
    let config = &proxy_handler.config;
    info!(
        "Listening on http{}://{}:{}",
        match config.over_tls {
            true => "s",
            false => "",
        },
        LOCAL_IP.as_str(),
        port
    );
    if config.over_tls {
        let mut acceptor = TlsAcceptor::new(
            tls_config(&config.key, &config.cert)?,
            create_dual_stack_listener(port).await?,
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
                    #[allow(clippy::expect_used)]
                    let new_config = message.expect("Channel should not be closed");
                    info!("tls config is updated for port:{}",port);
                    // Replace the acceptor with the new one
                    acceptor.replace_config(new_config);
                }
                conn = acceptor.accept() => {
                    match conn {
                        Ok((conn,client_socket_addr)) => {
                            let proxy_handler=proxy_handler.clone();
                            tokio::spawn(async move {
                                serve(conn, proxy_handler, client_socket_addr).await;
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
        let tcp_listener = create_dual_stack_listener(port).await?;
        loop {
            if let Ok((tcp_stream, client_socket_addr)) = tcp_listener.accept().await {
                let proxy_handler = proxy_handler.clone();
                tokio::task::spawn(async move {
                    serve(tcp_stream, proxy_handler, client_socket_addr).await;
                });
            }
        }
    }
}

async fn serve<T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static>(
    io: T,
    proxy_handler: Arc<ProxyHandler>,
    client_socket_addr: SocketAddr,
) {
    let timed_io = TimeoutIO::new(io, IDLE_TIMEOUT);
    let timed_io = Box::pin(timed_io);
    if let Err(err) = auto::Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(
            TokioIo::new(timed_io),
            service_fn(|req| proxy(req, client_socket_addr, proxy_handler.clone())),
        )
        .await
    {
        handle_hyper_error(client_socket_addr, err);
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
    client_socket_addr: SocketAddr,
    proxy_handler: Arc<ProxyHandler>,
) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
    proxy_handler
        .proxy(req, client_socket_addr)
        .await
        .map_err(|e| {
            warn!("proxy error:{}", e);
            e
        })
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
                "[hyper user error]: {:?} from {}",
                cause,
                SocketAddrFormat(&client_socket_addr)
            );
        } else {
            // 系统错误
            log::debug!(
                "[hyper system error]: {:?} from {}",
                cause,
                SocketAddrFormat(&client_socket_addr)
            );
        }
    } else if let Some(io_err) = http_err.downcast_ref::<io::Error>() {
        // 转换为io::Error
        warn!(
            "[hyper io error]: [{}] {} from {}",
            io_err.kind(),
            io_err,
            SocketAddrFormat(&client_socket_addr)
        );
    } else {
        warn!(
            "[hyper other error]: {} from {}",
            http_err,
            SocketAddrFormat(&client_socket_addr)
        );
    }
}

#[cfg(unix)]
fn handle_signal() -> io::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
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

#[cfg(windows)]
fn handle_signal() -> io::Result<()> {
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        info!("ctrl_c => shutdowning");
        std::process::exit(0); // 并不优雅关闭
    });
    Ok(())
}
