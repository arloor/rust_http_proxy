// #![deny(warnings)]
// #![deny(clippy::unwrap_used)]
// #![deny(clippy::expect_used)]
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
mod web_func;

use crate::config::Config;

use axum::body::Body;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use axum_bootstrap::{AppError, ReqInterceptor, TlsParam};
use config::load_config;
use futures_util::future::select_all;
use http::StatusCode;
use ip_x::local_ip;
use log::info;
use proxy::ProxyHandler;
use std::error::Error as stdError;
use std::io;
use std::os::unix::net::SocketAddr;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;

use std::sync::Arc;
use std::time::Duration;

pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(if !cfg!(debug_assertions) { 600 } else { 10 }); // 3 minutes

type DynError = Box<dyn stdError + Send + Sync>; // wrapper for dyn Error

// 使用jemalloc作为全局内存分配器
#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

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

#[derive(Clone)]
struct ProxyInterceptor {
    proxy_handler: Arc<ProxyHandler>,
}

impl ReqInterceptor for ProxyInterceptor {
    fn intercept(
        &self, req: http::Request<hyper::body::Incoming>, ip: std::net::SocketAddr,
    ) -> impl std::future::Future<Output = axum_bootstrap::InterceptResult> + Send {
        let proxy_handler = self.proxy_handler.clone();
        async move {
            let result = proxy_handler.proxy(req, ip).await;
            match result {
                Ok(response) => {
                    let (parts, body) = response.into_parts();
                    axum_bootstrap::InterceptResult::Return(Response::from_parts(parts, Body::new(body)))
                }
                Err(err) => {
                    log::error!("Error handling request: {}", err);
                    axum_bootstrap::InterceptResult::Error(AppError::new(err))
                }
            }
        }
    }
}

async fn bootstrap(port: u16, proxy_handler: Arc<ProxyHandler>) -> Result<(), DynError> {
    let config = &proxy_handler.config;
    let tls_param = match config.over_tls {
        true => Some(TlsParam {
            tls: true,
            cert: config.cert.to_string(),
            key: config.key.to_string(),
        }),
        false => None,
    };
    axum_bootstrap::Server::<ProxyInterceptor>::new_with_interceptor(
        port,
        tls_param,
        ProxyInterceptor {
            proxy_handler: proxy_handler.clone(),
        },
        build_router(),
    )
    .run()
    .await
    // let config = &proxy_handler.config;
    // info!(
    //     "Listening on http{}://{}:{}",
    //     match config.over_tls {
    //         true => "s",
    //         false => "",
    //     },
    //     LOCAL_IP.as_str(),
    //     port
    // );
    // if config.over_tls {
    //     let mut acceptor =
    //         TlsAcceptor::new(tls_config(&config.key, &config.cert)?, create_dual_stack_listener(port).await?);

    //     let mut rx = match &config.tls_config_broadcast {
    //         Some(tls_config_broadcast) => tls_config_broadcast.subscribe(),
    //         None => {
    //             warn!("no tls config broadcast channel");
    //             return Err("no tls config broadcast channel".into());
    //         }
    //     };
    //     loop {
    //         tokio::select! {
    //             message = rx.recv() => {
    //                 #[allow(clippy::expect_used)]
    //                 let new_config = message.expect("Channel should not be closed");
    //                 info!("tls config is updated for port:{}",port);
    //                 // Replace the acceptor with the new one
    //                 acceptor.replace_config(new_config);
    //             }
    //             conn = acceptor.accept() => {
    //                 match conn {
    //                     Ok((conn,client_socket_addr)) => {
    //                         let proxy_handler=proxy_handler.clone();
    //                         tokio::spawn(async move {
    //                             serve(conn, proxy_handler, client_socket_addr).await;
    //                         });
    //                     }
    //                     Err(err) => {
    //                         warn!("Error accepting connection: {}", err);
    //                     }
    //                 }
    //             }
    //         }
    //     }
    // } else {
    //     let tcp_listener = create_dual_stack_listener(port).await?;
    //     loop {
    //         if let Ok((tcp_stream, client_socket_addr)) = tcp_listener.accept().await {
    //             let proxy_handler = proxy_handler.clone();
    //             tokio::task::spawn(async move {
    //                 serve(tcp_stream, proxy_handler, client_socket_addr).await;
    //             });
    //         }
    //     }
    // }
}

pub(crate) fn build_router() -> Router {
    // build our application with a route
    Router::new()
        .route("/", get(|| async { (StatusCode::OK, "OK") }))
        .layer((CorsLayer::permissive(), TimeoutLayer::new(Duration::from_secs(30)), CompressionLayer::new()))
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
