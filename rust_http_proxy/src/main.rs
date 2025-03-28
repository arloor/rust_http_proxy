#![deny(warnings)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
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

use axum::routing::get;
use axum::Router;
use axum_bootstrap::{AppError, InterceptResult, ReqInterceptor, TlsParam};
use chrono::Local;
use config::load_config;
use futures_util::future::select_all;
use http::{HeaderMap, StatusCode};
use log::info;
use proxy::ProxyHandler;
use std::error::Error as stdError;
use std::io;
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
    // handle_signal()?;
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
                Ok(adaptor) => adaptor.into(),
                Err(err) => InterceptResult::Error(AppError::new(err)),
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
    axum_bootstrap::new_server_with_interceptor::<ProxyInterceptor>(
        port,
        tls_param,
        ProxyInterceptor { proxy_handler },
        build_router(),
    )
    .with_timeout(IDLE_TIMEOUT)
    .run()
    .await
}

pub(crate) const BODY404: &str = include_str!("../html/404.html");
pub(crate) fn build_router() -> Router {
    // build our application with a route
    Router::new()
        .route("/time", get(|| async { (StatusCode::OK, format!("{}", Local::now())) }))
        .fallback(get(|| async {
            let mut header_map = HeaderMap::new();
            #[allow(clippy::expect_used)]
            header_map.insert("content-type", "text/html; charset=utf-8".parse().expect("should be valid header"));
            (StatusCode::NOT_FOUND, header_map, BODY404)
        }))
        .layer((CorsLayer::permissive(), TimeoutLayer::new(Duration::from_secs(30)), CompressionLayer::new()))
}

#[cfg(unix)]
#[allow(unused)]
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
#[allow(unused)]
fn handle_signal() -> io::Result<()> {
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        info!("ctrl_c => shutdowning");
        std::process::exit(0); // 并不优雅关闭
    });
    Ok(())
}
