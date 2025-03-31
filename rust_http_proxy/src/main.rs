#![deny(warnings)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
mod address;
mod axum_handler;
mod config;
#[cfg(all(target_os = "linux", feature = "bpf"))]
mod ebpf;
mod http1_client;
mod ip_x;
#[cfg(target_os = "linux")]
mod linux_monitor;
mod metrics;
mod proxy;
mod raw_serve;
mod reverse;

use crate::axum_handler::{build_router, AppState};
use crate::config::Config;
use crate::metrics::METRICS;

use axum_bootstrap::{AppError, InterceptResult, ReqInterceptor, TlsParam};
use config::load_config;
use futures_util::future::select_all;

use proxy::ProxyHandler;
use std::error::Error as stdError;

use std::sync::{Arc, LazyLock};
use std::time::Duration;

pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(if !cfg!(debug_assertions) { 600 } else { 10 }); // 3 minutes

type DynError = Box<dyn stdError + Send + Sync>; // wrapper for dyn Error

// 使用jemalloc作为全局内存分配器
#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

static CONFIG: LazyLock<Config> = LazyLock::new(|| {
    // This will be initialized when the program starts
    // to ensure we have a default configuration
    #[allow(clippy::expect_used)]
    load_config().expect("Failed to load config")
});

#[tokio::main]
async fn main() -> Result<(), DynError> {
    let ports = CONFIG.port.clone();
    let proxy_handler = Arc::new(ProxyHandler::new()?);
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    crate::ebpf::init_once();
    #[cfg(target_os = "linux")]
    crate::linux_monitor::init_once();
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
struct ProxyInterceptor(Arc<ProxyHandler>);

impl ReqInterceptor for ProxyInterceptor {
    async fn intercept(
        &self, req: http::Request<hyper::body::Incoming>, ip: std::net::SocketAddr,
    ) -> axum_bootstrap::InterceptResult {
        match self.0.handle(req, ip).await {
            Ok(adaptor) => adaptor.into(),
            Err(err) => InterceptResult::Error(AppError::new(err)),
        }
    }
}

async fn bootstrap(port: u16, proxy_handler: Arc<ProxyHandler>) -> Result<(), DynError> {
    let config = &crate::CONFIG;
    let basic_auth = config.basic_auth.clone();

    let router = build_router(AppState { basic_auth });
    axum_bootstrap::new_server(port, router)
        .with_timeout(IDLE_TIMEOUT)
        .with_tls_param(match config.over_tls {
            true => Some(TlsParam {
                tls: true,
                cert: config.cert.to_string(),
                key: config.key.to_string(),
            }),
            false => None,
        })
        .with_interceptor(ProxyInterceptor(proxy_handler))
        .run()
        .await
}
