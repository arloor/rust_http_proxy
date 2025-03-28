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
    let config = &crate::CONFIG;
    let basic_auth = config.basic_auth.clone();
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
        build_router(AppState { basic_auth }),
    )
    .with_timeout(IDLE_TIMEOUT)
    .run()
    .await
}

#[cfg(all(target_os = "linux", feature = "bpf"))]
pub(crate) fn snapshot_metrics() {
    use prom_label::LabelImpl;
    use proxy::NetDirectionLabel;

    use crate::ebpf;
    {
        METRICS
            .net_bytes
            .get_or_create(&LabelImpl::new(NetDirectionLabel { direction: "egress" }))
            .inner()
            .store(ebpf::get_egress(), std::sync::atomic::Ordering::Relaxed);
        METRICS
            .net_bytes
            .get_or_create(&LabelImpl::new(NetDirectionLabel { direction: "ingress" }))
            .inner()
            .store(ebpf::get_ingress(), std::sync::atomic::Ordering::Relaxed);

        METRICS
            .cgroup_bytes
            .get_or_create(&LabelImpl::new(NetDirectionLabel { direction: "egress" }))
            .inner()
            .store(ebpf::get_cgroup_egress(), std::sync::atomic::Ordering::Relaxed);
        METRICS
            .cgroup_bytes
            .get_or_create(&LabelImpl::new(NetDirectionLabel { direction: "ingress" }))
            .inner()
            .store(ebpf::get_cgroup_ingress(), std::sync::atomic::Ordering::Relaxed);
    }
}
