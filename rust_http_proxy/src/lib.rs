#![deny(warnings)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
mod address;
mod axum_handler;
#[cfg(target_os = "linux")]
mod cgroup_stats;
pub mod config;
#[cfg(all(target_os = "linux", feature = "bpf"))]
mod ebpf;
mod forward_proxy_client;
mod ip_x;
#[cfg(target_os = "linux")]
mod linux_axum_handler;
#[cfg(target_os = "linux")]
mod linux_monitor;
mod location;
mod metrics;
mod proxy;
mod static_serve;

pub use metrics::METRICS;

use crate::axum_handler::{build_router, AppState};
use crate::config::{Config, Param};

use axum_bootstrap::{InterceptResult, ReqInterceptor, TlsParam};
use axum_handler::AppProxyError;
use config::load_config;
use futures_util::future::join_all;

use log::{info, warn};
use proxy::ProxyHandler;
use std::error::Error as stdError;
use tokio::sync::mpsc::Sender;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

pub const IDLE_TIMEOUT: Duration = Duration::from_secs(if !cfg!(debug_assertions) { 600 } else { 10 }); // 3 minutes

pub type DynError = Box<dyn stdError + Send + Sync>; // wrapper for dyn Error

pub const BUILD_TIME: &str = build_time::build_time_local!("%Y-%m-%d %H:%M:%S %:z");

#[derive(Clone)]
struct ProxyInterceptor(Arc<ProxyHandler>);

impl ReqInterceptor for ProxyInterceptor {
    type Error = AppProxyError;
    async fn intercept(
        &self, req: http::Request<hyper::body::Incoming>, ip: std::net::SocketAddr,
    ) -> axum_bootstrap::InterceptResult<Self::Error> {
        match self.0.handle(req, ip).await {
            Ok(adaptor) => adaptor.into(),
            Err(err) => {
                warn!("Request handling error: {:?}", err);
                InterceptResult::Error(AppProxyError::new(err))
            }
        }
    }
}

fn create_future(
    port: u16, proxy_handler: Arc<ProxyHandler>, config: Arc<Config>,
) -> (impl Future<Output = Result<(), std::io::Error>>, Sender<()>) {
    let basic_auth = config.basic_auth.clone();

    let router = build_router(AppState { basic_auth });
    let (server, shutdown_tx) = axum_bootstrap::new_server(port, router);

    let server = server
        .with_timeout(IDLE_TIMEOUT)
        .with_tls_param(match config.over_tls {
            true => Some(TlsParam {
                tls: true,
                cert: config.cert.to_string(),
                key: config.key.to_string(),
            }),
            false => None,
        })
        .with_interceptor(ProxyInterceptor(proxy_handler));
    (server.run(), shutdown_tx)
}

/// Run the proxy service asynchronously.
/// This is the main entry point for running the proxy.
pub async fn run(param: Param) -> Result<(), DynError> {
    let (server_futures, shutdown_tx_list) = create_futures(param)?;
    // Spawn a task to handle signals and send shutdown signal
    tokio::spawn(async move {
        if (axum_bootstrap::wait_signal().await).is_ok() {
            for ele in shutdown_tx_list {
                let _ = ele.send(()).await;
            }
        }
    });
    server_futures.await;
    Ok(())
}

#[allow(clippy::type_complexity)]
pub fn create_futures(
    param: Param,
) -> Result<(impl Future<Output = Vec<Result<(), std::io::Error>>>, Vec<Sender<()>>), DynError> {
    let config = Arc::new(load_config(param)?);
    let ports = config.port.clone();
    let proxy_handler = Arc::new(ProxyHandler::new(config.clone())?);
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    crate::ebpf::init_once();
    #[cfg(target_os = "linux")]
    crate::linux_monitor::init_once();
    let mut shutdown_tx_list = vec![];
    let main_futures = ports
        .into_iter()
        .map(|port| {
            let (main_future, shutdown_tx) = create_future(port, proxy_handler.clone(), config.clone());
            shutdown_tx_list.push(shutdown_tx);
            async move {
                let res = main_future.await;
                info!("HTTP Proxy server on port {port} exited with: {res:?}");
                if let Err(ref err) = res {
                    if err.kind() == std::io::ErrorKind::AddrInUse {
                        log::error!("Port {port} is already in use. Exiting.");
                        std::process::exit(1);
                    }
                }
                res
            }
        })
        .map(Box::pin)
        .collect::<Vec<_>>();
    Ok((join_all(main_futures), shutdown_tx_list))
}
