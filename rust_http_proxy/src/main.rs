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
mod metrics;
mod proxy;
mod reverse;
mod web_func;

use crate::config::Config;
use crate::metrics::METRICS;

use axum::extract::State;
use axum::response::Html;
use axum::routing::get;
use axum::{Json, Router};
use axum_bootstrap::{AppError, InterceptResult, ReqInterceptor, TlsParam};
use axum_extra::extract::Host;
use axum_macros::debug_handler;
use config::load_config;
use futures_util::future::select_all;
use http::{HeaderMap, StatusCode};
use linux_monitor::Snapshot;
use log::warn;

use prometheus_client::encoding::text::encode;
use proxy::ProxyHandler;
use std::error::Error as stdError;
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
        build_router(AppState {}),
    )
    .with_timeout(IDLE_TIMEOUT)
    .run()
    .await
}

pub(crate) struct AppState {}

pub(crate) const BODY404: &str = include_str!("../html/404.html");
pub(crate) fn build_router(appstate: AppState) -> Router {
    // build our application with a route
    let router = Router::new()
        .route("/metrics", get(serve_metrics))
        .fallback(get(|| async {
            let mut header_map = HeaderMap::new();
            #[allow(clippy::expect_used)]
            header_map.insert("content-type", "text/html; charset=utf-8".parse().expect("should be valid header"));
            (StatusCode::NOT_FOUND, header_map, BODY404)
        }))
        .layer((CorsLayer::permissive(), TimeoutLayer::new(Duration::from_secs(30)), CompressionLayer::new()));
    #[cfg(target_os = "linux")]
    let router = router
        .route("/nt", get(count_stream))
        .route("/net", get(net_html))
        .route("/netx", get(netx_html))
        .route("/net.json", get(net_json));

    router.with_state(Arc::new(appstate))
}

async fn serve_metrics(State(_): State<Arc<AppState>>) -> Result<String, AppError> {
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    snapshot_metrics();
    let mut buffer = String::new();
    encode(&mut buffer, &METRICS.registry).map_err(AppError::new)?;
    Ok(buffer)
}

#[debug_handler]
#[cfg(target_os = "linux")]
async fn count_stream() -> Result<(HeaderMap, String), AppError> {
    let mut headers = HeaderMap::new();
    match std::process::Command::new("sh")
                .arg("-c")
                .arg(r#"
                netstat -ntp|grep -E "ESTABLISHED|CLOSE_WAIT"|awk -F "[ :]+"  -v OFS="" '$5<10000 && $5!="22" && $7>1024 {printf("%15s   => %15s:%-5s %s\n",$6,$4,$5,$9)}'|sort|uniq -c|sort -rn
                "#)
                .output() {
            Ok(output) => {
                #[allow(clippy::expect_used)]
                headers.insert(http::header::REFRESH, "3".parse().expect("should be valid header")); // 设置刷新时间
                Ok((headers, String::from_utf8(output.stdout).unwrap_or("".to_string())
                + (&*String::from_utf8(output.stderr).unwrap_or("".to_string()))))
            },
            Err(e) => {
                warn!("sh -c error: {}", e);
                Err(AppError::new(e))
            },
        }
}
#[cfg(target_os = "linux")]
async fn net_html(State(_): State<Arc<AppState>>, Host(host): Host) -> Result<Html<String>, AppError> {
    use linux_monitor::NET_MONITOR;

    NET_MONITOR
        .net_html("/net", &host)
        .await
        .map_err(AppError::new)
        .map(Html)
}
#[cfg(target_os = "linux")]
async fn netx_html(State(_): State<Arc<AppState>>, Host(host): Host) -> Result<Html<String>, AppError> {
    use linux_monitor::NET_MONITOR;
    NET_MONITOR
        .net_html("/netx", &host)
        .await
        .map_err(AppError::new)
        .map(Html)
}
#[cfg(target_os = "linux")]
async fn net_json(State(_): State<Arc<AppState>>) -> Result<Json<Snapshot>, AppError> {
    use linux_monitor::NET_MONITOR;
    Ok(Json(NET_MONITOR.net_json().await))
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
