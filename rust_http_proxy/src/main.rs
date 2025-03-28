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

use axum::extract::State;
use axum::response::Html;
use axum::routing::get;
use axum::{Json, Router};
use axum_bootstrap::{AppError, InterceptResult, ReqInterceptor, TlsParam};
use axum_extra::extract::Host;
use axum_macros::debug_handler;
use chrono::Local;
use config::load_config;
use futures_util::future::select_all;
use http::{HeaderMap, StatusCode};
use linux_monitor::{NetMonitor, Snapshot};
use log::{info, warn};
use prom_label::{Label, LabelImpl};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use proxy::{AccessLabel, NetDirectionLabel, ProxyHandler, ReqLabels, ReverseProxyReqLabel};
use std::error::Error as stdError;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;

use std::sync::{Arc, LazyLock};
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

static METRICS: LazyLock<Metrics> = LazyLock::new(|| {
    let mut registry = Registry::default();
    let http_req_counter = Family::<LabelImpl<ReqLabels>, Counter>::default();
    registry.register("req_from_out", "Number of HTTP requests received", http_req_counter.clone());
    let reverse_proxy_req = Family::<LabelImpl<ReverseProxyReqLabel>, Counter>::default();
    registry.register("reverse_proxy_req", "Number of reverse proxy requests", reverse_proxy_req.clone());
    let proxy_traffic = Family::<LabelImpl<AccessLabel>, Counter>::default();
    registry.register("proxy_traffic", "num proxy_traffic", proxy_traffic.clone());
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    let net_bytes = Family::<LabelImpl<NetDirectionLabel>, Counter>::default();
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    registry.register("net_bytes", "num hosts net traffic in bytes", net_bytes.clone());
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    let cgroup_bytes = Family::<LabelImpl<NetDirectionLabel>, Counter>::default();
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    registry.register("cgroup_bytes", "num this cgroup's net traffic in bytes", cgroup_bytes.clone());

    register_metric_cleaner(proxy_traffic.clone(), "proxy_traffic".to_owned(), 24);
    // register_metric_cleaner(http_req_counter.clone(), 7 * 24);

    Metrics {
        registry,
        http_req_counter,
        proxy_traffic,
        reverse_proxy_req,
        #[cfg(all(target_os = "linux", feature = "bpf"))]
        net_bytes,
        #[cfg(all(target_os = "linux", feature = "bpf"))]
        cgroup_bytes,
    }
});

pub(crate) struct Metrics {
    pub(crate) registry: Registry,
    pub(crate) http_req_counter: Family<LabelImpl<ReqLabels>, Counter>,
    pub(crate) proxy_traffic: Family<LabelImpl<AccessLabel>, Counter>,
    pub(crate) reverse_proxy_req: Family<LabelImpl<ReverseProxyReqLabel>, Counter>,
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    pub(crate) net_bytes: Family<LabelImpl<NetDirectionLabel>, Counter>,
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    pub(crate) cgroup_bytes: Family<LabelImpl<NetDirectionLabel>, Counter>,
}

// 每两小时清空一次，否则一直累积，光是exporter的流量就很大，观察到每天需要3.7GB。不用担心rate函数不准，promql查询会自动处理reset（数据突降）的数据。
// 不过，虽然能够处理reset，但increase会用最后一个出现的值-第一个出现的值。在我们清空的实现下，reset后第一个出现的值肯定不是0，所以increase的算出来的值会稍少（少第一次出现的值）
// 因此对于准确性要求较高的http_req_counter，这里的清空间隔就放大一点
fn register_metric_cleaner<T: Label + Send + Sync>(counter: Family<T, Counter>, name: String, interval_in_hour: u64) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(interval_in_hour * 60 * 60)).await;
            info!("cleaning prometheus metric labels for {}", name);
            counter.clear();
        }
    });
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
    let net_monitor = proxy_handler.linux_monitor.clone();
    axum_bootstrap::new_server_with_interceptor::<ProxyInterceptor>(
        port,
        tls_param,
        ProxyInterceptor { proxy_handler },
        build_router(net_monitor),
    )
    .with_timeout(IDLE_TIMEOUT)
    .run()
    .await
}

pub(crate) struct AppState {
    pub(crate) net_monitor: NetMonitor,
}

pub(crate) const BODY404: &str = include_str!("../html/404.html");
pub(crate) fn build_router(net_monitor: NetMonitor) -> Router {
    // build our application with a route
    let router = Router::new()
        .route("/time", get(|| async { (StatusCode::OK, format!("{}", Local::now())) }))
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

    router.with_state(Arc::new(AppState { net_monitor }))
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
async fn net_html(State(state): State<Arc<AppState>>, Host(host): Host) -> Result<Html<String>, AppError> {
    state
        .net_monitor
        .net_html("/net", &host)
        .await
        .map_err(AppError::new)
        .map(Html)
}
#[cfg(target_os = "linux")]
async fn netx_html(State(state): State<Arc<AppState>>, Host(host): Host) -> Result<Html<String>, AppError> {
    state
        .net_monitor
        .net_html("/netx", &host)
        .await
        .map_err(AppError::new)
        .map(Html)
}
#[cfg(target_os = "linux")]
async fn net_json(State(state): State<Arc<AppState>>) -> Result<Json<Snapshot>, AppError> {
    Ok(Json(state.net_monitor.net_json().await))
}
