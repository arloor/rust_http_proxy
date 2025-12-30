use crate::proxy::{AccessLabel, ReqLabels, ReverseProxyReqLabel, TunnelHandshakeLabel};
use log::info;
use prom_label::{Label, LabelImpl};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
#[cfg(target_os = "linux")]
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
use std::sync::LazyLock;
use std::time::Duration;

pub static METRICS: LazyLock<Metrics> = LazyLock::new(|| {
    let mut registry = Registry::default();
    let http_req_counter = Family::<LabelImpl<ReqLabels>, Counter>::default();
    registry.register("req_from_out", "Number of HTTP requests received", http_req_counter.clone());
    let reverse_proxy_req = Family::<LabelImpl<ReverseProxyReqLabel>, Counter>::default();
    registry.register("reverse_proxy_req", "Number of reverse proxy requests", reverse_proxy_req.clone());
    let proxy_traffic = Family::<LabelImpl<AccessLabel>, Counter>::default();
    registry.register("proxy_traffic", "num proxy_traffic", proxy_traffic.clone());

    // Summary指标：统计tunnel_proxy_bypass从接收请求到完成bypass握手的耗时
    let tunnel_handshake_duration = Family::<LabelImpl<TunnelHandshakeLabel>, Histogram>::new_with_constructor(|| {
        // 使用细粒度的buckets来统计耗时分布，单位是ms
        Histogram::new([1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0])
    });
    registry.register(
        "tunnel_handshake_duration",
        "Duration in seconds from receiving request to completing tunnel handshake",
        tunnel_handshake_duration.clone(),
    );

    #[cfg(all(target_os = "linux", feature = "bpf"))]
    let net_bytes = Family::<LabelImpl<crate::proxy::NetDirectionLabel>, Counter>::default();
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    registry.register("net_bytes", "num hosts net traffic in bytes", net_bytes.clone());
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    let cgroup_bytes = Family::<LabelImpl<crate::proxy::NetDirectionLabel>, Counter>::default();
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    registry.register("cgroup_bytes", "num this cgroup's net traffic in bytes", cgroup_bytes.clone());

    #[cfg(target_os = "linux")]
    let cgroup_cpu_total_ns = Counter::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_cpu_total_ns",
        "Total CPU time used by cgroup in nanoseconds",
        cgroup_cpu_total_ns.clone(),
    );
    #[cfg(target_os = "linux")]
    let cgroup_cpu_user_ns = Counter::default();
    #[cfg(target_os = "linux")]
    registry.register("cgroup_cpu_user_ns", "User CPU time used by cgroup in nanoseconds", cgroup_cpu_user_ns.clone());
    #[cfg(target_os = "linux")]
    let cgroup_cpu_system_ns = Counter::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_cpu_system_ns",
        "System CPU time used by cgroup in nanoseconds",
        cgroup_cpu_system_ns.clone(),
    );
    #[cfg(target_os = "linux")]
    let cgroup_memory_current_bytes = Gauge::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_memory_current_bytes",
        "Current memory usage by cgroup in bytes",
        cgroup_memory_current_bytes.clone(),
    );
    #[cfg(target_os = "linux")]
    let cgroup_memory_peak_bytes = Gauge::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_memory_peak_bytes",
        "Peak memory usage by cgroup in bytes",
        cgroup_memory_peak_bytes.clone(),
    );
    #[cfg(target_os = "linux")]
    let cgroup_memory_rss_bytes = Gauge::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_memory_rss_bytes",
        "RSS memory usage by cgroup in bytes",
        cgroup_memory_rss_bytes.clone(),
    );
    #[cfg(target_os = "linux")]
    let cgroup_memory_cache_bytes = Gauge::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_memory_cache_bytes",
        "Cache memory usage by cgroup in bytes",
        cgroup_memory_cache_bytes.clone(),
    );
    #[cfg(target_os = "linux")]
    let cgroup_memory_inactive_file_bytes = Gauge::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_memory_inactive_file_bytes",
        "Inactive file memory by cgroup in bytes",
        cgroup_memory_inactive_file_bytes.clone(),
    );
    #[cfg(target_os = "linux")]
    let cgroup_memory_working_set_bytes = Gauge::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_memory_working_set_bytes",
        "Working set memory by cgroup in bytes (same as k8s dashboard)",
        cgroup_memory_working_set_bytes.clone(),
    );

    register_metric_cleaner(proxy_traffic.clone(), "proxy_traffic".to_owned(), 2);
    register_metric_cleaner(reverse_proxy_req.clone(), "reverse_proxy_req".to_owned(), 24);
    register_metric_cleaner(tunnel_handshake_duration.clone(), "tunnel_handshake_duration".to_owned(), 2);
    register_metric_cleaner(http_req_counter.clone(), "http_req_counter".to_owned(), 7 * 24);

    Metrics {
        registry,
        http_req_counter,
        proxy_traffic,
        reverse_proxy_req,
        tunnel_bypass_setup_duration: tunnel_handshake_duration,
        #[cfg(all(target_os = "linux", feature = "bpf"))]
        net_bytes,
        #[cfg(all(target_os = "linux", feature = "bpf"))]
        cgroup_bytes,
        #[cfg(target_os = "linux")]
        cgroup_cpu_total_ns,
        #[cfg(target_os = "linux")]
        cgroup_cpu_user_ns,
        #[cfg(target_os = "linux")]
        cgroup_cpu_system_ns,
        #[cfg(target_os = "linux")]
        cgroup_memory_current_bytes,
        #[cfg(target_os = "linux")]
        cgroup_memory_peak_bytes,
        #[cfg(target_os = "linux")]
        cgroup_memory_rss_bytes,
        #[cfg(target_os = "linux")]
        cgroup_memory_cache_bytes,
        #[cfg(target_os = "linux")]
        cgroup_memory_inactive_file_bytes,
        #[cfg(target_os = "linux")]
        cgroup_memory_working_set_bytes,
    }
});

pub struct Metrics {
    pub registry: Registry,
    pub http_req_counter: Family<LabelImpl<ReqLabels>, Counter>,
    pub proxy_traffic: Family<LabelImpl<AccessLabel>, Counter>,
    pub reverse_proxy_req: Family<LabelImpl<ReverseProxyReqLabel>, Counter>,
    pub tunnel_bypass_setup_duration: Family<LabelImpl<TunnelHandshakeLabel>, Histogram>,
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    pub net_bytes: Family<LabelImpl<crate::proxy::NetDirectionLabel>, Counter>,
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    pub cgroup_bytes: Family<LabelImpl<crate::proxy::NetDirectionLabel>, Counter>,
    #[cfg(target_os = "linux")]
    pub cgroup_cpu_total_ns: Counter,
    #[cfg(target_os = "linux")]
    pub cgroup_cpu_user_ns: Counter,
    #[cfg(target_os = "linux")]
    pub cgroup_cpu_system_ns: Counter,
    #[cfg(target_os = "linux")]
    pub cgroup_memory_current_bytes: Gauge,
    #[cfg(target_os = "linux")]
    pub cgroup_memory_peak_bytes: Gauge,
    #[cfg(target_os = "linux")]
    pub cgroup_memory_rss_bytes: Gauge,
    #[cfg(target_os = "linux")]
    pub cgroup_memory_cache_bytes: Gauge,
    #[cfg(target_os = "linux")]
    pub cgroup_memory_inactive_file_bytes: Gauge,
    #[cfg(target_os = "linux")]
    pub cgroup_memory_working_set_bytes: Gauge,
}

#[cfg(target_os = "linux")]
pub(crate) fn update_cgroup_metrics() {
    use crate::cgroup_stats::collect_cgroup_stats;
    use log::warn;

    match collect_cgroup_stats() {
        Ok(stats) => {
            METRICS
                .cgroup_cpu_total_ns
                .inner()
                .store(stats.cpu_total_ns, std::sync::atomic::Ordering::Relaxed);
            METRICS
                .cgroup_cpu_user_ns
                .inner()
                .store(stats.cpu_user_ns, std::sync::atomic::Ordering::Relaxed);
            METRICS
                .cgroup_cpu_system_ns
                .inner()
                .store(stats.cpu_system_ns, std::sync::atomic::Ordering::Relaxed);
            METRICS
                .cgroup_memory_current_bytes
                .set(stats.memory_current_bytes as i64);
            METRICS
                .cgroup_memory_peak_bytes
                .set(stats.memory_peak_bytes.unwrap_or(0) as i64);
            METRICS.cgroup_memory_rss_bytes.set(stats.memory_rss_bytes as i64);
            METRICS.cgroup_memory_cache_bytes.set(stats.memory_cache_bytes as i64);
            METRICS
                .cgroup_memory_inactive_file_bytes
                .set(stats.memory_inactive_file_bytes as i64);
            METRICS
                .cgroup_memory_working_set_bytes
                .set(stats.memory_working_set_bytes as i64);
        }
        Err(e) => {
            warn!("Failed to collect cgroup stats: {}", e);
        }
    }
}

// 每两小时清空一次，否则一直累积，光是exporter的流量就很大，观察到每天需要3.7GB。不用担心rate函数不准，promql查询会自动处理reset（数据突降）的数据。
// 不过，虽然能够处理reset，但increase会用最后一个出现的值-第一个出现的值。在我们清空的实现下，reset后第一个出现的值肯定不是0，所以increase的算出来的值会稍少（少第一次出现的值）
// 因此对于准确性要求较高的http_req_counter，这里的清空间隔就放大一点
fn register_metric_cleaner<T: Label + Send + Sync, M: 'static + Send + Sync>(
    counter: Family<T, M>, name: String, interval_in_hour: u64,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(interval_in_hour * 60 * 60)).await;
            info!("cleaning prometheus metric labels for {name}");
            counter.clear();
        }
    });
}
