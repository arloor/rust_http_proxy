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

#[cfg(target_os = "linux")]
static LAST_CGROUP_CPU_WARNING_SECONDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(target_os = "linux")]
static LAST_CGROUP_MEMORY_WARNING_SECONDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

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
    let cgroup_cpu_collection_success = Gauge::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_cpu_collection_success",
        "Whether the latest cgroup CPU collection succeeded (1 for success, 0 for failure)",
        cgroup_cpu_collection_success.clone(),
    );
    #[cfg(target_os = "linux")]
    let cgroup_cpu_collection_errors = Counter::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_cpu_collection_errors",
        "Total number of failed cgroup CPU collections",
        cgroup_cpu_collection_errors.clone(),
    );
    #[cfg(target_os = "linux")]
    let cgroup_cpu_last_collection_timestamp_seconds = Gauge::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_cpu_last_collection_timestamp_seconds",
        "Unix timestamp of the latest successful cgroup CPU collection",
        cgroup_cpu_last_collection_timestamp_seconds.clone(),
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
    let cgroup_memory_peak_available = Gauge::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_memory_peak_available",
        "Whether the cgroup memory peak metric is available (1 for available, 0 for unavailable)",
        cgroup_memory_peak_available.clone(),
    );
    #[cfg(target_os = "linux")]
    let cgroup_memory_limit_bytes = Gauge::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_memory_limit_bytes",
        "Configured cgroup memory hard limit in bytes",
        cgroup_memory_limit_bytes.clone(),
    );
    #[cfg(target_os = "linux")]
    let cgroup_memory_limit_enabled = Gauge::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_memory_limit_enabled",
        "Whether a finite cgroup memory hard limit is configured (1 for enabled, 0 for unlimited)",
        cgroup_memory_limit_enabled.clone(),
    );
    #[cfg(target_os = "linux")]
    let cgroup_memory_anon_bytes = Gauge::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_memory_anon_bytes",
        "Anonymous memory used by cgroup in bytes (v1 uses RSS as the closest equivalent)",
        cgroup_memory_anon_bytes.clone(),
    );
    #[cfg(target_os = "linux")]
    let cgroup_memory_active_file_bytes = Gauge::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_memory_active_file_bytes",
        "Active file-backed memory used by cgroup in bytes",
        cgroup_memory_active_file_bytes.clone(),
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
    let cgroup_memory_kernel_bytes = Gauge::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_memory_kernel_bytes",
        "Kernel memory used by cgroup in bytes",
        cgroup_memory_kernel_bytes.clone(),
    );
    #[cfg(target_os = "linux")]
    let cgroup_memory_kernel_available = Gauge::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_memory_kernel_available",
        "Whether cgroup kernel memory accounting is available (1 for available, 0 for unavailable)",
        cgroup_memory_kernel_available.clone(),
    );
    #[cfg(target_os = "linux")]
    let cgroup_memory_working_set_bytes = Gauge::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_memory_working_set_bytes",
        "Working set memory by cgroup in bytes (same as k8s dashboard)",
        cgroup_memory_working_set_bytes.clone(),
    );
    #[cfg(target_os = "linux")]
    let cgroup_memory_collection_success = Gauge::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_memory_collection_success",
        "Whether the latest cgroup memory collection succeeded (1 for success, 0 for failure)",
        cgroup_memory_collection_success.clone(),
    );
    #[cfg(target_os = "linux")]
    let cgroup_memory_collection_errors = Counter::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_memory_collection_errors",
        "Total number of failed cgroup memory collections",
        cgroup_memory_collection_errors.clone(),
    );
    #[cfg(target_os = "linux")]
    let cgroup_memory_last_collection_timestamp_seconds = Gauge::default();
    #[cfg(target_os = "linux")]
    registry.register(
        "cgroup_memory_last_collection_timestamp_seconds",
        "Unix timestamp of the latest successful cgroup memory collection",
        cgroup_memory_last_collection_timestamp_seconds.clone(),
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
        cgroup_cpu_collection_success,
        #[cfg(target_os = "linux")]
        cgroup_cpu_collection_errors,
        #[cfg(target_os = "linux")]
        cgroup_cpu_last_collection_timestamp_seconds,
        #[cfg(target_os = "linux")]
        cgroup_memory_current_bytes,
        #[cfg(target_os = "linux")]
        cgroup_memory_peak_bytes,
        #[cfg(target_os = "linux")]
        cgroup_memory_peak_available,
        #[cfg(target_os = "linux")]
        cgroup_memory_limit_bytes,
        #[cfg(target_os = "linux")]
        cgroup_memory_limit_enabled,
        #[cfg(target_os = "linux")]
        cgroup_memory_anon_bytes,
        #[cfg(target_os = "linux")]
        cgroup_memory_active_file_bytes,
        #[cfg(target_os = "linux")]
        cgroup_memory_inactive_file_bytes,
        #[cfg(target_os = "linux")]
        cgroup_memory_kernel_bytes,
        #[cfg(target_os = "linux")]
        cgroup_memory_kernel_available,
        #[cfg(target_os = "linux")]
        cgroup_memory_working_set_bytes,
        #[cfg(target_os = "linux")]
        cgroup_memory_collection_success,
        #[cfg(target_os = "linux")]
        cgroup_memory_collection_errors,
        #[cfg(target_os = "linux")]
        cgroup_memory_last_collection_timestamp_seconds,
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
    pub cgroup_cpu_collection_success: Gauge,
    #[cfg(target_os = "linux")]
    pub cgroup_cpu_collection_errors: Counter,
    #[cfg(target_os = "linux")]
    pub cgroup_cpu_last_collection_timestamp_seconds: Gauge,
    #[cfg(target_os = "linux")]
    pub cgroup_memory_current_bytes: Gauge,
    #[cfg(target_os = "linux")]
    pub cgroup_memory_peak_bytes: Gauge,
    #[cfg(target_os = "linux")]
    pub cgroup_memory_peak_available: Gauge,
    #[cfg(target_os = "linux")]
    pub cgroup_memory_limit_bytes: Gauge,
    #[cfg(target_os = "linux")]
    pub cgroup_memory_limit_enabled: Gauge,
    #[cfg(target_os = "linux")]
    pub cgroup_memory_anon_bytes: Gauge,
    #[cfg(target_os = "linux")]
    pub cgroup_memory_active_file_bytes: Gauge,
    #[cfg(target_os = "linux")]
    pub cgroup_memory_inactive_file_bytes: Gauge,
    #[cfg(target_os = "linux")]
    pub cgroup_memory_kernel_bytes: Gauge,
    #[cfg(target_os = "linux")]
    pub cgroup_memory_kernel_available: Gauge,
    #[cfg(target_os = "linux")]
    pub cgroup_memory_working_set_bytes: Gauge,
    #[cfg(target_os = "linux")]
    pub cgroup_memory_collection_success: Gauge,
    #[cfg(target_os = "linux")]
    pub cgroup_memory_collection_errors: Counter,
    #[cfg(target_os = "linux")]
    pub cgroup_memory_last_collection_timestamp_seconds: Gauge,
}

#[cfg(target_os = "linux")]
pub(crate) fn update_cgroup_metrics() {
    use crate::cgroup_stats::{collect_cgroup_cpu_stats, collect_cgroup_memory_stats, discover_cgroup_paths};

    let paths = match discover_cgroup_paths() {
        Ok(paths) => paths,
        Err(error) => {
            record_cgroup_cpu_collection_error(&error);
            record_cgroup_memory_collection_error(&error);
            return;
        }
    };

    match collect_cgroup_cpu_stats(&paths) {
        Ok(stats) => {
            METRICS
                .cgroup_cpu_total_ns
                .inner()
                .store(stats.total_ns, std::sync::atomic::Ordering::Relaxed);
            METRICS
                .cgroup_cpu_user_ns
                .inner()
                .store(stats.user_ns, std::sync::atomic::Ordering::Relaxed);
            METRICS
                .cgroup_cpu_system_ns
                .inner()
                .store(stats.system_ns, std::sync::atomic::Ordering::Relaxed);
            METRICS.cgroup_cpu_collection_success.set(1);
            METRICS
                .cgroup_cpu_last_collection_timestamp_seconds
                .set(unix_timestamp_seconds());
        }
        Err(error) => record_cgroup_cpu_collection_error(&error),
    }

    match collect_cgroup_memory_stats(&paths) {
        Ok(stats) => {
            METRICS
                .cgroup_memory_current_bytes
                .set(saturating_i64(stats.current_bytes));
            match stats.peak_bytes {
                Some(peak_bytes) => {
                    METRICS.cgroup_memory_peak_bytes.set(saturating_i64(peak_bytes));
                    METRICS.cgroup_memory_peak_available.set(1);
                }
                None => {
                    METRICS.cgroup_memory_peak_available.set(0);
                }
            }
            match stats.limit_bytes {
                Some(limit_bytes) => {
                    METRICS.cgroup_memory_limit_bytes.set(saturating_i64(limit_bytes));
                    METRICS.cgroup_memory_limit_enabled.set(1);
                }
                None => {
                    METRICS.cgroup_memory_limit_enabled.set(0);
                }
            }
            METRICS.cgroup_memory_anon_bytes.set(saturating_i64(stats.anon_bytes));
            METRICS
                .cgroup_memory_active_file_bytes
                .set(saturating_i64(stats.active_file_bytes));
            METRICS
                .cgroup_memory_inactive_file_bytes
                .set(saturating_i64(stats.inactive_file_bytes));
            match stats.kernel_bytes {
                Some(kernel_bytes) => {
                    METRICS.cgroup_memory_kernel_bytes.set(saturating_i64(kernel_bytes));
                    METRICS.cgroup_memory_kernel_available.set(1);
                }
                None => {
                    METRICS.cgroup_memory_kernel_available.set(0);
                }
            }
            METRICS
                .cgroup_memory_working_set_bytes
                .set(saturating_i64(stats.working_set_bytes));
            METRICS.cgroup_memory_collection_success.set(1);
            METRICS
                .cgroup_memory_last_collection_timestamp_seconds
                .set(unix_timestamp_seconds());
        }
        Err(error) => record_cgroup_memory_collection_error(&error),
    }
}

#[cfg(target_os = "linux")]
fn record_cgroup_cpu_collection_error(error: &std::io::Error) {
    METRICS.cgroup_cpu_collection_success.set(0);
    METRICS.cgroup_cpu_collection_errors.inc();
    warn_cgroup_error_rate_limited("CPU", error, &LAST_CGROUP_CPU_WARNING_SECONDS);
}

#[cfg(target_os = "linux")]
fn record_cgroup_memory_collection_error(error: &std::io::Error) {
    METRICS.cgroup_memory_collection_success.set(0);
    METRICS.cgroup_memory_collection_errors.inc();
    warn_cgroup_error_rate_limited("memory", error, &LAST_CGROUP_MEMORY_WARNING_SECONDS);
}

#[cfg(target_os = "linux")]
fn warn_cgroup_error_rate_limited(
    component: &str, error: &std::io::Error, last_warning: &std::sync::atomic::AtomicU64,
) {
    use std::sync::atomic::Ordering;

    let now = unix_timestamp_seconds().max(0) as u64;
    let previous = last_warning.load(Ordering::Relaxed);
    if now.saturating_sub(previous) >= 60
        && last_warning
            .compare_exchange(previous, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        log::warn!("Failed to collect cgroup {component} stats: {error}");
    }
}

#[cfg(target_os = "linux")]
fn unix_timestamp_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| saturating_i64(duration.as_secs()))
}

#[cfg(target_os = "linux")]
fn saturating_i64(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
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
