use crate::proxy::{AccessLabel, ReqLabels, ReverseProxyReqLabel};
use log::info;
use prom_label::{Label, LabelImpl};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use std::sync::LazyLock;
use std::time::Duration;

pub(crate) static METRICS: LazyLock<Metrics> = LazyLock::new(|| {
    let mut registry = Registry::default();
    let http_req_counter = Family::<LabelImpl<ReqLabels>, Counter>::default();
    registry.register("req_from_out", "Number of HTTP requests received", http_req_counter.clone());
    let reverse_proxy_req = Family::<LabelImpl<ReverseProxyReqLabel>, Counter>::default();
    registry.register("reverse_proxy_req", "Number of reverse proxy requests", reverse_proxy_req.clone());
    let proxy_traffic = Family::<LabelImpl<AccessLabel>, Counter>::default();
    registry.register("proxy_traffic", "num proxy_traffic", proxy_traffic.clone());
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    let net_bytes = Family::<LabelImpl<crate::proxy::NetDirectionLabel>, Counter>::default();
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    registry.register("net_bytes", "num hosts net traffic in bytes", net_bytes.clone());
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    let cgroup_bytes = Family::<LabelImpl<crate::proxy::NetDirectionLabel>, Counter>::default();
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
    pub(crate) net_bytes: Family<LabelImpl<crate::proxy::NetDirectionLabel>, Counter>,
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    pub(crate) cgroup_bytes: Family<LabelImpl<crate::proxy::NetDirectionLabel>, Counter>,
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
