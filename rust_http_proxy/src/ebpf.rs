use crate::{proxy, METRICS};

pub(crate) fn init_once() {
    static INIT_ONCE: std::sync::Once = std::sync::Once::new();
    INIT_ONCE.call_once(|| {
        log::info!("init bpf programs");
        CGROUP_TRANSMIT_COUNTER.as_ref(); // trigger the lazy init.
        SOCKET_FILTER.as_ref(); // trigger the lazy init.
    });
}

static SOCKET_FILTER: std::sync::LazyLock<Option<socket_filter::TransmitCounter>> = std::sync::LazyLock::new(|| {
    let open_object = Box::leak(Box::new(std::mem::MaybeUninit::uninit())); // make the ebpf prog lives as long as the process.
    match socket_filter::TransmitCounter::new(open_object, crate::linux_monitor::IGNORED_INTERFACES) {
        Ok(transmit_counter) => Option::Some(transmit_counter),
        Err(e) => {
            log::warn!("socket_filter::TransmitCounter::init error: {}", e);
            Option::None
        }
    }
});

static CGROUP_TRANSMIT_COUNTER: std::sync::LazyLock<Option<cgroup_traffic::CgroupTransmitCounter>> =
    std::sync::LazyLock::new(|| {
        let open_object = Box::leak(Box::new(std::mem::MaybeUninit::uninit())); // make the ebpf prog lives as long as the process.
        match cgroup_traffic::init_cgroup_skb_monitor(open_object, cgroup_traffic::SELF) {
            Ok((cgroup_transmit_counter, links)) => {
                Box::leak(Box::new(links)); // make the ebpf prog lives as long as the process.
                Option::Some(cgroup_transmit_counter)
            }
            Err(e) => {
                log::warn!("cgroup_traffic::init_cgroup_skb_monitor error: {}", e);
                Option::None
            }
        }
    });

pub(crate) fn get_cgroup_egress() -> u64 {
    match CGROUP_TRANSMIT_COUNTER.as_ref() {
        Some(counter) => counter.get_egress(),
        None => 0,
    }
}

pub(crate) fn get_cgroup_ingress() -> u64 {
    match CGROUP_TRANSMIT_COUNTER.as_ref() {
        Some(counter) => counter.get_ingress(),
        None => 0,
    }
}

pub fn get_egress() -> u64 {
    match SOCKET_FILTER.as_ref() {
        Some(counter) => counter.get_egress(),
        None => 0,
    }
}

pub fn get_ingress() -> u64 {
    match SOCKET_FILTER.as_ref() {
        Some(counter) => counter.get_ingress(),
        None => 0,
    }
}

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
