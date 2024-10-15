pub(crate) fn init_once() {
    static INIT_ONCE: std::sync::Once = std::sync::Once::new();
    INIT_ONCE.call_once(|| {
        log::info!("init bpf programs");
        CGROUP_TRANSMIT_COUNTER.as_ref(); // trigger the lazy init.
        SOCKET_FILTER.as_ref(); // trigger the lazy init.
    });
}

static SOCKET_FILTER: std::sync::LazyLock<Option<socket_filter::TransmitCounter>> =
    std::sync::LazyLock::new(|| {
        let open_object = Box::leak(Box::new(std::mem::MaybeUninit::uninit())); // make the ebpf prog lives as long as the process.
        match socket_filter::TransmitCounter::new(
            open_object,
            crate::linux_monitor::IGNORED_INTERFACES,
        ) {
            Ok(transmit_counter) => {
                return Option::Some(transmit_counter);
            }
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
