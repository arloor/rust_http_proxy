// only compile in linux.

use chrono::{DateTime, Local};
use serde::Serialize;
use std::collections::VecDeque;

use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

pub(crate) fn init_once() {
    static INIT_ONCE: std::sync::Once = std::sync::Once::new();
    INIT_ONCE.call_once(|| {
        log::info!("init linux net monitor");
        NET_MONITOR.start(); // This will ensure that the NetMonitor is initialized and starts monitoring.
    });
}

pub(crate) static NET_MONITOR: LazyLock<NetMonitor> = LazyLock::new(|| {
    // 创建 NetMonitor 实例
    #[allow(clippy::expect_used)]
    NetMonitor::new().expect("Failed to create NetMonitor")
});

#[derive(Debug, Clone)]
pub struct TimeValue {
    pub time: String,
    pub egress: u64,
    pub ingress: u64,
}

impl TimeValue {
    pub fn new(time: String, egress: u64, ingress: u64) -> TimeValue {
        TimeValue { time, egress, ingress }
    }
}

pub(crate) const IGNORED_INTERFACES: &[&str; 8] = &["lo", "podman", "veth", "flannel", "cni0", "utun", "docker", "wg"];

#[derive(Clone)]
pub struct NetMonitor {
    buffer: Arc<RwLock<VecDeque<TimeValue>>>,
}
const TOTAL_SECONDS: u64 = 900;
const INTERVAL_SECONDS: u64 = 5;
const SIZE: usize = TOTAL_SECONDS as usize / INTERVAL_SECONDS as usize;
impl NetMonitor {
    pub fn new() -> Result<NetMonitor, crate::DynError> {
        Ok(NetMonitor {
            buffer: Arc::new(RwLock::new(VecDeque::<TimeValue>::new())),
        })
    }

    async fn fetch_all(&self) -> Snapshot {
        let buffer = self.buffer.read().await;
        let x = buffer.as_slices();
        let mut r = vec![];
        r.extend_from_slice(x.0);
        r.extend_from_slice(x.1);
        drop(buffer);

        let mut scales = vec![];
        let mut series_up = vec![];
        let mut series_down = vec![];
        for x in r {
            scales.push(x.time);
            series_up.push(x.egress);
            series_down.push(x.ingress);
        }

        // 计算总和，谁的总和大就显示标记
        let sum_up: u64 = series_up.iter().sum();
        let sum_down: u64 = series_down.iter().sum();
        let (show_up, show_down) = if sum_up >= sum_down {
            (true, false)
        } else {
            (false, true)
        };

        Snapshot {
            scales,
            series_vec: vec![
                Series {
                    name: "上行网速".to_string(),
                    data: series_up,
                    show_avg_line: show_up,
                    show_max_point: show_up,
                    color: Some("#ef0000".to_string()),
                    serires_type: None,
                },
                Series {
                    name: "下行网速".to_string(),
                    data: series_down,
                    show_avg_line: show_down,
                    show_max_point: show_down,
                    color: Some("#5c7bd9".to_string()),
                    serires_type: None,
                },
            ],
        }
    }

    pub(crate) fn start(&self) {
        let buffer_clone = self.buffer.clone();
        tokio::spawn(async move {
            let mut last_egress: u64 = 0;
            let mut last_ingress: u64 = 0;
            loop {
                {
                    #[cfg(feature = "bpf")]
                    let new = (crate::ebpf::get_egress(), crate::ebpf::get_ingress());
                    #[cfg(not(feature = "bpf"))]
                    let new = get_egress_ingress();
                    if last_egress != 0 || last_ingress != 0 {
                        let system_time = SystemTime::now();
                        let datetime: DateTime<Local> = system_time.into();
                        let mut buffer = buffer_clone.write().await;
                        buffer.push_back(TimeValue::new(
                            datetime.format("%H:%M:%S").to_string(),
                            (new.0 - last_egress) * 8 / INTERVAL_SECONDS,
                            (new.1 - last_ingress) * 8 / INTERVAL_SECONDS,
                        ));
                        if buffer.len() > SIZE {
                            buffer.pop_front();
                        }
                    }
                    last_egress = new.0;
                    last_ingress = new.1;
                }
                tokio::time::sleep(Duration::from_secs(INTERVAL_SECONDS)).await;
            }
        });
    }

    pub async fn net_json(&self) -> Snapshot {
        self.fetch_all().await
    }
}

#[derive(Serialize)]
pub struct Snapshot {
    scales: Vec<String>,
    series_vec: Vec<Series>,
}

#[derive(Serialize)]
pub struct Series {
    name: String,
    data: Vec<u64>,
    show_max_point: bool,
    show_avg_line: bool,
    color: Option<String>,
    #[serde(rename = "type")]
    serires_type: Option<SeriesType>,
}
#[derive(Serialize)]
pub enum SeriesType {
    #[allow(dead_code)]
    #[serde(rename = "line")]
    Line,
    #[allow(dead_code)]
    #[serde(rename = "bar")]
    Bar,
}

// Inter-|   Receive                                                |  Transmit
//      face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
//         lo: 199123505  183957    0    0    0     0          0         0 199123505  183957    0    0    0     0       0          0
//       ens5: 194703959  424303    0    0    0     0          0         0 271636211  425623    0    0    0     0       0          0
#[cfg(not(feature = "bpf"))]
pub fn get_egress_ingress() -> (u64, u64) {
    use std::fs;
    if let Ok(mut content) = fs::read_to_string("/proc/net/dev") {
        content = content.replace("\r\n", "\n");
        let strs = content.split('\n');
        let mut egress: u64 = 0;
        let mut ingress: u64 = 0;
        for str in strs {
            let array: Vec<&str> = str.split_whitespace().collect();

            if array.len() == 17 {
                let interface = *array.first().unwrap_or(&"");
                if IGNORED_INTERFACES.iter().any(|&ignored| interface.starts_with(ignored)) {
                    continue;
                }
                egress += array.get(9).unwrap_or(&"").parse::<u64>().unwrap_or(0);
                ingress += array.get(1).unwrap_or(&"").parse::<u64>().unwrap_or(0);
            }
        }
        (egress, ingress)
    } else {
        (0, 0)
    }
}
