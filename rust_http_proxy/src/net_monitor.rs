use chrono::{DateTime, Local};
use std::collections::VecDeque;

use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct TimeValue {
    pub time: String,
    pub value: u64,
}

impl TimeValue {
    pub fn new(time: String, value: u64) -> TimeValue {
        TimeValue { time, value }
    }
}

#[cfg(feature = "bpf")]
use socket_filter::SocketFilter;

#[derive(Clone)]
pub struct NetMonitor {
    buffer: Arc<RwLock<VecDeque<TimeValue>>>,
    #[cfg(feature = "bpf")]
    socket_filter: Arc<SocketFilter>,
}
const TOTAL_SECONDS: u64 = 900;
const INTERVAL_SECONDS: u64 = 5;
const SIZE: usize = TOTAL_SECONDS as usize / INTERVAL_SECONDS as usize;
impl NetMonitor {
    pub fn new() -> NetMonitor {
        NetMonitor {
            buffer: Arc::new(RwLock::new(VecDeque::<TimeValue>::new())),
            #[cfg(feature = "bpf")]
            socket_filter: Arc::new(SocketFilter::default()),
        }
    }

    pub async fn _fetch_all(&self) -> Vec<TimeValue> {
        let buffer = self.buffer.clone();
        let buffer = buffer.read().await;
        let x = buffer.as_slices();
        let mut r = vec![];
        r.extend_from_slice(x.0);
        r.extend_from_slice(x.1);
        r
    }

    pub fn start(&self) {
        if cfg!(target_os = "linux") {
            let self_clone = self.clone();
            tokio::spawn(async move {
                let mut last: u64 = 0;
                loop {
                    {
                        let new = self_clone.fetch_current_value();
                        if last != 0 {
                            let system_time = SystemTime::now();
                            let datetime: DateTime<Local> = system_time.into();
                            let mut buffer = self_clone.buffer.write().await;
                            buffer.push_back(TimeValue::new(
                                datetime.format("%H:%M:%S").to_string(),
                                (new - last) * 8 / INTERVAL_SECONDS,
                            ));
                            if buffer.len() > SIZE {
                                buffer.pop_front();
                            }
                        }
                        last = new;
                    }
                    tokio::time::sleep(Duration::from_secs(INTERVAL_SECONDS)).await;
                }
            });
        }
    }

    #[cfg(feature = "bpf")]
    pub fn fetch_current_value(&self) -> u64 {
        self.socket_filter.get_current_outbound_bytes()
    }

    // Inter-|   Receive                                                |  Transmit
    //      face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    //         lo: 199123505  183957    0    0    0     0          0         0 199123505  183957    0    0    0     0       0          0
    //       ens5: 194703959  424303    0    0    0     0          0         0 271636211  425623    0    0    0     0       0          0
    #[cfg(not(feature = "bpf"))]
    pub fn fetch_current_value(&self) -> u64 {
        use std::fs;
        if let Ok(mut content) = fs::read_to_string("/proc/net/dev") {
            content = content.replace("\r\n", "\n");
            let strs = content.split('\n');
            let mut new: u64 = 0;
            for str in strs {
                let array: Vec<&str> = str.split_whitespace().collect();

                if array.len() == 17 {
                    if *array.first().unwrap_or(&"") == "lo:" {
                        continue;
                    }
                    if array.first().unwrap_or(&"").starts_with("veth") {
                        continue;
                    }
                    if array.first().unwrap_or(&"").starts_with("flannel") {
                        continue;
                    }
                    if array.first().unwrap_or(&"").starts_with("cni0") {
                        continue;
                    }
                    if array.first().unwrap_or(&"").starts_with("utun") {
                        continue;
                    }
                    new += array.get(9).unwrap_or(&"").parse::<u64>().unwrap_or(0);
                }
            }
            new
        } else {
            0
        }
    }
}
