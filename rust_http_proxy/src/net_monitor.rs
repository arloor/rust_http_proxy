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
use bpf_socket_filter::SocketFilter;
#[derive(Clone)]
pub struct NetMonitor {
    buffer: Arc<RwLock<VecDeque<TimeValue>>>,
    #[cfg(feature = "bpf")]
    socket_filter:Arc<SocketFilter>,
}

impl NetMonitor {
    pub fn new() -> NetMonitor {
        NetMonitor {
            buffer: Arc::new(RwLock::new(VecDeque::<TimeValue>::new())),
            #[cfg(feature = "bpf")]
            socket_filter:Arc::new(SocketFilter::default()),
        }
    }

    pub fn _get_data(&self) -> Arc<RwLock<VecDeque<TimeValue>>> {
        self.buffer.clone()
    }
    pub fn start(&self) {
        if cfg!(target_os = "linux") {
            let to_move = self.buffer.clone();
            #[cfg(feature = "bpf")]
            let socket_filter = self.socket_filter.clone();
            tokio::spawn(async move {
                let mut last: u64 = 0;
                loop {
                    {
                        #[cfg(feature = "bpf")]
                        let new = socket_filter.get_value();
                        #[cfg(not(feature = "bpf"))]
                        let new = fetch_current_value();
                        if last != 0 {
                            let system_time = SystemTime::now();
                            let datetime: DateTime<Local> = system_time.into();
                            let mut buffer = to_move.write().await;
                            buffer.push_back(TimeValue::new(
                                datetime.format("%H:%M:%S").to_string(),
                                (new - last) * 8,
                            ));
                            if buffer.len() > MAX_NUM {
                                buffer.pop_front();
                            }
                        }
                        last = new;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            });
        }
    }
}

const MAX_NUM: usize = 300;



// Inter-|   Receive                                                |  Transmit
//      face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
//         lo: 199123505  183957    0    0    0     0          0         0 199123505  183957    0    0    0     0       0          0
//       ens5: 194703959  424303    0    0    0     0          0         0 271636211  425623    0    0    0     0       0          0
#[cfg(not(feature = "bpf"))]
fn fetch_current_value() -> u64 {
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
