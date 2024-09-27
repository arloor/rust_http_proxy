// only compile in linux.

use chrono::{DateTime, Local};
use std::collections::VecDeque;

use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct TimeValue {
    pub _time: String,
    pub _value: u64,
}

impl TimeValue {
    pub fn new(time: String, value: u64) -> TimeValue {
        TimeValue {
            _time: time,
            _value: value,
        }
    }
}

pub(crate) const IGNORED_INTERFACES: &[&str; 7] =
    &["lo", "podman", "veth", "flannel", "cni0", "utun", "docker"];

#[derive(Clone)]
pub struct NetMonitor {
    buffer: Arc<RwLock<VecDeque<TimeValue>>>,
    #[cfg(feature = "bpf")]
    transmit_counter: Arc<socket_filter::TransmitCounter>,
    #[cfg(feature = "bpf")]
    cgroup_transmit_counter: Arc<cgroup_traffic::CgroupTransmitCounter>,
}
const TOTAL_SECONDS: u64 = 900;
const INTERVAL_SECONDS: u64 = 5;
const SIZE: usize = TOTAL_SECONDS as usize / INTERVAL_SECONDS as usize;
impl NetMonitor {
    pub fn new() -> Result<NetMonitor, crate::DynError> {
        Ok(NetMonitor {
            buffer: Arc::new(RwLock::new(VecDeque::<TimeValue>::new())),
            #[cfg(feature = "bpf")]
            cgroup_transmit_counter: Arc::new(cgroup_traffic::init_cgroup_skb_monitor(
                cgroup_traffic::SELF,
            )?),
            #[cfg(feature = "bpf")]
            transmit_counter: Arc::new(socket_filter::TransmitCounter::new(IGNORED_INTERFACES)?),
        })
    }

    #[cfg(feature = "bpf")]
    pub(crate) fn get_cgroup_egress(&self) -> u64 {
        self.cgroup_transmit_counter.get_egress()
    }

    #[cfg(feature = "bpf")]
    pub(crate) fn get_cgroup_ingress(&self) -> u64 {
        self.cgroup_transmit_counter.get_ingress()
    }

    async fn fetch_all(&self) -> Vec<TimeValue> {
        let buffer = self.buffer.read().await;
        let x = buffer.as_slices();
        let mut r = vec![];
        r.extend_from_slice(x.0);
        r.extend_from_slice(x.1);
        r
    }

    pub(crate) fn start(&self) {
        let self_clone = self.clone();
        tokio::spawn(async move {
            let mut last: u64 = 0;
            loop {
                {
                    let new = self_clone.get_egress();
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

    #[cfg(feature = "bpf")]
    pub fn get_egress(&self) -> u64 {
        self.transmit_counter.get_egress()
    }
    #[cfg(feature = "bpf")]
    pub fn get_ingress(&self) -> u64 {
        self.transmit_counter.get_ingress()
    }

    // Inter-|   Receive                                                |  Transmit
    //      face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    //         lo: 199123505  183957    0    0    0     0          0         0 199123505  183957    0    0    0     0       0          0
    //       ens5: 194703959  424303    0    0    0     0          0         0 271636211  425623    0    0    0     0       0          0
    #[cfg(not(feature = "bpf"))]
    pub fn get_egress(&self) -> u64 {
        use std::fs;
        if let Ok(mut content) = fs::read_to_string("/proc/net/dev") {
            content = content.replace("\r\n", "\n");
            let strs = content.split('\n');
            let mut new: u64 = 0;
            for str in strs {
                let array: Vec<&str> = str.split_whitespace().collect();

                if array.len() == 17 {
                    let interface = *array.first().unwrap_or(&"");
                    if IGNORED_INTERFACES
                        .iter()
                        .any(|&ignored| interface.starts_with(ignored))
                    {
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

    pub async fn speed(
        &self,
        hostname: &str,
        can_gzip: bool,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
        let r = self.fetch_all().await;
        let mut scales = vec![];
        let mut series_up = vec![];
        let mut max_up = 0;
        for x in r {
            scales.push(x._time);
            series_up.push(x._value);
            if x._value > max_up {
                max_up = x._value;
            }
        }
        let mut interval = if max_up > 1024 * 1024 * 8 {
            1024 * 1024 * 8
        } else {
            1024 * 1024
        };
        if max_up / interval > 10 {
            interval = (max_up / interval / 10) * interval;
        }
        let body = format!(
            "{} {}网速 {} {:?} {} {} {}  {:?} {}",
            _PART0, hostname, _PART1, scales, _PART2, interval, _PART3, series_up, _PART4
        );
        let builder = Response::builder()
            .status(StatusCode::OK)
            .header(http::header::SERVER, SERVER_NAME)
            .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8");
        if can_gzip {
            let compressed_data = match compress_string(&body) {
                Ok(compressed_data) => compressed_data,
                Err(e) => {
                    warn!("compress body error: {}", e);
                    return Ok(build_500_resp());
                }
            };
            builder
                .header(http::header::CONTENT_ENCODING, GZIP)
                .body(full_body(compressed_data))
        } else {
            builder.body(full_body(body))
        }
    }
}

pub fn count_stream() -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    match std::process::Command::new("sh")
            .arg("-c")
            .arg(r#"
            netstat -ntp|grep -E "ESTABLISHED|CLOSE_WAIT"|awk -F "[ :]+"  -v OFS="" '$5<10000 && $5!="22" && $7>1024 {printf("%15s   => %15s:%-5s %s\n",$6,$4,$5,$9)}'|sort|uniq -c|sort -rn
            "#)
            .output() {
        Ok(output) => {
            Response::builder()
            .status(StatusCode::OK)
            .header(http::header::SERVER, SERVER_NAME)
            .header(http::header::REFRESH, "3")
            .body(full_body(
                String::from_utf8(output.stdout).unwrap_or("".to_string())
                    + (&*String::from_utf8(output.stderr).unwrap_or("".to_string())),
            ))
        },
        Err(e) => {
            warn!("sh -c error: {}", e);
            Ok(build_500_resp())
        },
    }
}
