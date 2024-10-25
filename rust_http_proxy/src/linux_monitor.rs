// only compile in linux.

use chrono::{DateTime, Local};
use http::{Error, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use log::warn;
use serde::Serialize;
use std::collections::VecDeque;

use std::io;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

use crate::proxy::full_body;
use crate::web_func::{build_500_resp, GZIP, SERVER_NAME};

#[derive(Debug, Clone)]
pub struct TimeValue {
    pub time: String,
    pub egress: u64,
    pub ingress: u64,
}

impl TimeValue {
    pub fn new(time: String, egress: u64, ingress: u64) -> TimeValue {
        TimeValue {
            time,
            egress,
            ingress,
        }
    }
}

pub(crate) const IGNORED_INTERFACES: &[&str; 7] =
    &["lo", "podman", "veth", "flannel", "cni0", "utun", "docker"];

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

        let mut scales = vec![];
        let mut series_up = vec![];
        let mut series_down = vec![];
        for x in r {
            scales.push(x.time);
            series_up.push(x.egress);
            series_down.push(x.ingress);
        }
        Snapshot {
            scales,
            series_up,
            series_down,
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

    pub async fn net_html(
        &self,
        hostname: &str,
        can_gzip: bool,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
        // 创建上下文并插入数据
        let mut context = tera::Context::new();
        context.insert("hostname", hostname);

        // 渲染模板
        let body: String = TERA.render(NET_HTML, &context).unwrap_or("".to_string());
        let builder = Response::builder()
            .status(StatusCode::OK)
            .header(http::header::SERVER, SERVER_NAME)
            .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8");
        if can_gzip {
            let compressed_data = match crate::web_func::compress_string(&body) {
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

    pub async fn net_json(
        &self,
        can_gzip: bool,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
        let snapshot = self.fetch_all().await;
        let body = serde_json::to_string(&snapshot).unwrap_or("{}".to_string());
        let builder = Response::builder()
            .status(StatusCode::OK)
            .header(http::header::SERVER, SERVER_NAME)
            .header(
                http::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            );
        if can_gzip {
            let compressed_data = match crate::web_func::compress_string(&body) {
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

#[derive(Serialize)]
pub struct Snapshot {
    scales: Vec<String>,
    series_up: Vec<u64>,
    series_down: Vec<u64>,
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

const NET_HTML: &str = "net.html";
const NET_HTML_TEMPLATE: &str = include_str!("../html/net.html");
static TERA: LazyLock<tera::Tera> = LazyLock::new(|| {
    let mut tmp = tera::Tera::default();
    tmp.add_raw_template(NET_HTML, NET_HTML_TEMPLATE)
        .unwrap_or(());
    tmp
});

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
                if IGNORED_INTERFACES
                    .iter()
                    .any(|&ignored| interface.starts_with(ignored))
                {
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
