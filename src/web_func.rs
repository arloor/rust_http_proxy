use crate::net_monitor::{NetMonitor, TimeValue};
use crate::prom_label::LabelImpl;
use crate::proxy::empty_body;
use crate::proxy::full_body;
use crate::proxy::ReqLabels;
use crate::Config;
use lazy_static::lazy_static;

use async_compression::tokio::bufread::GzipEncoder;
use futures_util::TryStreamExt;
use http::Error;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, StreamBody};
use httpdate::fmt_http_date;
use hyper::body::{Body, Bytes, Frame};
use hyper::header::{CONTENT_ENCODING, REFERER};
use hyper::{http, Method, Request, Response, StatusCode};
use log::{info, warn};
use mime_guess::from_path;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use regex::Regex;
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::ops::Deref;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::fs::{metadata, File};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, BufReader};
use tokio::sync::RwLock;
use tokio_util::io::ReaderStream;

const SERVER_NAME: &str = "arloor's creation";

static GZIP: &str = "gzip";

pub async fn serve_http_request(
    req: &Request<impl Body>,
    client_socket_addr: SocketAddr,
    proxy_config: &'static Config,
    path: &str,
    _net_monitor: NetMonitor,
    http_req_counter: Family<LabelImpl<ReqLabels>, Counter, fn() -> Counter>,
    prom_registry: Arc<Registry>,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    let _hostname = &proxy_config.hostname;
    let web_content_path = &proxy_config.web_content_path;
    let refer = &proxy_config.referer;
    let referer_header = req
        .headers()
        .get(REFERER)
        .map_or("", |h| h.to_str().unwrap_or(""));
    if (path.ends_with(".png") || path.ends_with(".jpeg") || path.ends_with(".jpg"))
        && !refer.is_empty()
        && !referer_header.is_empty()
    {
        // 拒绝图片盗链
        if !referer_header.contains(refer) {
            warn!(
                "{} wrong Referer Header \"{}\" from {}",
                path, referer_header, client_socket_addr
            );
            return Ok(build_500_resp());
        }
    }
    return match (req.method(), path) {
        (_, "/ip") => serve_ip(client_socket_addr),
        #[cfg(target_os = "linux")]
        (_, "/nt") => _count_stream(),
        #[cfg(target_os = "linux")]
        (_, "/speed") => _speed(_net_monitor, _hostname).await,
        #[cfg(target_os = "linux")]
        (_, "/net") => _speed(_net_monitor, _hostname).await,
        (_, "/metrics") => metrics(prom_registry.clone()).await,
        (&Method::GET, path) => {
            let is_shell = path.ends_with(".sh");
            let is_outer_view_html = (path.ends_with('/') || path.ends_with(".html"))
                && !referer_header.is_empty()
                && !referer_header.contains(refer);
            info!(
                "{:>29} {:<5} {:^7} {} {:?} {}",
                "https://ip.im/".to_owned() + &client_socket_addr.ip().to_canonical().to_string(),
                client_socket_addr.port(),
                req.method().as_str(),
                path,
                req.version(),
                if is_outer_view_html
                //来自外链的点击，记录Referer
                {
                    format!("\"Referer: {}\"", referer_header)
                } else {
                    "".to_string()
                },
            );
            let r = serve_path(web_content_path, path, req, true).await;
            incr_counter_if_need(
                &r,
                is_outer_view_html,
                is_shell,
                http_req_counter,
                referer_header,
                path,
            );
            r
        }
        (&Method::HEAD, path) => serve_path(web_content_path, path, req, false).await,
        _ => not_found(),
    };
}

fn incr_counter_if_need(
    r: &Result<Response<BoxBody<Bytes, io::Error>>, Error>,
    is_outer_view_html: bool,
    is_shell: bool,
    http_req_counter: Family<LabelImpl<ReqLabels>, Counter>,
    referer_header: &str,
    path: &str,
) {
    if let Ok(ref res) = *r {
        if (is_outer_view_html || is_shell)
            && (res.status().is_success() || res.status().is_redirection())
        {
            http_req_counter
                .get_or_create(&LabelImpl::from(ReqLabels {
                    referer: referer_header.to_string(),
                    path: path.to_string(),
                }))
                .inc();
            if !is_shell {
                http_req_counter
                    .get_or_create(&LabelImpl::from(ReqLabels {
                        referer: "all".to_string(),
                        path: "all".to_string(),
                    }))
                    .inc();
            }
        }
    }
}

async fn metrics(registry: Arc<Registry>) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    let mut buffer = String::new();
    if let Err(e) = encode(&mut buffer, registry.deref()) {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(http::header::SERVER, SERVER_NAME)
            .body(full_body(format!("encode metrics error: {}", e)))
    } else {
        Response::builder()
            .status(StatusCode::OK)
            .header(http::header::SERVER, SERVER_NAME)
            .body(full_body(buffer))
    }
}

async fn serve_path(
    web_content_path: &String,
    url_path: &str,
    req: &Request<impl Body>,
    need_body: bool,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    if String::from(url_path).contains("/..") {
        return not_found();
    }
    let mut path = PathBuf::from(if String::from(url_path).ends_with('/') {
        format!("{}{}index.html", web_content_path, url_path)
    } else {
        format!("{}{}", web_content_path, url_path)
    });
    let meta = match metadata(&path).await {
        Ok(meta) => {
            if meta.is_file() {
                meta
            } else {
                path = PathBuf::from(format!("{}{}/index.html", web_content_path, url_path));
                match metadata(&path).await {
                    Ok(m) => m,
                    Err(_) => return not_found(),
                }
            }
        }
        Err(_) => {
            if url_path == "/favicon.ico" {
                return serve_favico(req, need_body);
            };
            return not_found();
        }
    };

    let last_modified: SystemTime = match meta.modified() {
        Ok(time) => time,
        Err(_) => return not_found(),
    };
    let mime_type = from_path(&path).first_or_octet_stream();
    if let Some(request_if_modified_since) = req.headers().get(http::header::IF_MODIFIED_SINCE) {
        if let Ok(request_if_modified_since) = request_if_modified_since.to_str() {
            if request_if_modified_since == fmt_http_date(last_modified).as_str() {
                return not_modified(last_modified);
            }
        }
    }

    let content_type = mime_type.as_ref();
    let content_type = if !content_type.to_ascii_lowercase().contains("charset") {
        format!("{}{}", &content_type, "; charset=utf-8")
    } else {
        String::from(content_type)
    };
    let mut builder = Response::builder()
        .header(http::header::CONTENT_TYPE, content_type.clone())
        .header(http::header::LAST_MODIFIED, fmt_http_date(last_modified))
        .header(http::header::ACCEPT_RANGES, "bytes")
        .header(http::header::SERVER, SERVER_NAME);

    // 判断客户端是否支持gzip
    let content_type = content_type.as_str();
    let accept_encoding = req
        .headers()
        .get(http::header::ACCEPT_ENCODING)
        .map_or("", |h| h.to_str().unwrap_or(""));
    let need_gzip = accept_encoding.contains(GZIP)
        && (content_type.starts_with("text/html")
            || content_type.starts_with("text/css")
            || content_type.starts_with("application/javascript")
            || content_type.starts_with("application/json")
            || content_type.starts_with("text/xml")
            || content_type.starts_with("application/xml")
            || content_type.starts_with("text/plain")
            || content_type.starts_with("text/markdown"));
    if need_gzip {
        builder = builder.header(CONTENT_ENCODING, GZIP)
    };
    if !need_body {
        return builder.body(empty_body());
    }

    let mut file = match File::open(path).await {
        Ok(file) => file,
        Err(_) => return not_found(),
    };

    let file_size = meta.len();
    let mut start = 0;
    let mut end = file_size - 1;
    if let Some(range_header) = req.headers().get(http::header::RANGE) {
        let range_value = range_header.to_str().unwrap();
        // 如果range_value中的 '-' 个数不等于1，则报错
        if range_value.matches('-').count() != 1 {
            let msg = "limitation: do not support multiple range";
            warn!("{}", msg);
            return Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(http::header::SERVER, SERVER_NAME)
                .body(full_body(msg));
        }
        // 编译正则表达式，并处理可能的错误
        let re = Regex::new(r"bytes=(\d*)-(\d*)").unwrap();

        // 使用正则表达式匹配字符串并捕获组
        let caps = re.captures(range_value);
        match caps {
            Some(caps) => {
                // 捕获组可以通过索引访问，索引0是整个匹配，索引1开始是捕获的组
                let left = caps.get(1).map_or("", |m| m.as_str());
                let right = caps.get(2).map_or("", |m| m.as_str());

                println!("range_value: {}-{}", left, right);
                if left.is_empty() {
                    if !right.is_empty() { // suffix-length格式，例如bytes=-100
                        let right = right.parse::<u64>().unwrap();
                        if right < file_size {
                            start = file_size - right;
                        } else {
                            let msg = "suffix-length bigger than file size";
                            warn!("{}", msg);
                            return Response::builder()
                                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                                .header(http::header::SERVER, SERVER_NAME)
                                .body(full_body(msg));
                        }
                    }
                } else { // start-end格式，例如bytes=100-200或bytes=100-
                    start = left.parse::<u64>().unwrap();
                    if !right.is_empty() {
                        end = right.parse::<u64>().unwrap();
                    }
                }
            }
            None => {
                let msg = "invalid range";
                warn!("{}", msg);
                return Response::builder()
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header(http::header::SERVER, SERVER_NAME)
                    .body(full_body(msg));
            }
        }

        builder = builder
            .header(
                "Content-Range",
                format!("bytes {}-{}/{}", start, end, file_size),
            )
            .status(http::StatusCode::PARTIAL_CONTENT);
    }
    if end < start {
        let msg = "end must be greater than or equal to start";
        warn!("{}", msg);
        return Response::builder()
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header(http::header::SERVER, SERVER_NAME)
            .body(full_body(msg));
    }
    if end >= file_size {
        let msg = "end must be less than file length";
        warn!("{}", msg);
        return Response::builder()
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header(http::header::SERVER, SERVER_NAME)
            .body(full_body(msg));
    }

    if start != 0 {
        if let Err(e) = file.seek(io::SeekFrom::Start(start)).await {
            warn!("seek file error: {}", e);
            return Ok(build_500_resp());
        };
    }
    let dyn_async_read: Box<dyn AsyncRead + Unpin + Send + Sync> = if end != file_size - 1 {
        Box::new(file.take(end - start + 1))
    } else {
        Box::new(file)
    };

    if need_gzip {
        let buf_stream = BufReader::new(dyn_async_read);
        let encoder = GzipEncoder::with_quality(buf_stream, async_compression::Level::Best);
        let reader_stream: ReaderStream<GzipEncoder<_>> = ReaderStream::new(encoder);
        let stream_body = StreamBody::new(reader_stream.map_ok(Frame::data));
        builder.body(stream_body.boxed())
    } else {
        let reader_stream = ReaderStream::new(dyn_async_read);
        let stream_body = StreamBody::new(reader_stream.map_ok(Frame::data));
        builder.body(stream_body.boxed())
    }
}

fn serve_favico(
    req: &Request<impl Body>,
    need_body: bool,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    if let Some(request_if_modified_since) = req.headers().get(http::header::IF_MODIFIED_SINCE) {
        if let Ok(request_if_modified_since) = request_if_modified_since.to_str() {
            if request_if_modified_since == fmt_http_date(BOOTUP_TIME.to_owned()).as_str() {
                return not_modified(BOOTUP_TIME.to_owned());
            }
        }
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::SERVER, SERVER_NAME)
        .header(
            http::header::LAST_MODIFIED,
            fmt_http_date(BOOTUP_TIME.to_owned()),
        )
        .header(http::header::CONTENT_TYPE, "image/x-icon")
        .body(if need_body {
            full_body(FAV_ICO.to_vec())
        } else {
            empty_body()
        })
}

fn serve_ip(client_socket_addr: SocketAddr) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::SERVER, SERVER_NAME)
        .body(full_body(
            client_socket_addr.ip().to_canonical().to_string(),
        ))
}

fn _count_stream() -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    match Command::new("sh")
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
        Err(_) => {
            Ok(build_500_resp())
        },
    }
}

fn not_found() -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(http::header::SERVER, SERVER_NAME)
        .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(full_body(H404))
}

fn not_modified(last_modified: SystemTime) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(http::header::LAST_MODIFIED, fmt_http_date(last_modified))
        .header(http::header::SERVER, SERVER_NAME)
        .body(empty_body())
}

const _PART0: &str = include_str!("../html/part0.html");
const _PART1: &str = include_str!("../html/part1.html");
const _PART2: &str = include_str!("../html/part2.html");
const _PART3: &str = include_str!("../html/part3.html");
const _PART4: &str = include_str!("../html/part4.html");
const H404: &str = include_str!("../html/404.html");
const FAV_ICO: &[u8] = include_bytes!("../html/favicon.ico");
lazy_static! {
    static ref BOOTUP_TIME: SystemTime = SystemTime::now();
}

async fn _speed(
    net_monitor: NetMonitor,
    hostname: &String,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    let r = _fetch_all(net_monitor._get_data()).await;
    let mut scales = vec![];
    let mut series_up = vec![];
    let mut max_up = 0;
    for x in r {
        scales.push(x.time);
        series_up.push(x.value);
        if x.value > max_up {
            max_up = x.value;
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
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::SERVER, SERVER_NAME)
        .body(full_body(format!(
            "{} {}网速 {} {:?} {} {} {}  {:?} {}",
            _PART0, hostname, _PART1, scales, _PART2, interval, _PART3, series_up, _PART4
        )))
}

async fn _fetch_all(buffer: Arc<RwLock<VecDeque<TimeValue>>>) -> Vec<TimeValue> {
    let buffer = buffer.read().await;
    let x = buffer.as_slices();
    let mut r = vec![];
    r.extend_from_slice(x.0);
    r.extend_from_slice(x.1);
    r
}

fn build_500_resp() -> Response<BoxBody<Bytes, std::io::Error>> {
    let mut resp = Response::new(full_body("Internal Server Error"));
    *resp.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
    resp
}
