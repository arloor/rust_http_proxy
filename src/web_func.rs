use crate::net_monitor::{NetMonitor, TimeValue};
use crate::proxy::empty_body;
use crate::proxy::full_body;
use crate::proxy::ReqLabels;
use crate::ProxyConfig;
use futures_util::TryStreamExt;
use http::Error;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, StreamBody};
use httpdate::fmt_http_date;
use hyper::body::{Body, Bytes, Frame};
use hyper::header::REFERER;
use hyper::{http, Method, Request, Response, StatusCode};
use log::{info, warn};
use mime_guess::from_path;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::ops::Deref;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::fs::{metadata, File};
use tokio::sync::RwLock;
use tokio_util::io::ReaderStream;

const SERVER_NAME: &str = "arloor's creation";

pub async fn serve_http_request(
    req: &Request<impl Body>,
    client_socket_addr: SocketAddr,
    proxy_config: &'static ProxyConfig,
    path: &str,
    net_monitor: NetMonitor,
    http_req_counter: Family<ReqLabels, Counter, fn() -> Counter>,
    prom_registry: Arc<RwLock<Registry>>,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    let hostname = proxy_config.hostname;
    let web_content_path = proxy_config.web_content_path;
    let refer = proxy_config.refer;
    let referer_header = req
        .headers()
        .get(REFERER)
        .map_or("", |h| h.to_str().unwrap_or(""));
    if (path.ends_with(".png") || path.ends_with(".jpeg") || path.ends_with(".jpg"))
        && refer != ""
        && referer_header != ""
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
        (_, "/nt") => {
            if cfg!(target_os = "windows") {
                not_found()
            } else {
                count_stream()
            }
        }
        (_, "/speed") => speed(net_monitor, hostname).await,
        (_, "/net") => speed(net_monitor, hostname).await,
        (_, "/metrics") => metrics(prom_registry.clone()).await,
        (&Method::GET, path) => {
            let is_outer_view_html = (path.ends_with("/") || path.ends_with(".html"))
                && referer_header != ""
                && !referer_header.contains(refer);
            info!(
                "{:>21?} {:^7} {} {:?} {}",
                client_socket_addr,
                req.method().as_str(),
                path,
                req.version(),
                if is_outer_view_html
                //来自外链的点击，记录Referer
                {
                    format!("\"Referer: {}\"", referer_header)
                } else {
                    "".to_string()
                }
            );
            let r = serve_path(web_content_path, path, req).await;
            if let Ok(ref res) = r {
                if is_outer_view_html
                    && (res.status().is_success() || res.status().is_redirection())
                {
                    http_req_counter
                        .get_or_create(&ReqLabels {
                            referer: referer_header.to_string(),
                            path: path.to_string(),
                        })
                        .inc();
                    http_req_counter
                        .get_or_create(&ReqLabels {
                            referer: "all".to_string(),
                            path: "all".to_string(),
                        })
                        .inc();
                }
            }
            r
        }
        (&Method::HEAD, path) => serve_path(web_content_path, path, req).await,
        _ => not_found(),
    };
}

async fn metrics(
    registry: Arc<RwLock<Registry>>,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    let mut buffer = String::new();
    if let Err(e) = encode(&mut buffer, registry.read().await.deref()) {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(http::header::SERVER, SERVER_NAME)
            .body(full_body(format!("encode metrics error: {}", e)));
    } else {
        return Response::builder()
            .status(StatusCode::OK)
            .header(http::header::SERVER, SERVER_NAME)
            .body(full_body(buffer));
    }
}

async fn serve_path(
    web_content_path: &String,
    url_path: &str,
    req: &Request<impl Body>,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    if String::from(url_path).contains("/..") {
        return not_found();
    }
    let mut path = PathBuf::from(if String::from(url_path).ends_with("/") {
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
        Err(_) => return not_found(),
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
    let file = match File::open(path).await {
        Ok(file) => file,
        Err(_) => return not_found(),
    };

    // Wrap to a tokio_util::io::ReaderStream
    let reader_stream = ReaderStream::new(file);

    // Convert to http_body_util::BoxBody
    let stream_body = StreamBody::new(reader_stream.map_ok(Frame::data));
    let boxed_body = stream_body.boxed();

    let content_type = mime_type.as_ref();
    let content_type = if !content_type.to_ascii_lowercase().contains("charset") {
        format!("{}{}", &content_type, "; charset=utf-8")
    } else {
        String::from(content_type)
    };
    Response::builder()
        .header(http::header::CONTENT_TYPE, content_type)
        .header(http::header::LAST_MODIFIED, fmt_http_date(last_modified))
        .header(http::header::SERVER, SERVER_NAME)
        .body(boxed_body)
}

fn serve_ip(client_socket_addr: SocketAddr) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::SERVER, SERVER_NAME)
        .body(full_body(client_socket_addr.ip().to_string()))
}

fn count_stream() -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    let output = Command::new("sh")
        .arg("-c")
        .arg("netstat -ntp|tail -n +3|grep -E  \"ESTABLISHED|CLOSE_WAIT\"|awk -F \"[ :]+\"  -v OFS=\"\" '$5<10000 && $5!=\"22\" && $7>1024 {printf(\"%15s   => %15s:%-5s %s\\n\",$6,$4,$5,$9)}'|sort|uniq -c|sort -rn")
        .output()
        .expect("error call netstat");

    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::SERVER, SERVER_NAME)
        .header(http::header::REFRESH, "3")
        .body(full_body(
            String::from_utf8(output.stdout).unwrap_or("".to_string())
                + (&*String::from_utf8(output.stderr).unwrap_or("".to_string())),
        ))
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

const PART0: &'static str = include_str!("../html/part0.html");
const PART1: &'static str = include_str!("../html/part1.html");
const PART2: &'static str = include_str!("../html/part2.html");
const PART3: &'static str = include_str!("../html/part3.html");
const PART4: &'static str = include_str!("../html/part4.html");
const H404: &'static str = include_str!("../html/404.html");

async fn speed(
    net_monitor: NetMonitor,
    hostname: &String,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    let r = fetch_all(net_monitor.get_data()).await;
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
            PART0, hostname, PART1, scales, PART2, interval, PART3, series_up, PART4
        )))
}

async fn fetch_all(buffer: Arc<RwLock<VecDeque<TimeValue>>>) -> Vec<TimeValue> {
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
