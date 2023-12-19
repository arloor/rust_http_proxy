use crate::monitor::Point;
use httpdate::fmt_http_date;
use hyper::http::HeaderValue;
use hyper::{http, Method, Request, Response, StatusCode};
use log::{info, warn};
use mime_guess::from_path;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::ops::Deref;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::SystemTime;
use futures_util::TryStreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Body, Bytes, Frame};
use hyper::header::REFERER;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use tokio::fs::{metadata, File};
use tokio::sync::RwLock;
use tokio_util::io::ReaderStream;
use crate::{_build_500_resp, empty, full, ReqLabels, StaticConfig};
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;

const SERVER_NAME: &str = "arloor's creation";

pub async fn serve_http_request(
    req: &Request<impl Body>,
    client_socket_addr: SocketAddr,
    config: &'static StaticConfig,
    path: &str,
    buffer: Arc<RwLock<VecDeque<Point>>>,
    http_requests: Family<ReqLabels, Counter, fn() -> Counter>,
    registry:Arc<RwLock<Registry>>
) -> Response<BoxBody<Bytes, std::io::Error>> {
    let hostname = config.hostname;
    let web_content_path = config.web_content_path;
    let refer = config.refer;
    let referer_header = req.headers().get(REFERER).map_or("", |h| h.to_str().unwrap_or(""));
    if (path.ends_with(".png") || path.ends_with(".jpeg") || path.ends_with(".jpg"))
        && refer != "" && referer_header != ""
    { // 拒绝图片盗链
        if !referer_header.contains(refer) {
            warn!("{} wrong Referer Header \"{}\" from {}",path,referer_header,client_socket_addr);
            return _build_500_resp();
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
        (_, "/speed") => speed(buffer, hostname).await,
        (_, "/net") => speed(buffer, hostname).await,
        (_, "/metrics") => metrics(registry.clone()).await,
        (&Method::GET, path) => {
            info!(
                "{:>21?} {:^7} {} {:?} {}",
                client_socket_addr,
                req.method().as_str(),
                path,
                req.version(),
                if (path.ends_with("/")||path.ends_with(".html"))
                    &&referer_header!=""
                    &&!referer_header.contains(refer) //来自外链的点击，记录Referer
                {
                    http_requests.get_or_create(
                        &ReqLabels { referer: referer_header.to_string(), path: path.to_string() }
                    ).inc();
                    http_requests.get_or_create(
                        &ReqLabels { referer: "all".to_string(), path: "all".to_string() }
                    ).inc();
                    format!("\"Referer: {}\"",referer_header)
                }else{
                    "".to_string()
                }
            );
            serve_path(web_content_path, path, req).await
        }
        (&Method::HEAD, path) => serve_path(web_content_path, path, req).await,
        _ => not_found(),
    };
}

async fn metrics( registry:Arc<RwLock<Registry>>) -> Response<BoxBody<Bytes, std::io::Error>>{
    let mut buffer = String::new();
    encode(&mut buffer, registry.read().await.deref()).unwrap();
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::SERVER, SERVER_NAME)
        .body(full(buffer))
        .unwrap()

}

async fn serve_path(
    web_content_path: &String,
    url_path: &str,
    req: &Request<impl Body>,
) -> Response<BoxBody<Bytes, std::io::Error>> {
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
        if request_if_modified_since
            == HeaderValue::from_str(fmt_http_date(last_modified).as_str()).unwrap()
        {
            return not_modified(last_modified);
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
    let content_type = if !content_type
        .to_ascii_lowercase()
        .contains("; charset=utf-8")
    {
        format!("{}{}", &content_type, "; charset=utf-8")
    } else {
        String::from(content_type)
    };
    Response::builder()
        .header(http::header::CONTENT_TYPE, content_type)
        .header(http::header::LAST_MODIFIED, fmt_http_date(last_modified))
        .header(http::header::SERVER, SERVER_NAME)
        .body(boxed_body)
        .unwrap()
}

fn serve_ip(client_socket_addr: SocketAddr) -> Response<BoxBody<Bytes, std::io::Error>> {
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::SERVER, SERVER_NAME)
        .body(full(client_socket_addr.ip().to_string()))
        .unwrap()
}

fn count_stream() -> Response<BoxBody<Bytes, std::io::Error>> {
    let output = Command::new("sh")
        .arg("-c")
        .arg("netstat -ntp|tail -n +3|grep -E  \"ESTABLISHED|CLOSE_WAIT\"|awk -F \"[ :]+\"  -v OFS=\"\" '$5<10000 && $5!=\"22\" && $7>1024 {printf(\"%15s   => %15s:%-5s %s\\n\",$6,$4,$5,$9)}'|sort|uniq -c|sort -rn")
        .output()
        .expect("error call netstat");

    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::SERVER, SERVER_NAME)
        .header(http::header::REFRESH, "3")
        .body(full(
            String::from_utf8(output.stdout).unwrap()
                + (&*String::from_utf8(output.stderr).unwrap()),
        ))
        .unwrap()
}

fn not_found() -> Response<BoxBody<Bytes, std::io::Error>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(http::header::SERVER, SERVER_NAME)
        .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(full(H404))
        .unwrap()
}

fn not_modified(last_modified: SystemTime) -> Response<BoxBody<Bytes, std::io::Error>> {
    Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(http::header::LAST_MODIFIED, fmt_http_date(last_modified))
        .header(http::header::SERVER, SERVER_NAME)
        .body(empty())
        .unwrap()
}

const PART0: &'static str = include_str!("../html/part0.html");
const PART1: &'static str = include_str!("../html/part1.html");
const PART2: &'static str = include_str!("../html/part2.html");
const PART3: &'static str = include_str!("../html/part3.html");
const PART4: &'static str = include_str!("../html/part4.html");
const H404: &'static str = include_str!("../html/404.html");

async fn speed(buffer: Arc<RwLock<VecDeque<Point>>>, hostname: &String) -> Response<BoxBody<Bytes, std::io::Error>> {
    let r = fetch_all(buffer).await;
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
        .body(full(format!(
            "{} {}网速 {} {:?} {} {} {}  {:?} {}",
            PART0, hostname, PART1, scales, PART2, interval, PART3, series_up, PART4
        )))
        .unwrap()
}

async fn fetch_all(buffer: Arc<RwLock<VecDeque<Point>>>) -> Vec<Point> {
    let buffer = buffer.read().await;
    let x = buffer.as_slices();
    let mut r = vec![];
    r.extend_from_slice(x.0);
    r.extend_from_slice(x.1);
    r
}
