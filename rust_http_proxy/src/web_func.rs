use crate::ip_x::SocketAddrFormat;
use crate::proxy::build_authenticate_resp;
use crate::proxy::check_auth;
use crate::proxy::empty_body;
use crate::proxy::full_body;
use crate::proxy::ProxyHandler;
use crate::proxy::ReqLabels;
use async_compression::tokio::bufread::GzipEncoder;
use futures_util::TryStreamExt;
use http::response::Builder;
use http::{Error, HeaderValue};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, StreamBody};
use httpdate::fmt_http_date;
use hyper::body::{Body, Bytes, Frame};
use hyper::header::{CONTENT_ENCODING, REFERER};
use hyper::{http, Method, Request, Response, StatusCode};
use log::{info, warn};
use mime_guess::from_path;
use prom_label::LabelImpl;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;
use regex::Regex;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin;
use std::sync::LazyLock;
use std::time::SystemTime;
use tokio::fs::{metadata, File};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, BufReader};
use tokio_util::io::ReaderStream;

pub(crate) static GZIP: &str = "gzip";
pub(crate) const SERVER_NAME: &str = "The Bad Server";

pub async fn serve_http_request(
    proxy_handler: &ProxyHandler, req: &Request<impl Body>, client_socket_addr: SocketAddr, path: &str,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    let web_content_path = &proxy_handler.config.web_content_path;
    let referer_keywords_to_self = &proxy_handler.config.referer_keywords_to_self;
    let referer_header = req.headers().get(REFERER).map_or("", |h| h.to_str().unwrap_or(""));
    if (path.ends_with(".png") || path.ends_with(".jpeg") || path.ends_with(".jpg"))
        && !referer_keywords_to_self.is_empty()
        && !referer_header.is_empty()
    {
        // 如果referer_header不包含任何一个refers，则返回404
        if !referer_keywords_to_self
            .iter()
            .any(|refer| referer_header.contains(refer))
        {
            warn!(
                "{} wrong Referer Header \"{}\" from [{}]",
                path,
                referer_header,
                SocketAddrFormat(&client_socket_addr)
            );
            return not_found();
        }
    }
    #[cfg(target_os = "linux")]
    let hostname = req
        .uri()
        .authority()
        .map_or(proxy_handler.config.hostname.as_str(), |authority| authority.host());
    let accept_encoding = req
        .headers()
        .get(http::header::ACCEPT_ENCODING)
        .map_or("", |h| h.to_str().unwrap_or(""));
    let can_gzip = accept_encoding.contains(GZIP);
    #[allow(clippy::needless_return)]
    return match (req.method(), path) {
        (_, "/ip") => serve_ip(client_socket_addr),
        #[cfg(target_os = "linux")]
        (_, "/nt") => crate::linux_monitor::count_stream(),
        #[cfg(target_os = "linux")]
        (_, "/net" | "/netx") => proxy_handler.linux_monitor.net_html(path, hostname, can_gzip).await,
        #[cfg(target_os = "linux")]
        (_, "/net.json") => proxy_handler.linux_monitor.net_json(can_gzip).await,
        (_, "/metrics") => {
            if let (_, false) =
                check_auth(&proxy_handler.config.basic_auth, req, &client_socket_addr, hyper::header::AUTHORIZATION)
            {
                return Ok(build_authenticate_resp(false));
            }
            #[cfg(all(target_os = "linux", feature = "bpf"))]
            proxy_handler.snapshot_metrics();
            serve_metrics(&proxy_handler.prom_registry, can_gzip).await
        }
        (&Method::GET, path) => {
            let is_outer_view_html = (path.ends_with('/') || path.ends_with(".html"))
                && !referer_header.is_empty() // 存在Referer Header
                && !referer_keywords_to_self.is_empty() // Referer关键字不为空
                && !referer_keywords_to_self.iter().any(|refer| referer_header.contains(refer));
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
            let r = serve_path(web_content_path, path, req, can_gzip, true).await;
            let is_shell = path.ends_with(".sh");
            incr_counter_if_need(
                &r,
                is_outer_view_html,
                is_shell,
                &proxy_handler.metrics.http_req_counter,
                referer_header,
                path,
            );
            r
        }
        (&Method::HEAD, path) => serve_path(web_content_path, path, req, false, false).await,
        _ => not_found(),
    };
}

fn incr_counter_if_need(
    r: &Result<Response<BoxBody<Bytes, io::Error>>, Error>, is_outer_view_html: bool, _is_shell: bool,
    http_req_counter: &Family<LabelImpl<ReqLabels>, Counter>, referer_header: &str, path: &str,
) {
    if let Ok(ref res) = *r {
        if is_outer_view_html && (res.status().is_success() || res.status().is_redirection()) {
            http_req_counter
                .get_or_create(&LabelImpl::new(ReqLabels {
                    referer: extract_search_engine_from_referer(referer_header).unwrap_or("parse_failed".to_string()),
                    path: path.to_string(),
                }))
                .inc();
            http_req_counter.get_or_create(&ALL_HTTP_REQ).inc();
        }
    }
}

static ALL_HTTP_REQ: LazyLock<prom_label::LabelImpl<ReqLabels>> = LazyLock::new(|| {
    LabelImpl::new(ReqLabels {
        referer: "all".to_string(),
        path: "all".to_string(),
    })
});

fn extract_search_engine_from_referer(referer: &str) -> Result<String, regex::Error> {
    if let Some(caps) = Regex::new("^https?://(.+?)(/|$)")?.captures(referer) {
        let address = caps.get(1).map_or(referer, |g| g.as_str());
        if let Some(caps) =
            Regex::new("(google|baidu|bing|yandex|v2ex|github|stackoverflow|duckduckgo)")?.captures(address)
        {
            Ok(caps.get(1).map_or(address, |g| g.as_str()).to_string())
        } else {
            Ok(address.to_owned())
        }
    } else {
        Ok(referer.to_string())
    }
}

async fn serve_metrics(prom_registry: &Registry, can_gzip: bool) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    let mut buffer = String::new();
    if let Err(e) = encode(&mut buffer, prom_registry) {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(http::header::SERVER, SERVER_NAME)
            .body(full_body(format!("encode metrics error: {}", e)))
    } else {
        let builder = Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(http::header::SERVER, SERVER_NAME);
        if can_gzip {
            let compressed_data = match compress_string(&buffer) {
                Ok(compressed_data) => compressed_data,
                Err(e) => {
                    warn!("compress metrics error: {}", e);
                    return Ok(build_500_resp());
                }
            };
            builder
                .header(http::header::CONTENT_ENCODING, GZIP)
                .body(full_body(compressed_data))
        } else {
            builder.body(full_body(buffer))
        }
    }
}

async fn serve_path(
    web_content_path: &String, url_path: &str, req: &Request<impl Body>, can_gzip: bool, need_body: bool,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    if String::from(url_path).contains("/..") {
        return not_found();
    }
    // 禁止访问.git目录
    if String::from(url_path).starts_with("/.git/") {
        return not_found();
    }
    let path = if String::from(url_path).ends_with('/') {
        format!("{}{}index.html", web_content_path, url_path)
    } else {
        format!("{}{}", web_content_path, url_path)
    };
    let mut path = PathBuf::from(path);
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
    let file_len = meta.len();
    let file_etag = cal_file_etag(last_modified, file_len);
    if let Some(response) = return_304_if_not_modified(req, &file_etag, last_modified) {
        return response;
    }
    let mime_type = from_path(&path).first_or_octet_stream();
    let content_type = mime_type.as_ref();
    let content_type = if !content_type.to_ascii_lowercase().contains("charset") && !content_type.contains("wasm") {
        format!("{}{}", &content_type, "; charset=utf-8")
    } else {
        String::from(content_type)
    };
    let mut builder = Response::builder()
        .header(http::header::CONTENT_TYPE, content_type.as_str())
        .header(http::header::LAST_MODIFIED, fmt_http_date(last_modified))
        .header(http::header::ETAG, file_etag)
        .header(http::header::ACCEPT_RANGES, "bytes")
        .header(http::header::SERVER, SERVER_NAME);

    // 判断客户端是否支持gzip
    let content_type = content_type.as_str();
    let need_gzip = can_gzip
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

    let (start, end, builder) = match parse_range(req.headers().get(http::header::RANGE), file_len, builder) {
        Ok((start, end, builder)) => (start, end, builder),
        Err(e) => {
            return Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(http::header::SERVER, SERVER_NAME)
                .body(full_body(e.to_string()));
        }
    };

    if start != 0 {
        if let Err(e) = file.seek(io::SeekFrom::Start(start)).await {
            warn!("seek file error: {}", e);
            return Ok(build_500_resp());
        };
    }
    if end != file_len - 1 {
        final_build(need_gzip, file.take(end - start + 1), builder)
    } else {
        final_build(need_gzip, file, builder)
    }
}

fn return_304_if_not_modified(
    req: &Request<impl Body>, file_etag: &str, last_modified: SystemTime,
) -> Option<Result<Response<BoxBody<Bytes, io::Error>>, Error>> {
    match req.headers().get(http::header::IF_NONE_MATCH) {
        Some(if_none_match) => {
            // use if-none-match
            let if_none_match = if_none_match.to_str().ok()?;
            if if_none_match == file_etag {
                Some(not_modified(last_modified, file_etag))
            } else {
                None
            }
        }
        None => {
            // fallback to if-modified-since
            let if_modified_since = req.headers().get(http::header::IF_MODIFIED_SINCE)?;
            let if_modified_since = if_modified_since.to_str().ok()?;
            if if_modified_since == fmt_http_date(last_modified.to_owned()).as_str() {
                Some(not_modified(last_modified, file_etag))
            } else {
                None
            }
        }
    }
}

fn not_modified(last_modified: SystemTime, file_etag: &str) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(http::header::ETAG, file_etag)
        .header(http::header::LAST_MODIFIED, fmt_http_date(last_modified))
        .header(http::header::SERVER, SERVER_NAME)
        .body(empty_body())
}

fn cal_file_etag(last_modified: SystemTime, file_len: u64) -> String {
    let last_modified_secs = last_modified
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("\"{:x}-{:x}\"", last_modified_secs, file_len)
}

fn final_build<T>(
    need_gzip: bool, async_read: T, builder: Builder,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Error>
where
    T: AsyncRead + Send + Sync + Unpin + 'static,
{
    let stream_body = StreamBody::new(build_reader_stream(async_read, need_gzip).map_ok(Frame::data));
    builder.body(stream_body.boxed())
}

fn build_reader_stream<T>(
    async_read: T, need_gzip: bool,
) -> ReaderStream<pin::Pin<Box<dyn AsyncRead + Send + Sync + Unpin>>>
where
    T: AsyncRead + Send + Sync + Unpin + 'static,
{
    let dyn_async_read: pin::Pin<Box<dyn AsyncRead + Send + Sync + Unpin>> = if need_gzip {
        let buf_stream = BufReader::new(async_read);
        let encoder = GzipEncoder::with_quality(buf_stream, async_compression::Level::Best);
        Box::pin(encoder)
    } else {
        Box::pin(async_read)
    };
    ReaderStream::new(dyn_async_read)
}

fn parse_range(
    range_header: Option<&HeaderValue>, file_size: u64, mut builder: Builder,
) -> io::Result<(u64, u64, Builder)> {
    let mut start = 0;
    let mut end = file_size - 1;
    if let Some(range_value) = range_header {
        let range_value = range_value
            .to_str()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // 仅支持单个range，不支持多个range
        let re = Regex::new(r"^bytes=(\d*)-(\d*)$").map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // 使用正则表达式匹配字符串并捕获组
        let caps = re.captures(range_value);
        match caps {
            Some(caps) => {
                // 捕获组可以通过索引访问，索引0是整个匹配，索引1开始是捕获的组
                let left = caps.get(1).map_or("", |m| m.as_str());
                let right = caps.get(2).map_or("", |m| m.as_str());

                if left.is_empty() {
                    if !right.is_empty() {
                        // suffix-length格式，例如bytes=-100
                        let right = right
                            .parse::<u64>()
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                        if right < file_size {
                            start = file_size - right;
                        } else {
                            let msg = "suffix-length bigger than file size";
                            return Err(io::Error::new(io::ErrorKind::InvalidInput, msg));
                        }
                    }
                } else {
                    // start-end格式，例如bytes=100-200或bytes=100-
                    start = left
                        .parse::<u64>()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                    if !right.is_empty() {
                        end = right
                            .parse::<u64>()
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                    }
                }
                builder = builder
                    .header(http::header::CONTENT_RANGE, format!("bytes {}-{}/{}", start, end, file_size))
                    .status(http::StatusCode::PARTIAL_CONTENT);
            }
            None => {
                let msg = "invalid range";
                return Err(io::Error::new(io::ErrorKind::InvalidInput, msg));
            }
        }
    }
    if end < start {
        let msg = "end must be greater than or equal to start";
        return Err(io::Error::new(io::ErrorKind::InvalidInput, msg));
    }
    if end >= file_size {
        let msg = "end must be less than file length";
        return Err(io::Error::new(io::ErrorKind::InvalidInput, msg));
    }
    Ok((start, end, builder))
}

fn serve_favico(req: &Request<impl Body>, need_body: bool) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    let last_modified = BOOTUP_TIME.to_owned();
    let file_len = FAV_ICO.len() as u64;
    let file_etag = cal_file_etag(last_modified, file_len);
    if let Some(response) = return_304_if_not_modified(req, &file_etag, last_modified) {
        return response;
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::SERVER, SERVER_NAME)
        .header(http::header::LAST_MODIFIED, fmt_http_date(last_modified))
        .header(http::header::ETAG, file_etag)
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
        .body(full_body(client_socket_addr.ip().to_canonical().to_string()))
}

fn not_found() -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(http::header::SERVER, SERVER_NAME)
        .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(full_body(H404))
}
pub(crate) const H404: &str = include_str!("../html/404.html");
const FAV_ICO: &[u8] = include_bytes!("../html/favicon.ico");
static BOOTUP_TIME: LazyLock<SystemTime> = LazyLock::new(SystemTime::now);

pub(crate) fn build_500_resp() -> Response<BoxBody<Bytes, std::io::Error>> {
    let mut resp = Response::new(full_body("Internal Server Error"));
    *resp.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
    resp
}

use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::prelude::*;

pub(crate) fn compress_string(input: &str) -> io::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input.as_bytes())?;
    encoder.finish()
}

#[allow(unused)]
use flate2::read::GzDecoder;
#[allow(unused)]
fn decompress_string(input: &[u8]) -> io::Result<String> {
    let mut decoder = GzDecoder::new(input);
    let mut decompressed_data = String::new();
    decoder.read_to_string(&mut decompressed_data)?;
    Ok(decompressed_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_extract_domain_from_url() {
        assert_eq!(
            extract_search_engine_from_referer("https://www.baidu.com/").unwrap_or("default".to_string()),
            "baidu"
        );
        assert_eq!(
            extract_search_engine_from_referer("https://www.baidu.com").unwrap_or("default".to_string()),
            "baidu"
        );
        assert_eq!(
            extract_search_engine_from_referer("http://www.baidu.com/").unwrap_or("default".to_string()),
            "baidu"
        );
        assert_eq!(
            extract_search_engine_from_referer("sadasdasdsadas").unwrap_or("default".to_string()),
            "sadasdasdsadas"
        );
        assert_eq!(
            extract_search_engine_from_referer("http://huaiwen.com/baidu.com/bing.com")
                .unwrap_or("default".to_string()),
            "huaiwen.com"
        );
        assert_eq!(
            extract_search_engine_from_referer("http://huaiwenbaidu.com/baidu.com/bing.com")
                .unwrap_or("default".to_string()),
            "baidu"
        );
        assert_eq!(
            extract_search_engine_from_referer("https://www.google.com.hk/").unwrap_or("default".to_string()),
            "google"
        );
        assert_eq!(
            extract_search_engine_from_referer(
                "https://www.bing.com/search?q=google%E6%9C%8D%E5%8A%A1%E4%B8%8B%E8%BD%BD+anzhuo11&qs=ds&form=QBRE"
            )
            .unwrap_or("default".to_string()),
            "bing"
        );
    }

    #[test]
    fn test_gzip_compress_string() -> io::Result<()> {
        let original_string = "Hello, Rust! This is a test string for Gzip compression.";
        let compressed_data = compress_string(original_string)?;
        let decompressed_string = decompress_string(&compressed_data)?;

        assert_eq!(original_string, decompressed_string);
        Ok(())
    }
}
