use crate::METRICS;
use crate::config::Config;
use crate::ip_x::SocketAddrFormat;
use crate::proxy::ReqLabels;
use crate::proxy::empty_body;
use crate::proxy::full_body;
use async_compression::tokio::bufread::GzipEncoder;
use futures_util::TryStreamExt;
use http::response::Builder;
use http::{Error, HeaderValue};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, StreamBody};
use httpdate::fmt_http_date;
use hyper::body::{Body, Bytes, Frame};
use hyper::header::{CONTENT_ENCODING, REFERER};
use hyper::{Method, Request, Response, StatusCode, http};
use log::{info, warn};
use mime_guess::from_path;
use prom_label::LabelImpl;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use regex::Regex;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::pin;
use std::sync::LazyLock;
use std::time::SystemTime;
use tokio::fs::{File, metadata};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, BufReader};
use tokio_util::io::ReaderStream;

pub(crate) static GZIP: &str = "gzip";
pub(crate) const SERVER_NAME: &str = "The Bad Server";

pub async fn serve_http_request(
    req: &Request<impl Body>, client_socket_addr: SocketAddr, path: &str, static_dir: &str, config: &Config,
    auth_protected: bool,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    // 受 Basic 认证保护的路径禁止共享缓存（CDN）存储；未保护路径给出明确的 TTL 新鲜度
    let cache_control = if auth_protected {
        "private, no-store".to_string()
    } else {
        format!("public, max-age={}", config.static_cache_max_age)
    };
    let cache_control = cache_control.as_str();
    let referer_keywords_to_self = &config.referer_keywords_to_self;
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
    let accept_encoding = req
        .headers()
        .get(http::header::ACCEPT_ENCODING)
        .map_or("", |h| h.to_str().unwrap_or(""));
    let can_gzip = accept_encoding.contains(GZIP);

    #[allow(clippy::needless_return)]
    return match (req.method(), path) {
        (&Method::GET, path) => {
            let is_outer_view_html = (path.ends_with('/') || path.ends_with(".html"))
                && !referer_header.is_empty() // 存在Referer Header
                && !referer_keywords_to_self.is_empty() // Referer关键字不为空
                && !referer_keywords_to_self.iter().any(|refer| referer_header.contains(refer));

            info!(
                "{:>29} {:<5} {:^7} {} {:?} [dir: {} ] {}",
                "https://ip.im/".to_owned() + &client_socket_addr.ip().to_canonical().to_string(),
                client_socket_addr.port(),
                req.method().as_str(),
                path,
                req.version(),
                static_dir,
                if is_outer_view_html
                //来自外链的点击，记录Referer
                {
                    format!("\"Referer: {referer_header}\"")
                } else {
                    "".to_string()
                },
            );
            let r = serve_path(static_dir, path, req, can_gzip, true, cache_control).await;
            let is_shell = path.ends_with(".sh");
            incr_counter_if_need(&r, is_outer_view_html, is_shell, &METRICS.http_req_counter, referer_header, path);
            r
        }
        (&Method::HEAD, path) => serve_path(static_dir, path, req, false, false, cache_control).await,
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

async fn serve_path(
    static_dir: &str, url_path: &str, req: &Request<impl Body>, can_gzip: bool, need_body: bool, cache_control: &str,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    if !crate::path_security::valid_static_path(url_path) {
        return not_found();
    }
    let mut path = Path::new(static_dir).join(&url_path[1..]);
    if url_path.ends_with('/') {
        path.push("index.html");
    }
    match metadata(&path).await {
        Ok(meta) => {
            if meta.is_dir() {
                path.push("index.html");
            } else if !meta.is_file() {
                return not_found();
            }
        }
        Err(_) => {
            if url_path == "/favicon.ico" {
                return serve_favico(req, need_body, cache_control);
            };
            return not_found();
        }
    }
    // Resolve both the root and the selected index/file before checking containment.
    // The serving tree must not be writable by untrusted users during lookup/open.
    let root = match tokio::fs::canonicalize(static_dir).await {
        Ok(root) => root,
        Err(_) => return not_found(),
    };
    let path = match tokio::fs::canonicalize(path).await {
        Ok(path) if path.starts_with(&root) => path,
        _ => return not_found(),
    };
    let relative = match path.strip_prefix(&root) {
        Ok(relative) => relative,
        Err(_) => return not_found(),
    };
    if relative
        .components()
        .any(|part| part.as_os_str().to_string_lossy().eq_ignore_ascii_case(".git"))
    {
        return not_found();
    }
    let mut file = match File::open(&path).await {
        Ok(file) => file,
        Err(_) => return not_found(),
    };
    let meta = match file.metadata().await {
        Ok(meta) if meta.is_file() => meta,
        _ => return not_found(),
    };

    let last_modified: SystemTime = match meta.modified() {
        Ok(time) => time,
        Err(_) => return not_found(),
    };
    let file_len = meta.len();
    let file_etag = cal_file_etag(last_modified, file_len);
    if let Some(response) = return_304_if_not_modified(req, &file_etag, last_modified, cache_control) {
        return response;
    }
    let mime_type = from_path(&path).first_or_octet_stream();
    let content_type = mime_type.as_ref();
    let content_type = if !content_type.to_ascii_lowercase().contains("charset") && !content_type.contains("wasm") {
        format!("{}{}", content_type, "; charset=utf-8")
    } else {
        String::from(content_type)
    };
    let mut builder = Response::builder()
        .header(http::header::CONTENT_TYPE, content_type.as_str())
        .header(http::header::CACHE_CONTROL, cache_control)
        .header(http::header::LAST_MODIFIED, fmt_http_date(last_modified))
        .header(http::header::ETAG, file_etag)
        .header(http::header::ACCEPT_RANGES, "bytes")
        .header(http::header::SERVER, SERVER_NAME);

    // 判断客户端是否支持gzip
    let content_type = content_type.as_str();
    let need_gzip = can_gzip
        && file_len != 0
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
        return builder
            .header(http::header::CONTENT_LENGTH, file_len)
            .body(empty_body());
    }
    if file_len == 0 && !req.headers().contains_key(http::header::RANGE) {
        return builder.header(http::header::CONTENT_LENGTH, 0).body(empty_body());
    }

    let (start, end, builder) = match parse_range(req.headers().get(http::header::RANGE), file_len, builder) {
        Ok((start, end, builder)) => (start, end, builder),
        Err(e) => {
            return Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header(http::header::SERVER, SERVER_NAME)
                .header(http::header::CONTENT_RANGE, format!("bytes */{file_len}"))
                .header(http::header::CACHE_CONTROL, cache_control)
                .body(full_body(e.to_string()));
        }
    };

    if start != 0 {
        if let Err(e) = file.seek(io::SeekFrom::Start(start)).await {
            warn!("seek file error: {e}");
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
    req: &Request<impl Body>, file_etag: &str, last_modified: SystemTime, cache_control: &str,
) -> Option<Result<Response<BoxBody<Bytes, io::Error>>, Error>> {
    match req.headers().get(http::header::IF_NONE_MATCH) {
        Some(if_none_match) => {
            // use if-none-match
            let if_none_match = if_none_match.to_str().ok()?;
            if if_none_match == file_etag {
                Some(not_modified(last_modified, file_etag, cache_control))
            } else {
                None
            }
        }
        None => {
            // fallback to if-modified-since
            let if_modified_since = req.headers().get(http::header::IF_MODIFIED_SINCE)?;
            let if_modified_since = if_modified_since.to_str().ok()?;
            if if_modified_since == fmt_http_date(last_modified.to_owned()).as_str() {
                Some(not_modified(last_modified, file_etag, cache_control))
            } else {
                None
            }
        }
    }
}

fn not_modified(
    last_modified: SystemTime, file_etag: &str, cache_control: &str,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(http::header::ETAG, file_etag)
        .header(http::header::LAST_MODIFIED, fmt_http_date(last_modified))
        .header(http::header::CACHE_CONTROL, cache_control)
        .header(http::header::SERVER, SERVER_NAME)
        .body(empty_body())
}

fn cal_file_etag(last_modified: SystemTime, file_len: u64) -> String {
    let last_modified_secs = last_modified
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("\"{last_modified_secs:x}-{file_len:x}\"")
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
    let mut end = file_size
        .checked_sub(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty file has no byte ranges"))?;
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
                    .header(http::header::CONTENT_RANGE, format!("bytes {start}-{end}/{file_size}"))
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

fn serve_favico(
    req: &Request<impl Body>, need_body: bool, cache_control: &str,
) -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    let last_modified = BOOTUP_TIME.to_owned();
    let file_len = FAV_ICO.len() as u64;
    let file_etag = cal_file_etag(last_modified, file_len);
    if let Some(response) = return_304_if_not_modified(req, &file_etag, last_modified, cache_control) {
        return response;
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::SERVER, SERVER_NAME)
        .header(http::header::LAST_MODIFIED, fmt_http_date(last_modified))
        .header(http::header::ETAG, file_etag)
        .header(http::header::CACHE_CONTROL, cache_control)
        .header(http::header::CONTENT_TYPE, "image/x-icon")
        .body(if need_body {
            full_body(FAV_ICO.to_vec())
        } else {
            empty_body()
        })
}

pub(crate) fn not_found() -> Result<Response<BoxBody<Bytes, io::Error>>, Error> {
    Response::builder().status(StatusCode::NOT_FOUND).body(empty_body())
}
const FAV_ICO: &[u8] = include_bytes!("../html/favicon.ico");
static BOOTUP_TIME: LazyLock<SystemTime> = LazyLock::new(SystemTime::now);

pub(crate) fn build_500_resp() -> Response<BoxBody<Bytes, std::io::Error>> {
    let mut resp = Response::new(full_body("Internal Server Error"));
    *resp.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
    resp
}
use std::io::prelude::*;

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

    #[tokio::test]
    async fn security_empty_file_get_and_range_have_valid_responses() -> Result<(), crate::DynError> {
        use clap::Parser;
        let dir = crate::e2e_test_support::unique_temp_dir("empty_static")?;
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("empty.txt"), [])?;
        let config = Config::try_from(crate::config::Param::parse_from(["proxy"]))?;
        let peer = "127.0.0.1:1234".parse()?;
        let req = Request::builder().uri("/empty.txt").body(empty_body())?;
        let response = serve_http_request(&req, peer, "/empty.txt", &dir.to_string_lossy(), &config, false).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.into_body().collect().await?.to_bytes().is_empty());
        let req = Request::builder()
            .uri("/empty.txt")
            .header(http::header::RANGE, "bytes=0-")
            .body(empty_body())?;
        let response = serve_http_request(&req, peer, "/empty.txt", &dir.to_string_lossy(), &config, false).await?;
        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(response.headers().get(http::header::CONTENT_RANGE).unwrap(), "bytes */0");
        for method in [Method::GET, Method::HEAD] {
            let req = Request::builder()
                .method(method)
                .uri("/empty.txt")
                .header(http::header::ACCEPT_ENCODING, "gzip")
                .body(empty_body())?;
            let response = serve_http_request(&req, peer, "/empty.txt", &dir.to_string_lossy(), &config, true).await?;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[http::header::CONTENT_LENGTH], "0");
            assert_eq!(response.headers()[http::header::CACHE_CONTROL], "private, no-store");
            assert!(!response.headers().contains_key(http::header::CONTENT_ENCODING));
            assert!(response.into_body().collect().await?.to_bytes().is_empty());
        }
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[tokio::test]
    async fn static_files_keep_gzip_range_head_and_conditional_responses() -> Result<(), crate::DynError> {
        use clap::Parser;
        let dir = crate::e2e_test_support::unique_temp_dir("static_response_regression")?;
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("file.txt"), "hello-world")?;
        let config = Config::try_from(crate::config::Param::parse_from(["proxy"]))?;
        let peer = "127.0.0.1:1234".parse()?;
        let req = Request::builder()
            .uri("/file.txt")
            .header(http::header::ACCEPT_ENCODING, "gzip")
            .body(empty_body())?;
        let response = serve_http_request(&req, peer, "/file.txt", &dir.to_string_lossy(), &config, false).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[http::header::CONTENT_ENCODING], "gzip");
        let etag = response.headers()[http::header::ETAG].clone();
        let body = response.into_body().collect().await?.to_bytes();
        assert_eq!(decompress_string(&body)?, "hello-world");
        let req = Request::builder()
            .uri("/file.txt")
            .header(http::header::RANGE, "bytes=2-5")
            .body(empty_body())?;
        let response = serve_http_request(&req, peer, "/file.txt", &dir.to_string_lossy(), &config, false).await?;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.headers()[http::header::CONTENT_RANGE], "bytes 2-5/11");
        assert_eq!(response.into_body().collect().await?.to_bytes().as_ref(), b"llo-");
        let req = Request::builder()
            .method(Method::HEAD)
            .uri("/file.txt")
            .body(empty_body())?;
        let response = serve_http_request(&req, peer, "/file.txt", &dir.to_string_lossy(), &config, false).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[http::header::CONTENT_LENGTH], "11");
        assert!(response.into_body().collect().await?.to_bytes().is_empty());
        let req = Request::builder()
            .uri("/file.txt")
            .header(http::header::IF_NONE_MATCH, etag)
            .body(empty_body())?;
        let response = serve_http_request(&req, peer, "/file.txt", &dir.to_string_lossy(), &config, true).await?;
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(response.headers()[http::header::CACHE_CONTROL], "private, no-store");
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn security_static_junction_cannot_escape_root() -> Result<(), crate::DynError> {
        use clap::Parser;
        let dir = crate::e2e_test_support::unique_temp_dir("static_junction")?;
        let root = dir.join("www");
        let outside = dir.join("outside");
        std::fs::create_dir_all(&root)?;
        std::fs::create_dir_all(&outside)?;
        std::fs::write(outside.join("index.html"), "outside-secret")?;
        let link = root.join("link");
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .output()?;
        assert!(output.status.success(), "junction creation failed: {:?}", output);
        let config = Config::try_from(crate::config::Param::parse_from(["proxy"]))?;
        for path in ["/link", "/link/", "/link/index.html"] {
            let req = Request::builder().uri(path).body(empty_body())?;
            let response =
                serve_http_request(&req, "127.0.0.1:1234".parse()?, path, &root.to_string_lossy(), &config, false)
                    .await?;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        }
        std::fs::remove_dir(link)?;
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[tokio::test]
    async fn security_static_git_aliases_are_not_served() -> Result<(), crate::DynError> {
        use clap::Parser;
        let dir = crate::e2e_test_support::unique_temp_dir("static_git_aliases")?;
        std::fs::create_dir_all(dir.join(".git"))?;
        std::fs::write(dir.join(".git/config"), "git-secret")?;
        let config = Config::try_from(crate::config::Param::parse_from(["proxy"]))?;
        for path in ["/.git/config", "/./.git/config", "//.git/config"] {
            let req = Request::builder().uri("/").body(empty_body())?;
            let response =
                serve_http_request(&req, "127.0.0.1:1234".parse()?, path, &dir.to_string_lossy(), &config, false)
                    .await?;
            assert!(response.status().is_client_error(), "path {path}");
        }
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn security_windows_backslash_cannot_escape_static_root() -> Result<(), crate::DynError> {
        use clap::Parser;
        let dir = crate::e2e_test_support::unique_temp_dir("static_traversal")?;
        let root = dir.join("www");
        std::fs::create_dir_all(root.join("sub"))?;
        std::fs::write(dir.join("outside.txt"), "outside-secret")?;
        let config = Config::try_from(crate::config::Param::parse_from(["proxy"]))?;
        let req = Request::builder().uri("/").body(empty_body())?;
        let response = serve_http_request(
            &req,
            "127.0.0.1:1234".parse()?,
            "/sub\\..\\..\\outside.txt",
            &root.to_string_lossy(),
            &config,
            false,
        )
        .await?;
        std::fs::remove_dir_all(dir)?;
        assert!(response.status().is_client_error());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn security_static_symlink_cannot_escape_root() -> Result<(), crate::DynError> {
        use clap::Parser;
        let dir = crate::e2e_test_support::unique_temp_dir("static_symlink")?;
        let root = dir.join("www");
        std::fs::create_dir_all(&root)?;
        std::fs::write(dir.join("outside.txt"), "outside-secret")?;
        std::os::unix::fs::symlink(dir.join("outside.txt"), root.join("link.txt"))?;
        let config = Config::try_from(crate::config::Param::parse_from(["proxy"]))?;
        let req = Request::builder().uri("/link.txt").body(empty_body())?;
        let response =
            serve_http_request(&req, "127.0.0.1:1234".parse()?, "/link.txt", &root.to_string_lossy(), &config, false)
                .await?;
        std::fs::remove_dir_all(dir)?;
        assert!(response.status().is_client_error());
        Ok(())
    }

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

    use flate2::Compression;
    use flate2::write::GzEncoder;

    pub(crate) fn compress_string(input: &str) -> io::Result<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input.as_bytes())?;
        encoder.finish()
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
