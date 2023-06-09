use std::collections::VecDeque;
use hyper::{Body, http, Method, Request, Response, StatusCode};
use hyper::http::HeaderValue;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use tokio::fs::{File, metadata};
use tokio_util::codec::{BytesCodec, FramedRead};
use mime_guess::from_path;
use httpdate::fmt_http_date;
use std::time::SystemTime;
use tokio::sync::RwLock;


const SERVER_NAME: &str = "A Rust Web Server";

pub async fn serve_http_request(req: &Request<Body>, client_socket_addr: SocketAddr, web_content_path: &String, path: &str, buffer: Arc<RwLock<VecDeque<u64>>>) -> Response<Body> {
    return match (req.method(), path) {
        (_, "/ip") => serve_ip(client_socket_addr),
        (_, "/nt") => if cfg!(target_os="windows") { not_found() } else { count_stream() },
        (_, "/speed") => {
            // not_found()
            let buffer = buffer.read().await;
            let x = buffer.as_slices();
            let mut r = vec![];
            r.extend_from_slice(x.0);
            r.extend_from_slice(x.1);
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::SERVER, SERVER_NAME)
                .body(Body::from(format!("{:?}",&r)))
                .unwrap()
        }
        (&Method::GET, path) => serve_path(web_content_path, path, req).await,
        (&Method::HEAD, path) => serve_path(web_content_path, path, req).await,
        _ => not_found(),
    };
}

async fn serve_path(web_content_path: &String, url_path: &str, req: &Request<Body>) -> Response<Body> {
    if String::from(url_path).contains("/..") {
        return not_found();
    }
    let mut path = PathBuf::from(
        if String::from(url_path).ends_with("/") {
            format!("{}{}index.html", web_content_path, url_path)
        } else {
            format!("{}{}", web_content_path, url_path)
        });
    let meta = match metadata(&path).await {
        Ok(meta) => if meta.is_file() {
            meta
        } else {
            path = PathBuf::from(format!("{}{}/index.html", web_content_path, url_path));
            match metadata(&path).await {
                Ok(m) => m,
                Err(_) => return not_found(),
            }
        },
        Err(_) => return not_found(),
    };

    let last_modified: SystemTime = match meta.modified() {
        Ok(time) => time,
        Err(_) => return not_found(),
    };
    let mime_type = from_path(&path).first_or_octet_stream();
    if let Some(request_if_modified_since) = req.headers().get(http::header::IF_MODIFIED_SINCE) {
        if request_if_modified_since == HeaderValue::from_str(fmt_http_date(last_modified).as_str()).unwrap() {
            return not_modified(last_modified);
        }
    }
    let file = match File::open(path).await {
        Ok(file) => file,
        Err(_) => return not_found(),
    };

    let stream = FramedRead::new(file, BytesCodec::new());
    let body = Body::wrap_stream(stream);

    let content_type = mime_type.as_ref();
    let content_type = if !content_type.to_ascii_lowercase().contains("; charset=utf-8") {
        format!("{}{}", &content_type, "; charset=utf-8")
    } else {
        String::from(content_type)
    };
    Response::builder()
        .header(http::header::CONTENT_TYPE, content_type)
        .header(http::header::LAST_MODIFIED, fmt_http_date(last_modified))
        .header(http::header::SERVER, SERVER_NAME)
        .body(body)
        .unwrap()
}

fn serve_ip(client_socket_addr: SocketAddr) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::SERVER, SERVER_NAME)
        .body(Body::from(client_socket_addr.ip().to_string()))
        .unwrap()
}

fn count_stream() -> Response<Body> {
    let output = Command::new("sh")
        .arg("-c")
        .arg("netstat -nt|tail -n +3|grep -E  \"ESTABLISHED|CLOSE_WAIT\"|awk -F \"[ :]+\"  -v OFS=\"\" '$5<10000 && $5!=\"22\" && $7>1024 {printf(\"%15s   => %15s:%-5s %s\\n\",$6,$4,$5,$9)}'|sort|uniq -c|sort -rn")
        .output()
        .expect("error call netstat");

    Response::builder()
        .status(StatusCode::OK)
        .header(http::header::SERVER, SERVER_NAME)
        .header(http::header::REFRESH, "3")
        .body(Body::from(String::from_utf8(output.stdout).unwrap() + (&*String::from_utf8(output.stderr).unwrap())))
        .unwrap()
}

fn not_found() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(http::header::SERVER, SERVER_NAME)
        .body(Body::from("Not Found"))
        .unwrap()
}

fn not_modified(last_modified: SystemTime) -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(http::header::LAST_MODIFIED, fmt_http_date(last_modified))
        .header(http::header::SERVER, SERVER_NAME)
        .body(Body::empty())
        .unwrap()
}