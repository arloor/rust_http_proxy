use std::borrow::Cow;
use std::env;
use hyper::{Body, http, Method, Request, Response, StatusCode};
use hyper::http::HeaderValue;
use std::net::SocketAddr;
use std::ops::Add;
use std::path::PathBuf;
use std::process::Command;
use tokio::fs::{File, metadata};
use tokio_util::codec::{BytesCodec, FramedRead};
use mime_guess::from_path;
use httpdate::fmt_http_date;
use std::time::SystemTime;
use log::info;
use percent_encoding::percent_decode_str;


pub async fn serve_http_request(req: &Request<Body>, client_socket_addr: SocketAddr) -> Response<Body> {
    let raw_path = req.uri().path();
    let path = percent_decode_str(raw_path).decode_utf8().unwrap_or(Cow::from(raw_path));
    let path = path.as_ref();
    info!("{:>21?} {:>7?} {} {:?}", client_socket_addr,req.method(),path,req.version());

    let web_content_path: String = env::var("web_content_path").unwrap_or("/usr/share/nginx/html".to_string()); //默认为工作目录下
    let path = match (req.method(), path) {
        (&Method::GET, "/ip") => return serve_ip(client_socket_addr),
        (&Method::GET, "/nt") => return count_stream(),
        (&Method::GET, path) => {
            if String::from(path).contains("/../") {
                return not_found();
            }
            PathBuf::from(
                if String::from(path).ends_with("/") {
                    format!("{}{}index.html", web_content_path, path)
                } else {
                    format!("{}{}", web_content_path, path)
                })
        }
        _ => return not_found(),
    };
    let mime_type = from_path(&path).first_or_octet_stream();
    let metadata = match metadata(&path).await {
        Ok(metadata) => metadata,
        Err(_) => return not_found(),
    };

    let last_modified: SystemTime = match metadata.modified() {
        Ok(time) => time,
        Err(_) => return not_found(),
    };
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
        .header("Content-Type", content_type)
        .header("Last-Modified", fmt_http_date(last_modified))
        .body(body)
        .unwrap()
}

fn serve_ip(client_socket_addr: SocketAddr) -> Response<Body> {
    Response::new(Body::from(client_socket_addr.ip().to_string()))
}

fn count_stream() -> Response<Body> {
    let output = Command::new("sh")
        .arg("-c")
        .arg("netstat -nt|tail -n +3|grep -E  \"ESTABLISHED|CLOSE_WAIT\"|awk -F \"[ :]+\"  -v OFS=\"\" '$5<10000 && $5!=\"22\" && $7>1024 {printf(\"%15s   => %15s:%-5s %s\\n\",$6,$4,$5,$9)}'|sort|uniq -c|sort -rn")
        .output()
        .expect("error call netstat");
    let mut resp = Response::new(Body::from(String::from_utf8(output.stdout).unwrap().add(&*String::from_utf8(output.stderr).unwrap())));
    resp.headers_mut().append(http::header::REFRESH, HeaderValue::from_static("2"));
    return resp;
}

fn not_found() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("Not Found"))
        .unwrap()
}