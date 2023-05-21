use std::env;
use hyper::{Body, http, Method, Request, Response, StatusCode};
use hyper::http::HeaderValue;
use std::net::SocketAddr;
use std::ops::Add;
use std::path::PathBuf;
use std::process::Command;
use tokio::fs::File;
use tokio_util::codec::{BytesCodec, FramedRead};


pub async fn serve_http_request(req: &Request<Body>, client_socket_addr: SocketAddr) -> Response<Body> {
    let web_content_path: String = env::var("web_content_path").unwrap_or("/usr/share/nginx/html".to_string()); //默认为工作目录下
    let path = match (req.method(), req.uri().path()) {
        (&Method::GET, "/ip") => return serve_ip(client_socket_addr),
        (&Method::GET, "/nt") => return count_stream(),
        (&Method::GET, path) => {
            if String::from(path).contains("/../") {
                return not_found();
            }
            PathBuf::from(
                if String::from(path).ends_with("/") {
                    format!("{}/{}index.html", web_content_path, path)
                } else {
                    format!("{}/{}", web_content_path, path)
                })
        }
        _ => return not_found(),
    };
    let file = match File::open(path).await {
        Ok(file) => file,
        Err(_) => return not_found(),
    };

    let stream = FramedRead::new(file, BytesCodec::new());
    let body = Body::wrap_stream(stream);

    Response::new(body)
}

fn serve_ip(client_socket_addr: SocketAddr) -> Response<Body> {
    let mut resp = Response::new(Body::from(client_socket_addr.ip().to_string()));
    resp.headers_mut().append(http::header::REFRESH, HeaderValue::from_static("2"));
    return resp;
}

fn count_stream() -> Response<Body> {
    let output = Command::new("sh")
        .arg("-c")
        .arg("netstat -nt|tail -n +3|grep -E  \"ESTABLISHED|CLOSE_WAIT\"|awk -F \"[ :]+\"  -v OFS=\"\" '$5<10000 && $5!=\"22\" && $7>1024 {printf(\"%15s   => %15s:%-5s %s\\n\",$6,$4,$5,$9)}'|sort|uniq -c|sort -rn")
        .output()
        .expect("error call netstat");
    Response::new(Body::from(String::from_utf8(output.stdout).unwrap().add(&*String::from_utf8(output.stderr).unwrap())))
}

fn not_found() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("Not Found"))
        .unwrap()
}