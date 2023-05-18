#![deny(warnings)]

mod logx;

use futures_util::stream::StreamExt;

mod tls_helper;

use std::convert::Infallible;
use std::env;
use std::net::SocketAddr;


use hyper::service::{make_service_fn, service_fn};
use hyper::upgrade::Upgraded;
use hyper::{Body, Client, http, Method, Request, Response, Server};
use hyper::http::HeaderValue;

use hyper::server::conn::AddrIncoming;
use log::{debug, info, warn};
use tls_listener::TlsListener;
use std::future::ready;
use std::ops::Add;
use std::process::Command;
use rand::Rng;

use tokio::net::TcpStream;
use crate::logx::init_log;
use crate::tls_helper::tls_acceptor;

type HttpClient = Client<hyper::client::HttpConnector>;

// To try this example:
// 1. cargo run --example http_proxy
// 2. config http_proxy in command line
//    $ export http_proxy=http://127.0.0.1:8100
//    $ export https_proxy=http://127.0.0.1:8100
// 3. send requests
//    $ curl -i https://www.some_domain.com/
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let log_path = env::var("log_path").unwrap_or("proxy.log".to_string());
    init_log(&log_path);
    let port = env::var("port").unwrap_or("3128".to_string()).parse::<u16>().unwrap_or(444);
    let cert = env::var("cert").unwrap_or("cert.pem".to_string());
    let raw_key = env::var("raw_key").unwrap_or("privkey.pem".to_string());
    let basic_auth = env::var("basic_auth").unwrap_or("".to_string());
    let ask_for_auth = "true" == env::var("ask_for_auth").unwrap_or("true".to_string());
    //new
    let over_tls = "true" == env::var("over_tls").unwrap_or("false".to_string());

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let client = Client::builder()
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build_http();
    info!("rust_http_proxy is starting!");
    if over_tls {
        let make_service1 = make_service_fn(move |_| {
            let client = client.clone();
            let basic_auth = basic_auth.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    proxy(client.clone(), req, basic_auth.clone(), ask_for_auth)
                }))
            }
        });
        // This uses a filter to handle errors with connecting
        let acceptor = tls_acceptor(&raw_key, &cert);
        let incoming = TlsListener::new(acceptor, AddrIncoming::bind(&addr)?).filter(|conn| {
            match conn {
                Ok(stream) => {
                    info!("accept from {:?}",stream.get_ref().0.remote_addr());
                    ready(true)
                }
                Err(err) => {
                    warn!("Error: {:?}", err);
                    ready(false)
                }
            }
        });

        let server = Server::builder(hyper::server::accept::from_stream(incoming))
            .http1_title_case_headers(true)
            .serve(make_service1);
        info!("Listening on http{}://{}",if over_tls{"s"}else{""}, addr);
        server.await?;
        Ok(())
    } else {
        let make_service2 = make_service_fn(move |_| {
            let client = client.clone();
            let basic_auth = basic_auth.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    proxy(client.clone(), req, basic_auth.clone(), ask_for_auth)
                }))
            }
        });
        let server = Server::bind(&addr)
            .http1_preserve_header_case(true)
            .http1_title_case_headers(true)
            .serve(make_service2);
        info!("Listening on http{}://{}",if over_tls{"s"}else{""}, addr);
        server.await?;
        Ok(())
    }
}

fn count_stream() -> String {
    let output = Command::new("sh")
        .arg("-c")
        .arg("netstat -nt|tail -n +3|awk -F \"[ :]+\"  -v OFS=\"\" '$5<10000 && $5!=\"22\" && $7>1024 {printf(\"%15s   => %15s:%-5s %s\\n\",$6,$4,$5,$9)}'|sort|uniq -c|sort -rn")
        .output()
        .expect("error call netstat");
    String::from_utf8(output.stdout).unwrap().add(&*String::from_utf8(output.stderr).unwrap())
}

async fn proxy(client: HttpClient, mut req: Request<Body>, basic_auth: String, ask_for_auth: bool) -> Result<Response<Body>, hyper::Error> {
    if Method::CONNECT == req.method() {
        info!("proxy request: {:?} {:?} {:?}", req.method(),req.uri(),req.version());
    } else {
        match req.uri().host() {
            Some(_) => {
                info!("proxy request: {:?} {:?} {:?} Host: {:?} User-Agent: {:?}", req.method(),req.uri(),req.version(),req.headers().get(http::header::HOST).unwrap_or(&HeaderValue::from_str("None").unwrap()),req.headers().get(http::header::USER_AGENT).unwrap_or(&HeaderValue::from_str("None").unwrap()));
            }
            None => {
                info!("web request: {:?} {:?} {:?}", req.method(),req.uri(),req.version());
                let mut resp = Response::new(Body::from(count_stream()));
                resp.headers_mut().append(http::header::REFRESH, HeaderValue::from_static("2"));
                return Ok(resp);
            }
        }
    }

    if basic_auth.len() != 0 { //需要检验鉴权
        let auth = req.headers().get(http::header::PROXY_AUTHORIZATION);
        match auth {
            None => {
                return if ask_for_auth {
                    Ok(build_proxy_authenticate_resp())
                } else {
                    Ok(build_500_resp())
                };
            }
            Some(header) => {
                let x = header.to_str().unwrap();
                if x != basic_auth {
                    return if ask_for_auth {
                        Ok(build_proxy_authenticate_resp())
                    } else {
                        Ok(build_500_resp())
                    };
                }
            }
        }
    }

    // 删除代理
    req.headers_mut().remove(http::header::PROXY_AUTHORIZATION.to_string());
    req.headers_mut().remove("Proxy-Connection");

    if Method::CONNECT == req.method() {
        // Received an HTTP request like:
        // ```
        // CONNECT www.domain.com:443 HTTP/1.1
        // Host: www.domain.com:443
        // Proxy-Connection: Keep-Alive
        // ```
        //
        // When HTTP method is CONNECT we should return an empty body
        // then we can eventually upgrade the connection and talk a new protocol.
        //
        // Note: only after client received an empty body with STATUS_OK can the
        // connection be upgraded, so we can't return a response inside
        // `on_upgrade` future.
        if let Some(addr) = host_addr(req.uri()) {
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(upgraded, addr).await {
                            warn!("server io error: {}", e);
                        };
                    }
                    Err(e) => warn!("upgrade error: {}", e),
                }
            });
            let mut response = Response::new(Body::empty());
            // 针对connect请求中，在响应中增加随机长度的padding，防止每次建连时tcp数据长度特征过于敏感
            let count = rand::thread_rng().gen_range(1..150);
            info!("inject {} SERVER header into response",count);
            for _ in 0..count {
                response.headers_mut().append(http::header::SERVER, HeaderValue::from_static("rust_http_proxy"));
            }
            Ok(response)
        } else {
            warn!("CONNECT host is not socket addr: {:?}", req.uri());
            let mut resp = Response::new(Body::from("CONNECT must be to a socket address"));
            *resp.status_mut() = http::StatusCode::BAD_REQUEST;

            Ok(resp)
        }
    } else {
        client.request(req).await
    }
}

fn build_proxy_authenticate_resp() -> Response<Body> {
    let mut resp = Response::new(Body::from("auth need"));
    resp.headers_mut().append(http::header::PROXY_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"are you kidding me\""));
    *resp.status_mut() = http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
    resp
}

fn build_500_resp() -> Response<Body> {
    let mut resp = Response::new(Body::from("Internal Server Error"));
    *resp.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
    resp
}

fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().and_then(|auth| Some(auth.to_string()))
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(mut upgraded: Upgraded, addr: String) -> std::io::Result<()> {
    // Connect to remote server
    let mut server = TcpStream::connect(addr).await?;

    // Proxying data
    let (from_client, from_server) =
        tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;

    // Print message when done
    debug!(
        "client wrote {} bytes and received {} bytes",
        from_client, from_server
    );

    Ok(())
}