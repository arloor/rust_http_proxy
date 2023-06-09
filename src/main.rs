#![deny(warnings)]

mod logx;

use std::borrow::Cow;

mod tls_helper;
mod web_func;
mod acceptor;
mod monitor;

use std::sync::Arc;
use std::convert::Infallible;
use std::{env, io};
use std::collections::VecDeque;
use std::net::SocketAddr;
use monitor::Monitor;


use hyper::service::{make_service_fn, service_fn};
use hyper::upgrade::Upgraded;
use hyper::{Body, Client, http, Method, Request, Response, Server, Version};
use hyper::http::HeaderValue;

use hyper::server::conn::{AddrIncoming, AddrStream};
use log::{debug, error, info, warn};
use std::time::Duration;
use hyper::client::HttpConnector;
use percent_encoding::percent_decode_str;
use rand::Rng;

use tokio::net::TcpStream;
use tokio::signal::unix::{signal, SignalKind};
use crate::acceptor::TlsAcceptor;
use crate::logx::init_log;

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
    let log_dir = env::var("log_dir").unwrap_or("/tmp".to_string());
    let log_file = env::var("log_file").unwrap_or("proxy.log".to_string());
    init_log(&log_dir, &log_file);
    info!("some info about this software :\n\
    #############################################################\n\
    # Github: https://github.com/arloor/rust_http_proxy         #\n\
    # Usage: a http proxy on top of Rust                        #\n\
    # Author: arloor <admin@arloor.com>                         #\n\
    # Website: https://www.arloor.com/                          #\n\
    #############################################################\
    ");
    let port = env::var("port").unwrap_or("3128".to_string()).parse::<u16>().unwrap_or(444);
    let cert = env::var("cert").unwrap_or("cert.pem".to_string());
    let raw_key = env::var("raw_key").unwrap_or("privkey.pem".to_string());
    let basic_auth: &'static String = Box::leak(Box::new(env::var("basic_auth").unwrap_or("".to_string())));
    let web_content_path: &'static String = Box::leak(Box::new(env::var("web_content_path").unwrap_or("/usr/share/nginx/html".to_string()))); //默认为工作目录下
    let ask_for_auth = "true" == env::var("ask_for_auth").unwrap_or("true".to_string());
    let over_tls = "true" == env::var("over_tls").unwrap_or("false".to_string());

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let client: &'static Client<HttpConnector> = Box::leak(Box::new(Client::builder()
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build_http()));
    info!("rust_http_proxy is starting!");
    info!("serve web content of {}",web_content_path);
    let mut stream = signal(SignalKind::terminate())?;
    let holder: &'static Monitor = Box::leak(Box::new(Monitor::new()));
    holder.start();
    if over_tls {
        // This uses a filter to handle errors with connecting
        let incoming = AddrIncoming::bind(&addr)?;
        let acceptor = TlsAcceptor::new(raw_key, cert, incoming)?;
        let server = Server::builder(acceptor)
            .http1_title_case_headers(true)
            .http1_header_read_timeout(Duration::from_secs(30))
            .http2_keep_alive_interval(Duration::from_secs(15))
            .http2_keep_alive_timeout(Duration::from_secs(15))
            .serve(make_service_fn(move |conn: &acceptor::TlsStream| {
                let client_socket_addr = conn.remote_addr().unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));
                async move {
                    Ok::<_, Infallible>(service_fn(move |req| {
                        proxy(client, req, basic_auth, ask_for_auth, web_content_path, client_socket_addr, holder.get_buffer().clone())
                    }))
                }
            }));
        info!("Listening on https://{}:{}",local_ip().unwrap_or("0.0.0.0".to_string()), addr.port());
        let graceful = server.with_graceful_shutdown(async move {
            stream.recv().await;
            info!("graceful shutdown");
        });
        if let Err(e) = graceful.await {
            error!("server exit: {}",e);
        }
        Ok(())
    } else {
        let server = Server::bind(&addr)
            .http1_preserve_header_case(true)
            .http1_title_case_headers(true)
            .http1_header_read_timeout(Duration::from_secs(30))
            .http2_keep_alive_interval(Duration::from_secs(15))
            .http2_keep_alive_timeout(Duration::from_secs(15))
            .serve(make_service_fn(move |conn: &AddrStream| {
                let client_socket_addr = conn.remote_addr();
                async move {
                    Ok::<_, Infallible>(service_fn(move |req| {
                        proxy(client, req, basic_auth, ask_for_auth, web_content_path, client_socket_addr, holder.get_buffer().clone())
                    }))
                }
            }));
        info!("Listening on http://{}:{}",local_ip().unwrap_or("0.0.0.0".to_string()), addr.port());
        let graceful = server.with_graceful_shutdown(async move {
            stream.recv().await;
            info!("graceful shutdown");
        });
        if let Err(e) = graceful.await {
            error!("server exit: {}",e);
        }
        Ok(())
    }
}


async fn proxy(client: &HttpClient, mut req: Request<Body>, basic_auth: &String, ask_for_auth: bool, web_content_path: &String, client_socket_addr: SocketAddr, buffer: Arc<RwLock<VecDeque<u64>>>) -> Result<Response<Body>, hyper::Error> {
    if Method::CONNECT == req.method() {
        info!("{:>21?} {:^7} {:?}",client_socket_addr, req.method().as_str(),req.uri());
    } else {
        if req.version() == Version::HTTP_2 || None == req.uri().host() {
            let raw_path = req.uri().path();
            let path = percent_decode_str(raw_path).decode_utf8().unwrap_or(Cow::from(raw_path));
            let path = path.as_ref();
            info!("{:>21?} {:^7} {} {:?}", client_socket_addr,req.method().as_str(),path,req.version());
            return Ok(web_func::serve_http_request(&req, client_socket_addr, web_content_path, path, buffer).await);
        }
        if let Some(host) = req.uri().host() {
            let host = host.to_string();
            info!("{:>21?} {:^7} {:?} {:?} Host: {:?} User-Agent: {:?}",client_socket_addr, req.method().as_str(),req.uri(),req.version(),req.headers().get(http::header::HOST).unwrap_or(&HeaderValue::from_str(host.as_str()).unwrap()),req.headers().get(http::header::USER_AGENT).unwrap_or(&HeaderValue::from_str("None").unwrap()));
        };
    }

    if basic_auth.len() != 0 { //需要检验鉴权
        let mut authed: bool = false;
        match req.headers().get(http::header::PROXY_AUTHORIZATION) {
            None => warn!("no PROXY_AUTHORIZATION from {:?}",client_socket_addr),
            Some(header) => {
                match header.to_str() {
                    Err(e) => warn!("解header失败，{:?} {:?}",header,e),
                    Ok(request_auth) => {
                        if request_auth == *basic_auth {
                            authed = true;
                        } else {
                            warn!("wrong PROXY_AUTHORIZATION from {:?}, wrong:{:?},right:{:?}",client_socket_addr,request_auth,basic_auth)
                        }
                    }
                }
            }
        }
        if !authed {
            return if ask_for_auth {
                Ok(build_proxy_authenticate_resp())
            } else {
                Ok(build_500_resp())
            };
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


use std::net::UdpSocket;
use tokio::sync::RwLock;

pub fn local_ip() -> io::Result<String> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    return socket.local_addr().map(|local_addr| local_addr.ip().to_string());
}