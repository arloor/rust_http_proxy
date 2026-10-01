//! 重构前锁定的转发路径行为：每条路径的 proxy_traffic 标签与字节数、正向代理改写的请求头、
//! 旁路父代理不可用时的错误回包。字节数断言能发现 CounterIO 被漏包或重复包装。

use std::io::{self, ErrorKind};
use std::net::SocketAddr;

use base64::Engine as _;
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::DynError;
use crate::e2e_test_support::{
    SSH_BANNER, WS_PAYLOAD, assert_ok, closed_local_port, connect_to_mitm_target, header_value, read_exact_bytes,
    read_http_head, read_response, recv_channel, recv_connect_target, remove_temp_dir, start_forward_bypass_proxy,
    start_proxy, start_tcp_banner_server, start_tcp_echo_server, start_tls_http_server, timeout_step, unique_temp_dir,
    wait_for_proxy_traffic, write_test_ca,
};

const ALICE: &str = "alice:secret";
const PARENT_USER: &str = "proxyuser";
const PARENT_PASSWORD: &str = "proxypass";
const ORIGIN_BODY: &[u8] = b"origin-ok";
const ORIGIN_RESPONSE: &[u8] = b"\
HTTP/1.1 200 OK\r\n\
Content-Length: 9\r\n\
Connection: close\r\n\
\r\n\
origin-ok";
const PARENT_CONNECT_OK: &str = "HTTP/1.1 200 Connection Established\r\n\r\n";

struct CapturingServer {
    addr: SocketAddr,
    head_rx: tokio::sync::mpsc::Receiver<String>,
    task: JoinHandle<Result<(), DynError>>,
}

/// 只接受一个连接：记录请求头后回固定响应并关闭。
async fn start_capturing_server(response: &'static [u8]) -> Result<CapturingServer, DynError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let (head_tx, head_rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let head = read_http_head(&mut stream).await?;
        head_tx
            .send(head)
            .await
            .map_err(|_| io::Error::new(ErrorKind::BrokenPipe, "captured head receiver dropped"))?;
        stream.write_all(response).await?;
        Ok(())
    });
    Ok(CapturingServer { addr, head_rx, task })
}

/// 握手后立即回非 TLS 数据并关闭，用于模拟 https 父代理握手失败。
async fn start_non_tls_server() -> Result<CapturingServer, DynError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let (_head_tx, head_rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        stream.write_all(b"this is not tls\r\n\r\n").await?;
        Ok(())
    });
    Ok(CapturingServer { addr, head_rx, task })
}

fn basic_token(user_password: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(user_password.as_bytes())
}

fn mitm_args(ca_cert: &std::path::Path, ca_key: &std::path::Path, extra: Vec<String>) -> Vec<String> {
    let mut args = vec![
        "--mitm-domain-suffix".to_owned(),
        "localhost".to_owned(),
        "--mitm-ca-cert".to_owned(),
        ca_cert.to_string_lossy().into_owned(),
        "--mitm-ca-key".to_owned(),
        ca_key.to_string_lossy().into_owned(),
    ];
    args.extend(extra);
    args
}

async fn send_raw(proxy_port: u16, request: &str) -> Result<(String, Vec<u8>), DynError> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
    stream.write_all(request.as_bytes()).await?;
    timeout_step("proxy response", read_response(&mut stream))
        .await
        .map_err(Into::into)
}

#[tokio::test]
async fn forward_direct_http_rewrites_request_and_counts_traffic() -> Result<(), DynError> {
    let mut origin = start_capturing_server(ORIGIN_RESPONSE).await?;
    let proxy = start_proxy(vec!["--users".to_owned(), ALICE.to_owned()]).await?;
    let target = format!("127.0.0.1:{}", origin.addr.port());

    let (head, body) = send_raw(
        proxy.port,
        &format!(
            "\
GET http://{target}/item?x=1 HTTP/1.1\r\n\
Host: {target}\r\n\
Proxy-Authorization: Basic {}\r\n\
Proxy-Connection: keep-alive\r\n\
Connection: close\r\n\
\r\n",
            basic_token(ALICE)
        ),
    )
    .await?;
    assert_ok(&head)?;
    assert_eq!(body, ORIGIN_BODY);

    let upstream_head = recv_channel("origin head", &mut origin.head_rx).await?;
    assert!(upstream_head.starts_with("GET /item?x=1 HTTP/1.1\r\n"), "origin-form expected: {upstream_head}");
    assert_eq!(header_value(&upstream_head, "host"), Some(target.as_str()));
    assert!(header_value(&upstream_head, "proxy-authorization").is_none(), "{upstream_head}");
    assert!(header_value(&upstream_head, "proxy-connection").is_none(), "{upstream_head}");

    let expected = (upstream_head.len() + ORIGIN_RESPONSE.len()) as u64;
    assert_eq!(wait_for_proxy_traffic(&target, "alice", None, expected).await, expected);

    origin.task.await??;
    proxy.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn forward_proxy_challenges_missing_proxy_auth() -> Result<(), DynError> {
    let proxy = start_proxy(vec!["--users".to_owned(), ALICE.to_owned()]).await?;
    let closed = closed_local_port()?;
    let port = closed.port;

    let (head, body) = send_raw(
        proxy.port,
        &format!("GET http://127.0.0.1:{port}/item HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"),
    )
    .await?;
    assert!(head.starts_with("HTTP/1.1 407 "), "{head}");
    assert_eq!(header_value(&head, "proxy-authenticate"), Some("Basic realm=\"are you kidding me\""));
    assert_eq!(body, b"auth need");

    proxy.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn forward_bypass_http_rewrites_parent_headers_and_counts_traffic() -> Result<(), DynError> {
    let mut parent = start_capturing_server(ORIGIN_RESPONSE).await?;
    let parent_target = format!("127.0.0.1:{}", parent.addr.port());
    let proxy = start_proxy(vec![
        "--users".to_owned(),
        ALICE.to_owned(),
        "--forward-bypass-url".to_owned(),
        format!("http://{PARENT_USER}:{PARENT_PASSWORD}@{parent_target}"),
    ])
    .await?;

    let (head, body) = send_raw(
        proxy.port,
        &format!(
            "\
GET http://origin.invalid:8080/item?x=1 HTTP/1.1\r\n\
Host: origin.invalid:8080\r\n\
Proxy-Authorization: Basic {}\r\n\
Connection: close\r\n\
\r\n",
            basic_token(ALICE)
        ),
    )
    .await?;
    assert_ok(&head)?;
    assert_eq!(body, ORIGIN_BODY);

    let parent_head = recv_channel("parent head", &mut parent.head_rx).await?;
    assert!(
        parent_head.starts_with("GET http://origin.invalid:8080/item?x=1 HTTP/1.1\r\n"),
        "parent proxy must receive absolute-form: {parent_head}"
    );
    assert_eq!(header_value(&parent_head, "host"), Some(parent_target.as_str()));
    let parent_auth = format!("Basic {}", basic_token(&format!("{PARENT_USER}:{PARENT_PASSWORD}")));
    assert_eq!(header_value(&parent_head, "proxy-authorization"), Some(parent_auth.as_str()));

    let expected = (parent_head.len() + ORIGIN_RESPONSE.len()) as u64;
    assert_eq!(wait_for_proxy_traffic(&parent_target, "alice", Some(false), expected).await, expected);

    parent.task.await??;
    proxy.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn forward_direct_http_to_unreachable_origin_is_server_error() -> Result<(), DynError> {
    let proxy = start_proxy(Vec::new()).await?;
    let closed = closed_local_port()?;
    let target = format!("127.0.0.1:{}", closed.port);

    let (head, _) = send_raw(
        proxy.port,
        &format!("GET http://{target}/item HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"),
    )
    .await?;
    assert!(head.starts_with("HTTP/1.1 500 "), "{head}");

    proxy.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn forward_bypass_http_to_unreachable_parent_is_server_error() -> Result<(), DynError> {
    let closed = closed_local_port()?;
    let proxy = start_proxy(vec![
        "--forward-bypass-url".to_owned(),
        format!("http://127.0.0.1:{}", closed.port),
    ])
    .await?;

    let (head, _) = send_raw(
        proxy.port,
        "GET http://origin.invalid/item HTTP/1.1\r\nHost: origin.invalid\r\nConnection: close\r\n\r\n",
    )
    .await?;
    assert!(head.starts_with("HTTP/1.1 500 "), "{head}");

    proxy.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn direct_connect_tunnel_counts_payload_bytes() -> Result<(), DynError> {
    let upstream = start_tcp_echo_server().await?;
    let proxy = start_proxy(Vec::new()).await?;
    let target = format!("127.0.0.1:{}", upstream.addr.port());

    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await?;
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await?;
    assert_ok(&timeout_step("direct CONNECT response", read_http_head(&mut stream)).await?)?;
    stream.write_all(WS_PAYLOAD).await?;
    let echoed = timeout_step("direct CONNECT echo", read_exact_bytes(&mut stream, WS_PAYLOAD.len())).await?;
    assert_eq!(echoed, WS_PAYLOAD);

    let expected = (WS_PAYLOAD.len() * 2) as u64;
    assert_eq!(wait_for_proxy_traffic(&target, "unknown", None, expected).await, expected);

    drop(stream);
    upstream.task.await??;
    proxy.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn bypass_connect_tunnel_counts_handshake_and_payload_bytes() -> Result<(), DynError> {
    let upstream = start_tcp_echo_server().await?;
    let mut parent = start_forward_bypass_proxy().await?;
    let parent_target = format!("127.0.0.1:{}", parent.addr.port());
    let proxy = start_proxy(vec!["--forward-bypass-url".to_owned(), format!("http://{parent_target}")]).await?;
    let target = format!("127.0.0.1:{}", upstream.addr.port());

    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await?;
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await?;
    assert_ok(&timeout_step("bypass CONNECT response", read_http_head(&mut stream)).await?)?;
    stream.write_all(WS_PAYLOAD).await?;
    let echoed = timeout_step("bypass CONNECT echo", read_exact_bytes(&mut stream, WS_PAYLOAD.len())).await?;
    assert_eq!(echoed, WS_PAYLOAD);
    assert_eq!(recv_connect_target(&mut parent).await?, target);

    let parent_request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n");
    let expected = (parent_request.len() + PARENT_CONNECT_OK.len() + WS_PAYLOAD.len() * 2) as u64;
    assert_eq!(wait_for_proxy_traffic(&parent_target, "unknown", Some(false), expected).await, expected);

    drop(stream);
    upstream.task.await??;
    parent.task.await??;
    proxy.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn bypass_connect_to_unreachable_parent_is_bad_gateway() -> Result<(), DynError> {
    let closed = closed_local_port()?;
    let proxy = start_proxy(vec![
        "--forward-bypass-url".to_owned(),
        format!("http://127.0.0.1:{}", closed.port),
    ])
    .await?;

    let (head, body) = send_raw(proxy.port, "CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n").await?;
    assert!(head.starts_with("HTTP/1.1 502 "), "{head}");
    assert_eq!(body, b"Failed to connect to bypass server");

    proxy.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn bypass_connect_tls_failure_is_bad_gateway() -> Result<(), DynError> {
    let parent = start_non_tls_server().await?;
    let proxy = start_proxy(vec![
        "--forward-bypass-url".to_owned(),
        format!("https://127.0.0.1:{}", parent.addr.port()),
    ])
    .await?;

    let (head, body) = send_raw(proxy.port, "CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n").await?;
    assert!(head.starts_with("HTTP/1.1 502 "), "{head}");
    assert_eq!(body, b"Failed to establish TLS connection to bypass server");

    parent.task.await??;
    proxy.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn mitm_https_counts_upstream_traffic_under_mitm_target() -> Result<(), DynError> {
    let upstream = start_tls_http_server().await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_traffic_mitm_direct")?;
    let ca = write_test_ca(&temp_dir)?;
    let proxy = start_proxy(mitm_args(&ca.cert_path, &ca.key_path, Vec::new())).await?;
    let target = format!("localhost:{}", upstream.addr.port());

    let mut tls_stream = connect_to_mitm_target(proxy.port, upstream.addr.port(), ca.cert_der).await?;
    tls_stream
        .write_all(format!("GET /plain HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n").as_bytes())
        .await?;
    let (head, body) = timeout_step("MITM response", read_response(&mut tls_stream)).await?;
    assert_ok(&head)?;
    assert_eq!(body, b"hello-via-bypass");
    assert!(wait_for_proxy_traffic(&target, "unknown", Some(true), 1).await > 0);

    drop(tls_stream);
    upstream.task.await??;
    proxy.shutdown().await?;
    remove_temp_dir(temp_dir)?;
    Ok(())
}

#[tokio::test]
async fn mitm_https_via_bypass_counts_traffic_under_mitm_target() -> Result<(), DynError> {
    let upstream = start_tls_http_server().await?;
    let mut parent = start_forward_bypass_proxy().await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_traffic_mitm_bypass")?;
    let ca = write_test_ca(&temp_dir)?;
    let proxy = start_proxy(mitm_args(
        &ca.cert_path,
        &ca.key_path,
        vec![
            "--forward-bypass-url".to_owned(),
            format!("http://127.0.0.1:{}", parent.addr.port()),
        ],
    ))
    .await?;
    let target = format!("localhost:{}", upstream.addr.port());

    let mut tls_stream = connect_to_mitm_target(proxy.port, upstream.addr.port(), ca.cert_der).await?;
    tls_stream
        .write_all(format!("GET /plain HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n").as_bytes())
        .await?;
    let (head, body) = timeout_step("MITM bypass response", read_response(&mut tls_stream)).await?;
    assert_ok(&head)?;
    assert_eq!(body, b"hello-via-bypass");
    assert_eq!(recv_connect_target(&mut parent).await?, target);
    assert!(wait_for_proxy_traffic(&target, "unknown", Some(true), 1).await > 0);

    drop(tls_stream);
    upstream.task.await??;
    parent.task.await??;
    proxy.shutdown().await?;
    remove_temp_dir(temp_dir)?;
    Ok(())
}

#[tokio::test]
async fn mitm_non_http_direct_fallback_counts_tunnel_bytes() -> Result<(), DynError> {
    let upstream = start_tcp_banner_server().await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_traffic_mitm_raw_direct")?;
    let ca = write_test_ca(&temp_dir)?;
    let proxy = start_proxy(mitm_args(&ca.cert_path, &ca.key_path, Vec::new())).await?;
    let target = format!("localhost:{}", upstream.addr.port());

    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await?;
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await?;
    assert_ok(&timeout_step("MITM raw CONNECT response", read_http_head(&mut stream)).await?)?;
    let banner = timeout_step("MITM raw banner", read_exact_bytes(&mut stream, SSH_BANNER.len())).await?;
    assert_eq!(banner, SSH_BANNER);

    let expected = SSH_BANNER.len() as u64;
    assert_eq!(wait_for_proxy_traffic(&target, "unknown", None, expected).await, expected);

    drop(stream);
    upstream.task.await??;
    proxy.shutdown().await?;
    remove_temp_dir(temp_dir)?;
    Ok(())
}

#[tokio::test]
async fn mitm_non_http_bypass_fallback_counts_only_tunnel_bytes() -> Result<(), DynError> {
    let upstream = start_tcp_banner_server().await?;
    let mut parent = start_forward_bypass_proxy().await?;
    let parent_target = format!("127.0.0.1:{}", parent.addr.port());
    let temp_dir = unique_temp_dir("rust_http_proxy_traffic_mitm_raw_bypass")?;
    let ca = write_test_ca(&temp_dir)?;
    let proxy = start_proxy(mitm_args(
        &ca.cert_path,
        &ca.key_path,
        vec!["--forward-bypass-url".to_owned(), format!("http://{parent_target}")],
    ))
    .await?;
    let target = format!("localhost:{}", upstream.addr.port());

    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await?;
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await?;
    assert_ok(&timeout_step("MITM raw bypass CONNECT response", read_http_head(&mut stream)).await?)?;
    let banner = timeout_step("MITM raw bypass banner", read_exact_bytes(&mut stream, SSH_BANNER.len())).await?;
    assert_eq!(banner, SSH_BANNER);
    assert_eq!(recv_connect_target(&mut parent).await?, target);

    let expected = SSH_BANNER.len() as u64;
    assert_eq!(wait_for_proxy_traffic(&parent_target, "unknown", Some(false), expected).await, expected);

    drop(stream);
    upstream.task.await??;
    parent.task.await??;
    proxy.shutdown().await?;
    remove_temp_dir(temp_dir)?;
    Ok(())
}

#[tokio::test]
async fn reverse_proxy_counts_body_bytes_under_upstream_label() -> Result<(), DynError> {
    let mut origin = start_capturing_server(ORIGIN_RESPONSE).await?;
    let url_base = format!("http://127.0.0.1:{}/", origin.addr.port());
    let temp_dir = unique_temp_dir("rust_http_proxy_traffic_reverse")?;
    std::fs::create_dir_all(&temp_dir)?;
    let config_path = temp_dir.join("locations.yaml");
    std::fs::write(
        &config_path,
        format!("default_host:\n  - location: /api/\n    upstream:\n      url_base: {url_base}\n      version: H1\n"),
    )?;
    let proxy = start_proxy(vec![
        "--location-config-file".to_owned(),
        config_path.to_string_lossy().into_owned(),
    ])
    .await?;

    let (head, body) =
        send_raw(proxy.port, "GET /api/item?x=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await?;
    assert_ok(&head)?;
    assert_eq!(body, ORIGIN_BODY);
    let upstream_head = recv_channel("reverse origin head", &mut origin.head_rx).await?;
    assert!(upstream_head.starts_with("GET /item?x=1 HTTP/1.1\r\n"), "{upstream_head}");

    let expected = ORIGIN_BODY.len() as u64;
    assert_eq!(wait_for_proxy_traffic(&url_base, "reverse_proxy", None, expected).await, expected);

    origin.task.await??;
    proxy.shutdown().await?;
    remove_temp_dir(temp_dir)?;
    Ok(())
}
