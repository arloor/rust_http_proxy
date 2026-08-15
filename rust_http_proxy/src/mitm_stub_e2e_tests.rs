use std::io::{self, ErrorKind};

use http_body_util::{BodyExt as _, Empty};
use hyper::{Request, body::Bytes, client::conn::http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::DynError;
use crate::e2e_test_support::{
    WS_PAYLOAD, assert_ok, assert_switching_protocols, connect_to_mitm_target, connect_to_mitm_target_h2,
    read_exact_bytes, read_http_head, read_ws_frame_payload, start_proxy, start_tls_h2_routing_server,
    start_websocket_echo_server, timeout_step, unique_temp_dir, write_masked_text_frame, write_test_ca,
};

const STUB_SNI: &str = "localhost";
const STUB_AUTHORITY: &str = "virtual.stub.test";

#[tokio::test]
async fn detailed_dynamic_mitm_stub_uses_https_h2_connect_target_sni_and_authority() -> Result<(), DynError> {
    let upstream = start_tls_h2_routing_server(STUB_SNI, STUB_AUTHORITY).await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_dynamic_mitm_stub_h2_e2e")?;
    let ca = write_test_ca(&temp_dir)?;
    let stub_config_path = temp_dir.join("mitm-stubs.yaml");
    std::fs::write(
        &stub_config_path,
        format!(
            "localhost:{}:\n  - path: /check\n    upstream:\n      url_base: https://physical.invalid/backend\n      connect_to: 127.0.0.1:{}\n      tls_server_name: {STUB_SNI}\n      authority: {STUB_AUTHORITY}\n      version: H2\n",
            upstream.addr.port(),
            upstream.addr.port()
        ),
    )?;
    let proxy = start_proxy(vec![
        "--mitm-domain-suffix".to_owned(),
        "localhost".to_owned(),
        "--mitm-ca-cert".to_owned(),
        ca.cert_path.to_string_lossy().into_owned(),
        "--mitm-ca-key".to_owned(),
        ca.key_path.to_string_lossy().into_owned(),
        "--mitm-stub-config-file".to_owned(),
        stub_config_path.to_string_lossy().into_owned(),
    ])
    .await?;

    let mut tls_stream = connect_to_mitm_target(proxy.port, upstream.addr.port(), ca.cert_der).await?;
    tls_stream
        .write_all(
            format!("GET /check HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n", upstream.addr.port())
                .as_bytes(),
        )
        .await?;
    let response_head = read_http_head(&mut tls_stream).await?;
    assert_ok(&response_head)?;
    let body = read_exact_bytes(&mut tls_stream, 2).await?;
    assert_eq!(body, b"ok");

    proxy.shutdown().await?;
    upstream.task.await??;
    std::fs::remove_dir_all(temp_dir)?;
    Ok(())
}

#[tokio::test]
async fn detailed_dynamic_mitm_stub_auto_routes_h2_inbound_to_h2_upstream() -> Result<(), DynError> {
    let upstream = start_tls_h2_routing_server(STUB_SNI, STUB_AUTHORITY).await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_dynamic_mitm_stub_auto_h2_e2e")?;
    let ca = write_test_ca(&temp_dir)?;
    let stub_config_path = temp_dir.join("mitm-stubs.yaml");
    std::fs::write(
        &stub_config_path,
        format!(
            "localhost:{}:\n  - path: /check\n    upstream:\n      url_base: https://physical.invalid/backend\n      connect_to: 127.0.0.1:{}\n      tls_server_name: {STUB_SNI}\n      authority: {STUB_AUTHORITY}\n      version: AUTO\n",
            upstream.addr.port(),
            upstream.addr.port()
        ),
    )?;
    let proxy = start_proxy(vec![
        "--mitm-domain-suffix".to_owned(),
        "localhost".to_owned(),
        "--mitm-ca-cert".to_owned(),
        ca.cert_path.to_string_lossy().into_owned(),
        "--mitm-ca-key".to_owned(),
        ca.key_path.to_string_lossy().into_owned(),
        "--mitm-stub-config-file".to_owned(),
        stub_config_path.to_string_lossy().into_owned(),
    ])
    .await?;

    let tls_stream = connect_to_mitm_target_h2(proxy.port, upstream.addr.port(), ca.cert_der).await?;
    let (mut sender, connection) = http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(tls_stream))
        .await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("GET")
        .uri(format!("https://localhost:{}/check", upstream.addr.port()))
        .version(hyper::Version::HTTP_2)
        .body(Empty::<Bytes>::new())?;
    let response = sender.send_request(request).await?;
    assert_eq!(response.status(), hyper::StatusCode::OK);
    assert_eq!(response.into_body().collect().await?.to_bytes(), Bytes::from_static(b"ok"));

    proxy.shutdown().await?;
    upstream.task.await??;
    std::fs::remove_dir_all(temp_dir)?;
    Ok(())
}

#[tokio::test]
async fn dynamic_mitm_stub_receives_plaintext_request_and_returns_response_over_tls() -> Result<(), DynError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let dynamic_stub_addr = listener.local_addr()?;
    let dynamic_stub_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let request_head = read_http_head(&mut stream).await?;
        if !request_head.starts_with("POST /stub/users/current?verbose=1 HTTP/1.1\r\n") {
            return Err(io::Error::new(ErrorKind::InvalidData, request_head).into());
        }
        let lower_head = request_head.to_ascii_lowercase();
        if !lower_head.contains(&format!("\r\nhost: localhost:{}\r\n", dynamic_stub_addr.port()))
            || !lower_head.contains("\r\nx-dynamic-input: yes\r\n")
        {
            return Err(io::Error::new(ErrorKind::InvalidData, request_head).into());
        }
        let body = read_exact_bytes(&mut stream, 5).await?;
        if body != b"hello" {
            return Err(io::Error::new(ErrorKind::InvalidData, "dynamic stub received an unexpected body").into());
        }
        stream
            .write_all(
                b"HTTP/1.1 202 Accepted\r\n\
Content-Length: 7\r\n\
Content-Type: text/plain\r\n\
X-Stub-Mode: dynamic\r\n\
Connection: close\r\n\
\r\n\
dynamic",
            )
            .await?;
        Ok::<_, DynError>(())
    });

    let temp_dir = unique_temp_dir("rust_http_proxy_dynamic_mitm_stub_e2e")?;
    let ca = write_test_ca(&temp_dir)?;
    let stub_config_path = temp_dir.join("mitm-stubs.yaml");
    std::fs::write(
        &stub_config_path,
        format!(
            "localhost:{}:\n  - path: /users/current\n    upstream: http://127.0.0.1:{}/stub\n",
            dynamic_stub_addr.port(),
            dynamic_stub_addr.port()
        ),
    )?;
    let proxy = start_proxy(vec![
        "--mitm-domain-suffix".to_owned(),
        "localhost".to_owned(),
        "--mitm-ca-cert".to_owned(),
        ca.cert_path.to_string_lossy().into_owned(),
        "--mitm-ca-key".to_owned(),
        ca.key_path.to_string_lossy().into_owned(),
        "--mitm-stub-config-file".to_owned(),
        stub_config_path.to_string_lossy().into_owned(),
    ])
    .await?;

    let mut tls_stream = connect_to_mitm_target(proxy.port, dynamic_stub_addr.port(), ca.cert_der).await?;
    tls_stream
        .write_all(
            format!(
                "POST /users/current?verbose=1 HTTP/1.1\r\n\
Host: localhost:{}\r\n\
X-Dynamic-Input: yes\r\n\
Content-Length: 5\r\n\
Connection: close\r\n\
\r\n\
hello",
                dynamic_stub_addr.port()
            )
            .as_bytes(),
        )
        .await?;
    let response_head = timeout_step("dynamic MITM stub response", read_http_head(&mut tls_stream)).await?;
    assert!(response_head.starts_with("HTTP/1.1 202 "));
    assert!(
        response_head
            .to_ascii_lowercase()
            .contains("\r\nx-stub-mode: dynamic\r\n")
    );
    let body = timeout_step("dynamic MITM stub response body", read_exact_bytes(&mut tls_stream, 7)).await?;
    assert_eq!(body, b"dynamic");

    drop(tls_stream);
    dynamic_stub_task.await??;
    proxy.shutdown().await?;
    std::fs::remove_dir_all(temp_dir)?;
    Ok(())
}

#[tokio::test]
async fn dynamic_mitm_stub_streams_sse_events_without_buffering() -> Result<(), DynError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let dynamic_stub_addr = listener.local_addr()?;
    let (continue_tx, continue_rx) = oneshot::channel();
    let dynamic_stub_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let request_head = read_http_head(&mut stream).await?;
        if !request_head.starts_with("GET /events HTTP/1.1\r\n") {
            return Err(io::Error::new(ErrorKind::InvalidData, request_head).into());
        }
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
Content-Type: text/event-stream\r\n\
Cache-Control: no-cache\r\n\
Transfer-Encoding: chunked\r\n\
\r\n\
b\r\ndata: one\n\n\r\n",
            )
            .await?;
        continue_rx
            .await
            .map_err(|_| io::Error::new(ErrorKind::BrokenPipe, "SSE client stopped early"))?;
        stream.write_all(b"b\r\ndata: two\n\n\r\n0\r\n\r\n").await?;
        Ok::<_, DynError>(())
    });

    let temp_dir = unique_temp_dir("rust_http_proxy_dynamic_mitm_stub_sse_e2e")?;
    let ca = write_test_ca(&temp_dir)?;
    let stub_config_path = temp_dir.join("mitm-stubs.yaml");
    std::fs::write(
        &stub_config_path,
        format!(
            "localhost:{}:\n  - path: /events\n    upstream: http://127.0.0.1:{}\n",
            dynamic_stub_addr.port(),
            dynamic_stub_addr.port()
        ),
    )?;
    let proxy = start_proxy(vec![
        "--mitm-domain-suffix".to_owned(),
        "localhost".to_owned(),
        "--mitm-ca-cert".to_owned(),
        ca.cert_path.to_string_lossy().into_owned(),
        "--mitm-ca-key".to_owned(),
        ca.key_path.to_string_lossy().into_owned(),
        "--mitm-stub-config-file".to_owned(),
        stub_config_path.to_string_lossy().into_owned(),
    ])
    .await?;

    let mut tls_stream = connect_to_mitm_target(proxy.port, dynamic_stub_addr.port(), ca.cert_der).await?;
    tls_stream
        .write_all(
            format!(
                "GET /events HTTP/1.1\r\nHost: localhost:{}\r\nAccept: text/event-stream\r\n\r\n",
                dynamic_stub_addr.port()
            )
            .as_bytes(),
        )
        .await?;
    let response_head = timeout_step("dynamic MITM SSE response", read_http_head(&mut tls_stream)).await?;
    assert!(response_head.starts_with("HTTP/1.1 200 "));
    assert!(
        response_head
            .to_ascii_lowercase()
            .contains("content-type: text/event-stream")
    );
    let first_event = timeout_step("first dynamic MITM SSE event", read_http_chunk(&mut tls_stream)).await?;
    assert_eq!(first_event, b"data: one\n\n");
    let _ = continue_tx.send(());
    let second_event = timeout_step("second dynamic MITM SSE event", read_http_chunk(&mut tls_stream)).await?;
    assert_eq!(second_event, b"data: two\n\n");

    drop(tls_stream);
    dynamic_stub_task.await??;
    proxy.shutdown().await?;
    std::fs::remove_dir_all(temp_dir)?;
    Ok(())
}

#[tokio::test]
async fn dynamic_mitm_stub_tunnels_websocket_upgrade() -> Result<(), DynError> {
    let upstream = start_websocket_echo_server().await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_dynamic_mitm_stub_websocket_e2e")?;
    let ca = write_test_ca(&temp_dir)?;
    let stub_config_path = temp_dir.join("mitm-stubs.yaml");
    std::fs::write(
        &stub_config_path,
        format!(
            "localhost:{}:\n  - path: /ws\n    upstream: http://127.0.0.1:{}\n",
            upstream.addr.port(),
            upstream.addr.port()
        ),
    )?;
    let proxy = start_proxy(vec![
        "--mitm-domain-suffix".to_owned(),
        "localhost".to_owned(),
        "--mitm-ca-cert".to_owned(),
        ca.cert_path.to_string_lossy().into_owned(),
        "--mitm-ca-key".to_owned(),
        ca.key_path.to_string_lossy().into_owned(),
        "--mitm-stub-config-file".to_owned(),
        stub_config_path.to_string_lossy().into_owned(),
    ])
    .await?;

    let mut tls_stream = connect_to_mitm_target(proxy.port, upstream.addr.port(), ca.cert_der).await?;
    tls_stream
        .write_all(
            format!(
                "GET /ws HTTP/1.1\r\n\
Host: localhost:{}\r\n\
Connection: Upgrade\r\n\
Upgrade: websocket\r\n\
Sec-WebSocket-Version: 13\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
\r\n",
                upstream.addr.port()
            )
            .as_bytes(),
        )
        .await?;
    let response_head = timeout_step("dynamic MITM WebSocket response", read_http_head(&mut tls_stream)).await?;
    assert_switching_protocols(&response_head)?;
    write_masked_text_frame(&mut tls_stream, WS_PAYLOAD).await?;
    let echoed = timeout_step("dynamic MITM WebSocket echo", read_ws_frame_payload(&mut tls_stream)).await?;
    assert_eq!(echoed, WS_PAYLOAD);

    upstream.task.await??;
    proxy.shutdown().await?;
    std::fs::remove_dir_all(temp_dir)?;
    Ok(())
}

async fn read_http_chunk<T>(stream: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin,
{
    let mut size_line = Vec::new();
    let mut byte = [0u8; 1];
    while !size_line.ends_with(b"\r\n") {
        stream.read_exact(&mut byte).await?;
        size_line.push(byte[0]);
        if size_line.len() > 32 {
            return Err(io::Error::new(ErrorKind::InvalidData, "HTTP chunk size is too large"));
        }
    }
    let size_text = std::str::from_utf8(&size_line[..size_line.len() - 2])
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    let size = usize::from_str_radix(size_text, 16).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    let mut chunk = vec![0; size];
    stream.read_exact(&mut chunk).await?;
    let mut terminator = [0; 2];
    stream.read_exact(&mut terminator).await?;
    if terminator != *b"\r\n" {
        return Err(io::Error::new(ErrorKind::InvalidData, "invalid HTTP chunk terminator"));
    }
    Ok(chunk)
}
