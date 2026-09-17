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

#[tokio::test]
async fn ui_stub_api_applies_headers_body_and_captures_historical_source() -> Result<(), DynError> {
    let temp_dir = unique_temp_dir("ui_stub_e2e")?;
    let ca = write_test_ca(&temp_dir)?;
    let proxy = start_proxy(vec![
        "--mitm-users".into(),
        "admin:test".into(),
        "--mitm-domain-suffix".into(),
        "localhost".into(),
        "--mitm-dump".into(),
        "--mitm-ca-cert".into(),
        ca.cert_path.to_string_lossy().into_owned(),
        "--mitm-ca-key".into(),
        ca.key_path.to_string_lossy().into_owned(),
    ])
    .await?;
    let body = serde_json::json!({
        "authority":"localhost:443", "path":"/ui", "enabled":true, "mode":"response", "status":202,
        "body":"直接填写 body", "request_headers":[
            {"op":"set", "name":"x-request", "value":"replaced"},
            {"op":"remove", "name":"x-remove"}
        ], "response_headers":[
            {"op":"add", "name":"x-response", "value":"one"},
            {"op":"add", "name":"X-Response", "value":"two"},
            {"op":"set", "name":"content-type", "value":"text/plain; charset=utf-8"}
        ]
    })
    .to_string();
    let mut management = tokio::net::TcpStream::connect(("127.0.0.1", proxy.port)).await?;
    management.write_all(format!("POST /mitm/api/stubs HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWRtaW46dGVzdA==\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await?;
    let mut saved = String::new();
    management.read_to_string(&mut saved).await?;
    assert!(saved.starts_with("HTTP/1.1 200"), "{saved}");
    for method in ["GET", "HEAD"] {
        let mut tls = connect_to_mitm_target(proxy.port, 443, ca.cert_der.clone()).await?;
        tls.write_all(format!("{method} /ui?ignored=1 HTTP/1.1\r\nHost: localhost:443\r\nX-Request: original\r\nX-Remove: original\r\nConnection: close\r\n\r\n").as_bytes()).await?;
        let head = timeout_step("UI stub response", read_http_head(&mut tls)).await?;
        assert!(head.starts_with("HTTP/1.1 202"), "{head}");
        assert_eq!(head.to_ascii_lowercase().matches("\r\nx-response:").count(), 2, "{head}");
        if method == "GET" {
            let actual = read_exact_bytes(&mut tls, "直接填写 body".len()).await?;
            assert_eq!(actual, "直接填写 body".as_bytes());
        } else {
            let mut actual = Vec::new();
            timeout_step("HEAD ends without payload", tls.read_to_end(&mut actual)).await?;
            assert!(actual.is_empty());
        }
    }
    let (_, saved_body) = saved.split_once("\r\n\r\n").ok_or("missing saved rule")?;
    let saved_rule: serde_json::Value = serde_json::from_str(saved_body)?;
    let id = saved_rule["id"].as_str().ok_or("missing rule id")?;
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", proxy.port)).await?;
    stream.write_all(format!("DELETE /mitm/api/stubs/{id} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWRtaW46dGVzdA==\r\nConnection: close\r\n\r\n").as_bytes()).await?;
    let mut deleted = String::new();
    stream.read_to_string(&mut deleted).await?;
    assert!(deleted.starts_with("HTTP/1.1 204"), "{deleted}");
    // Query through the HTTP API after the writer has flushed, checking persisted provenance and effective headers.
    let mut found = false;
    for _ in 0..30 {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", proxy.port)).await?;
        stream
            .write_all(b"GET /mitm/api/records HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWRtaW46dGVzdA==\r\nConnection: close\r\n\r\n")
            .await?;
        let mut response = String::new();
        stream.read_to_string(&mut response).await?;
        if let Some((_, body)) = response.split_once("\r\n\r\n") {
            let page: serde_json::Value = serde_json::from_str(body)?;
            if let Some(record) = page["records"].as_array().and_then(|records| {
                records
                    .iter()
                    .find(|r| r["method"] == "GET" && r["capture_state"] == "complete")
            }) {
                let id = record["id"].as_str().ok_or("missing id")?;
                let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", proxy.port)).await?;
                stream
                    .write_all(
                        format!("GET /mitm/api/records/{id} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWRtaW46dGVzdA==\r\nConnection: close\r\n\r\n")
                            .as_bytes(),
                    )
                    .await?;
                let mut response = String::new();
                stream.read_to_string(&mut response).await?;
                let (_, body) = response.split_once("\r\n\r\n").ok_or("missing body")?;
                let detail: serde_json::Value = serde_json::from_str(body)?;
                assert_eq!(detail["stub"]["source"], "ui");
                assert_eq!(detail["response_body"], "直接填写 body");
                let headers = detail["request_headers"].as_array().ok_or("missing headers")?;
                assert!(headers.iter().any(|h| h[0] == "x-request" && h[1] == "replaced"));
                assert!(!headers.iter().any(|h| h[0] == "x-remove"));
                found = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(found, "completed capture not found");
    proxy.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn ui_headers_apply_to_dynamic_and_original_upstreams() -> Result<(), DynError> {
    use std::sync::Arc;
    use tokio_rustls::rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    let temp_dir = unique_temp_dir("ui_upstream_headers")?;
    let ca = write_test_ca(&temp_dir)?;
    let key = rcgen::KeyPair::generate()?;
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])?.self_signed(&key)?;
    let tls_config = ServerConfig::builder().with_no_client_auth().with_single_cert(
        vec![CertificateDer::from(cert.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let proxy = start_proxy(vec![
        "--mitm-users".into(),
        "admin:test".into(),
        "--mitm-domain-suffix".into(),
        "localhost".into(),
        "--mitm-ca-cert".into(),
        ca.cert_path.to_string_lossy().into_owned(),
        "--mitm-ca-key".into(),
        ca.key_path.to_string_lossy().into_owned(),
    ])
    .await?;
    for mode in ["upstream", "headers", "mod_header"] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();
        let acceptor = acceptor.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut stream: Box<dyn UiTestStream> = if mode != "upstream" {
                Box::new(acceptor.accept(stream).await?)
            } else {
                Box::new(stream)
            };
            let head = read_http_head(&mut stream).await?.to_ascii_lowercase();
            assert!(head.contains("\r\nx-set: replaced\r\n"), "{head}");
            assert!(!head.contains("x-remove"), "{head}");
            assert_eq!(head.matches("\r\nx-add:").count(), 2, "{head}");
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-Set: old\r\nX-Remove: old\r\nX-Add: original\r\nConnection: close\r\n\r\nbody").await?;
            stream.shutdown().await?;
            Ok::<_, DynError>(())
        });
        let edits = serde_json::json!([
            {"op":"add", "name":"x-add", "value":"extra"},
            {"op":"set", "name":"x-set", "value":"replaced"},
            {"op":"remove", "name":"x-remove"},
            {"enabled":false, "op":"set", "name":"x-set", "value":"disabled"}
        ]);
        let rule = serde_json::json!({"authority":format!("localhost:{port}"), "path":"/headers", "enabled":true, "mode":mode, "url_pattern":format!(r"^https://localhost:{port}/headers\?match=1$"), "upstream":format!("http://127.0.0.1:{port}"), "request_headers":edits, "response_headers":edits}).to_string();
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", proxy.port)).await?;
        stream.write_all(format!("POST /mitm/api/stubs HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWRtaW46dGVzdA==\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{rule}", rule.len()).as_bytes()).await?;
        let mut saved = String::new();
        stream.read_to_string(&mut saved).await?;
        assert!(saved.starts_with("HTTP/1.1 200"), "{saved}");
        let mut tls = connect_to_mitm_target(proxy.port, port, ca.cert_der.clone()).await?;
        tls.write_all(format!("GET /headers?match=1 HTTP/1.1\r\nHost: localhost:{port}\r\nX-Add: original\r\nX-Set: old\r\nX-Remove: old\r\nConnection: close\r\n\r\n").as_bytes()).await?;
        let head = timeout_step("header rule response", read_http_head(&mut tls))
            .await?
            .to_ascii_lowercase();
        assert!(head.starts_with("http/1.1 200"), "{head}");
        assert!(head.contains("\r\nx-set: replaced\r\n"), "{head}");
        assert!(!head.contains("x-remove"), "{head}");
        assert_eq!(head.matches("\r\nx-add:").count(), 2, "{head}");
        assert_eq!(read_exact_bytes(&mut tls, 4).await?, b"body");
        server.await??;
    }
    proxy.shutdown().await?;
    Ok(())
}

trait UiTestStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> UiTestStream for T {}
