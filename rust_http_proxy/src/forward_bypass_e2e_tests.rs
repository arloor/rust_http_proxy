use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;

use crate::DynError;
use crate::e2e_test_support::{
    WS_PAYLOAD, assert_ok, assert_switching_protocols, connect_to_mitm_target, read_exact_bytes, read_http_head,
    read_ws_frame_payload, recv_connect_target, recv_forward_request_target, start_forward_bypass_proxy,
    start_forward_request_proxy, start_plain_http_server, start_proxy, start_tcp_echo_server, start_tls_http_server,
    start_tls_websocket_echo_server, start_websocket_echo_server, timeout_step, unique_temp_dir,
    write_masked_text_frame, write_test_ca,
};

#[tokio::test]
async fn forward_http_request_uses_forward_bypass_proxy() -> Result<(), DynError> {
    let upstream = start_plain_http_server().await?;
    let mut forward_bypass = start_forward_request_proxy().await?;
    let proxy = start_proxy(vec![
        "--forward-bypass-url".to_owned(),
        format!("http://127.0.0.1:{}", forward_bypass.addr.port()),
    ])
    .await?;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await?;
    let request = format!(
        "\
GET http://127.0.0.1:{}/plain HTTP/1.1\r\n\
Host: 127.0.0.1:{}\r\n\
Connection: close\r\n\
\r\n",
        upstream.addr.port(),
        upstream.addr.port()
    );
    stream.write_all(request.as_bytes()).await?;
    assert_ok(&timeout_step("forward bypass HTTP response", read_http_head(&mut stream)).await?)?;
    let body = timeout_step("forward bypass HTTP body", read_exact_bytes(&mut stream, 16)).await?;
    assert_eq!(body, b"hello-via-bypass");

    let target =
        timeout_step("forward bypass request target", recv_forward_request_target(&mut forward_bypass)).await?;
    assert_eq!(target, format!("http://127.0.0.1:{}/plain", upstream.addr.port()));

    drop(stream);
    upstream.task.await??;
    forward_bypass.task.await??;
    proxy.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn forward_websocket_upgrade_uses_forward_bypass_proxy() -> Result<(), DynError> {
    let upstream = start_websocket_echo_server().await?;
    let mut forward_bypass = start_forward_request_proxy().await?;
    let proxy = start_proxy(vec![
        "--forward-bypass-url".to_owned(),
        format!("http://127.0.0.1:{}", forward_bypass.addr.port()),
    ])
    .await?;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await?;
    let request = format!(
        "\
GET ws://127.0.0.1:{}/ws HTTP/1.1\r\n\
Host: 127.0.0.1:{}\r\n\
Connection: Upgrade\r\n\
Upgrade: websocket\r\n\
Sec-WebSocket-Version: 13\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
\r\n",
        upstream.addr.port(),
        upstream.addr.port()
    );
    stream.write_all(request.as_bytes()).await?;
    assert_switching_protocols(&timeout_step("forward bypass websocket response", read_http_head(&mut stream)).await?)?;

    write_masked_text_frame(&mut stream, WS_PAYLOAD).await?;
    let echoed = timeout_step("forward bypass websocket echo", read_ws_frame_payload(&mut stream)).await?;
    assert_eq!(echoed, WS_PAYLOAD);

    let target =
        timeout_step("forward bypass request target", recv_forward_request_target(&mut forward_bypass)).await?;
    assert_eq!(target, format!("ws://127.0.0.1:{}/ws", upstream.addr.port()));

    drop(stream);
    upstream.task.await??;
    forward_bypass.task.await??;
    proxy.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn non_mitm_connect_tunnel_uses_forward_bypass_proxy() -> Result<(), DynError> {
    let upstream = start_tcp_echo_server().await?;
    let mut forward_bypass = start_forward_bypass_proxy().await?;
    let proxy = start_proxy(vec![
        "--forward-bypass-url".to_owned(),
        format!("http://127.0.0.1:{}", forward_bypass.addr.port()),
    ])
    .await?;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await?;
    let connect_request = format!(
        "\
CONNECT 127.0.0.1:{} HTTP/1.1\r\n\
Host: 127.0.0.1:{}\r\n\
\r\n",
        upstream.addr.port(),
        upstream.addr.port()
    );
    stream.write_all(connect_request.as_bytes()).await?;
    assert_ok(&timeout_step("forward bypass CONNECT response", read_http_head(&mut stream)).await?)?;

    stream.write_all(WS_PAYLOAD).await?;
    let echoed = timeout_step("forward bypass CONNECT echo", read_exact_bytes(&mut stream, WS_PAYLOAD.len())).await?;
    assert_eq!(echoed, WS_PAYLOAD);

    let connect_target =
        timeout_step("forward bypass CONNECT target", recv_connect_target(&mut forward_bypass)).await?;
    assert_eq!(connect_target, format!("127.0.0.1:{}", upstream.addr.port()));

    drop(stream);
    upstream.task.await??;
    forward_bypass.task.await??;
    proxy.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn mitm_https_request_uses_forward_bypass_proxy() -> Result<(), DynError> {
    let upstream = start_tls_http_server().await?;
    let mut forward_bypass = start_forward_bypass_proxy().await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_mitm_bypass")?;
    let ca = write_test_ca(&temp_dir)?;
    let proxy = start_proxy(vec![
        "--forward-bypass-url".to_owned(),
        format!("http://127.0.0.1:{}", forward_bypass.addr.port()),
        "--mitm-domain-suffix".to_owned(),
        "localhost".to_owned(),
        "--mitm-ca-cert".to_owned(),
        ca.cert_path.to_string_lossy().into_owned(),
        "--mitm-ca-key".to_owned(),
        ca.key_path.to_string_lossy().into_owned(),
    ])
    .await?;

    let mut tls_stream = connect_to_mitm_target(proxy.port, upstream.addr.port(), ca.cert_der).await?;
    tls_stream
        .write_all(
            format!(
                "\
GET /plain HTTP/1.1\r\n\
Host: localhost:{}\r\n\
Connection: close\r\n\
\r\n",
                upstream.addr.port()
            )
            .as_bytes(),
        )
        .await?;
    assert_ok(&timeout_step("MITM bypass HTTPS response", read_http_head(&mut tls_stream)).await?)?;
    let body = timeout_step("MITM bypass HTTPS body", read_exact_bytes(&mut tls_stream, 16)).await?;
    assert_eq!(body, b"hello-via-bypass");

    let connect_target =
        timeout_step("forward bypass CONNECT target", recv_connect_target(&mut forward_bypass)).await?;
    assert_eq!(connect_target, format!("localhost:{}", upstream.addr.port()));

    drop(tls_stream);
    upstream.task.await??;
    forward_bypass.task.await??;
    proxy.shutdown().await?;
    tokio::fs::remove_dir_all(temp_dir).await?;
    Ok(())
}

#[tokio::test]
async fn mitm_websocket_upgrade_uses_forward_bypass_proxy() -> Result<(), DynError> {
    let upstream = start_tls_websocket_echo_server().await?;
    let mut forward_bypass = start_forward_bypass_proxy().await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_ws_mitm_bypass")?;
    let ca = write_test_ca(&temp_dir)?;
    let proxy = start_proxy(vec![
        "--forward-bypass-url".to_owned(),
        format!("http://127.0.0.1:{}", forward_bypass.addr.port()),
        "--mitm-domain-suffix".to_owned(),
        "localhost".to_owned(),
        "--mitm-ca-cert".to_owned(),
        ca.cert_path.to_string_lossy().into_owned(),
        "--mitm-ca-key".to_owned(),
        ca.key_path.to_string_lossy().into_owned(),
    ])
    .await?;

    let mut tls_stream = connect_to_mitm_target(proxy.port, upstream.addr.port(), ca.cert_der).await?;
    let request = format!(
        "\
GET /ws HTTP/1.1\r\n\
Host: localhost:{}\r\n\
Connection: Upgrade\r\n\
Upgrade: websocket\r\n\
Sec-WebSocket-Version: 13\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
\r\n",
        upstream.addr.port()
    );
    tls_stream.write_all(request.as_bytes()).await?;
    assert_switching_protocols(
        &timeout_step("MITM bypass websocket response", read_http_head(&mut tls_stream)).await?,
    )?;

    write_masked_text_frame(&mut tls_stream, WS_PAYLOAD).await?;
    let echoed = timeout_step("MITM bypass websocket echo", read_ws_frame_payload(&mut tls_stream)).await?;
    assert_eq!(echoed, WS_PAYLOAD);

    let connect_target =
        timeout_step("forward bypass CONNECT target", recv_connect_target(&mut forward_bypass)).await?;
    assert_eq!(connect_target, format!("localhost:{}", upstream.addr.port()));

    drop(tls_stream);
    upstream.task.await??;
    forward_bypass.task.await??;
    proxy.shutdown().await?;
    tokio::fs::remove_dir_all(temp_dir).await?;
    Ok(())
}
