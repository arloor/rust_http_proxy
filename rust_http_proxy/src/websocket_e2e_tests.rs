use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;

use crate::DynError;
use crate::e2e_test_support::{
    WS_PAYLOAD, assert_switching_protocols, connect_to_mitm_target, read_http_head, read_ws_frame_payload, start_proxy,
    start_tls_websocket_echo_server, start_websocket_echo_server, timeout_step, unique_temp_dir,
    write_masked_text_frame, write_test_ca,
};

#[tokio::test]
async fn websocket_upgrade_through_forward_proxy_is_tunneled() -> Result<(), DynError> {
    let upstream = start_websocket_echo_server().await?;
    let proxy = start_proxy(Vec::new()).await?;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await?;
    let request = format!(
        "\
GET http://127.0.0.1:{}/ws HTTP/1.1\r\n\
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
    assert_switching_protocols(&read_http_head(&mut stream).await?)?;

    write_masked_text_frame(&mut stream, WS_PAYLOAD).await?;
    let echoed = read_ws_frame_payload(&mut stream).await?;
    assert_eq!(echoed, WS_PAYLOAD);

    upstream.task.await??;
    proxy.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn websocket_upgrade_through_reverse_proxy_is_tunneled() -> Result<(), DynError> {
    let upstream = start_websocket_echo_server().await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_ws_reverse")?;
    let location_config_path = temp_dir.join("locations.yaml");
    tokio::fs::create_dir_all(&temp_dir).await?;
    tokio::fs::write(
        &location_config_path,
        format!(
            "\
default_host:
  - location: /proxy/
    upstream:
      url_base: http://127.0.0.1:{}/
      version: H1
",
            upstream.addr.port()
        ),
    )
    .await?;
    let proxy = start_proxy(vec![
        "--location-config-file".to_owned(),
        location_config_path.to_string_lossy().into_owned(),
    ])
    .await?;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await?;
    let request = format!(
        "\
GET /proxy/ws HTTP/1.1\r\n\
Host: localhost:{}\r\n\
Connection: Upgrade\r\n\
Upgrade: websocket\r\n\
Sec-WebSocket-Version: 13\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
\r\n",
        proxy.port
    );
    stream.write_all(request.as_bytes()).await?;
    assert_switching_protocols(&read_http_head(&mut stream).await?)?;

    write_masked_text_frame(&mut stream, WS_PAYLOAD).await?;
    let echoed = read_ws_frame_payload(&mut stream).await?;
    assert_eq!(echoed, WS_PAYLOAD);

    upstream.task.await??;
    proxy.shutdown().await?;
    tokio::fs::remove_dir_all(temp_dir).await?;
    Ok(())
}

#[tokio::test]
async fn websocket_upgrade_through_mitm_proxy_is_tunneled() -> Result<(), DynError> {
    let upstream = start_tls_websocket_echo_server().await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_ws_mitm")?;
    let ca = write_test_ca(&temp_dir)?;
    let proxy = start_proxy(vec![
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
    assert_switching_protocols(&timeout_step("MITM websocket response", read_http_head(&mut tls_stream)).await?)?;

    write_masked_text_frame(&mut tls_stream, WS_PAYLOAD).await?;
    let echoed = timeout_step("MITM websocket echo", read_ws_frame_payload(&mut tls_stream)).await?;
    assert_eq!(echoed, WS_PAYLOAD);

    upstream.task.await??;
    proxy.shutdown().await?;
    tokio::fs::remove_dir_all(temp_dir).await?;
    Ok(())
}
