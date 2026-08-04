use std::io::{self, ErrorKind};

use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpListener;

use crate::DynError;
use crate::e2e_test_support::{
    connect_to_mitm_target, read_exact_bytes, read_http_head, start_proxy, timeout_step, unique_temp_dir, write_test_ca,
};

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
