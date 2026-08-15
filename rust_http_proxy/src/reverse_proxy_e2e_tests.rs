use std::io;

use http_body_util::{BodyExt as _, Empty};
use hyper::{Request, body::Bytes, client::conn::http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use crate::DynError;
use crate::e2e_test_support::{
    assert_ok, read_http_head, remove_temp_dir, start_proxy, start_tls_h1_routing_server, start_tls_h2_routing_server,
    unique_temp_dir,
};

const SNI: &str = "localhost";
const AUTHORITY: &str = "virtual.example.test";

#[tokio::test]
async fn reverse_http1_separates_connect_target_sni_and_authority() -> Result<(), DynError> {
    let upstream = start_tls_h1_routing_server(SNI, AUTHORITY).await?;
    run_routing_test("H1", upstream.addr.port()).await?;
    upstream.task.await??;
    Ok(())
}

#[tokio::test]
async fn reverse_http2_separates_connect_target_sni_and_authority() -> Result<(), DynError> {
    let upstream = start_tls_h2_routing_server(SNI, AUTHORITY).await?;
    run_routing_test("H2", upstream.addr.port()).await?;
    upstream.task.await??;
    Ok(())
}

#[tokio::test]
async fn reverse_auto_routes_http1_inbound_to_http1_upstream() -> Result<(), DynError> {
    let upstream = start_tls_h1_routing_server(SNI, AUTHORITY).await?;
    run_routing_test("AUTO", upstream.addr.port()).await?;
    upstream.task.await??;
    Ok(())
}

#[tokio::test]
async fn reverse_auto_routes_http2_inbound_to_http2_upstream() -> Result<(), DynError> {
    let upstream = start_tls_h2_routing_server(SNI, AUTHORITY).await?;
    let (proxy, temp_dir) = start_routing_proxy("AUTO", upstream.addr.port()).await?;

    let stream = TcpStream::connect(("127.0.0.1", proxy.port)).await?;
    let (mut sender, connection) = http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(stream))
        .await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("GET")
        .uri("http://incoming.example.test/proxy/check")
        .version(hyper::Version::HTTP_2)
        .body(Empty::<Bytes>::new())?;
    let response = sender.send_request(request).await?;
    assert_eq!(response.status(), hyper::StatusCode::OK);
    assert_eq!(response.into_body().collect().await?.to_bytes(), Bytes::from_static(b"ok"));

    proxy.shutdown().await?;
    upstream.task.await??;
    remove_temp_dir(temp_dir)?;
    Ok(())
}

async fn run_routing_test(version: &str, upstream_port: u16) -> Result<(), DynError> {
    let (proxy, temp_dir) = start_routing_proxy(version, upstream_port).await?;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await?;
    stream
        .write_all(b"GET /proxy/check HTTP/1.1\r\nHost: incoming.example.test\r\nConnection: close\r\n\r\n")
        .await?;
    let response_head = read_http_head(&mut stream).await?;
    if let Err(error) = assert_ok(&response_head) {
        let mut response_body = Vec::new();
        stream.read_to_end(&mut response_body).await?;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{error}; body={}", String::from_utf8_lossy(&response_body)),
        )
        .into());
    }
    let mut body = [0u8; 2];
    stream.read_exact(&mut body).await?;
    assert_eq!(&body, b"ok");

    proxy.shutdown().await?;
    remove_temp_dir(temp_dir)?;
    Ok(())
}

async fn start_routing_proxy(
    version: &str, upstream_port: u16,
) -> Result<(crate::e2e_test_support::RunningProxy, std::path::PathBuf), DynError> {
    let temp_dir = unique_temp_dir("rust_http_proxy_reverse_routing")?;
    let config_path = temp_dir.join("locations.yaml");
    std::fs::create_dir_all(&temp_dir)?;
    std::fs::write(
        &config_path,
        format!(
            "default_host:\n  - location: /proxy/\n    upstream:\n      url_base: https://physical.invalid/backend/\n      connect_to: 127.0.0.1:{upstream_port}\n      tls_server_name: {SNI}\n      authority: {AUTHORITY}\n      version: {version}\n"
        ),
    )?;
    let proxy = start_proxy(vec![
        "--location-config-file".to_owned(),
        config_path.to_string_lossy().into_owned(),
    ])
    .await?;
    Ok((proxy, temp_dir))
}
