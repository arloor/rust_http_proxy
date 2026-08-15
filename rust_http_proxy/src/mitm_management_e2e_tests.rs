use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::DynError;
use crate::e2e_test_support::start_proxy;

const BASIC_AUTH: &str = "Authorization: Basic YWRtaW46dGVzdA==\r\n";

#[tokio::test]
async fn mitm_routes_require_basic_auth_and_serve_embedded_ui() -> Result<(), DynError> {
    let static_dir = std::env::temp_dir().join(format!("rust_http_proxy_mitm_static_{:x}", rand::random::<u64>()));
    std::fs::create_dir_all(&static_dir)?;
    std::fs::write(static_dir.join("mitm"), "this static file must not win")?;
    let proxy = start_proxy(vec![
        "--users".to_owned(),
        "admin:test".to_owned(),
        "--web-content-path".to_owned(),
        static_dir.to_string_lossy().into_owned(),
    ])
    .await?;

    let unauthorized =
        request(proxy.port, "GET /mitm HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await?;
    assert!(unauthorized.starts_with("HTTP/1.1 401"));
    assert!(
        unauthorized
            .to_ascii_lowercase()
            .contains("www-authenticate: basic realm=\"rust_http_proxy mitm\"")
    );
    assert!(
        unauthorized
            .to_ascii_lowercase()
            .contains("cache-control: private, no-store")
    );

    let wrong_auth = request(
        proxy.port,
        "GET /mitm HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWRtaW46YmFk\r\nConnection: close\r\n\r\n",
    )
    .await?;
    assert!(wrong_auth.starts_with("HTTP/1.1 401"));

    let authorized =
        request(proxy.port, &format!("GET /mitm HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\n\r\n"))
            .await?;
    assert!(authorized.starts_with("HTTP/1.1 200"));
    assert!(authorized.contains("<title>MITM Observatory</title>"));
    assert!(!authorized.contains("this static file must not win"));
    assert!(
        authorized
            .to_ascii_lowercase()
            .contains("cache-control: private, no-store")
    );
    assert!(!authorized.to_ascii_lowercase().contains("access-control-allow-origin"));

    let asset_start = authorized
        .find("/mitm/assets/")
        .ok_or("embedded UI did not reference a hashed asset")?;
    let asset_end = authorized[asset_start..]
        .find('"')
        .map(|offset| asset_start + offset)
        .ok_or("embedded asset URL was not terminated")?;
    let asset_path = &authorized[asset_start..asset_end];
    let asset_unauthorized =
        request(proxy.port, &format!("GET {asset_path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
            .await?;
    assert!(asset_unauthorized.starts_with("HTTP/1.1 401"));
    let asset_authorized = request(
        proxy.port,
        &format!("GET {asset_path} HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\n\r\n"),
    )
    .await?;
    assert!(asset_authorized.starts_with("HTTP/1.1 200"));
    assert!(
        asset_authorized
            .to_ascii_lowercase()
            .contains("cache-control: private, no-store")
    );

    proxy.shutdown().await?;
    std::fs::remove_file(static_dir.join("mitm"))?;
    std::fs::remove_dir(static_dir)?;

    let proxy_without_users = start_proxy(Vec::new()).await?;
    let no_users = request(
        proxy_without_users.port,
        "GET /mitm/api/settings HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await?;
    assert!(no_users.starts_with("HTTP/1.1 401"));
    proxy_without_users.shutdown().await
}

#[tokio::test]
async fn mitm_api_manages_targets_without_a_global_switch() -> Result<(), DynError> {
    let proxy = start_proxy(vec!["--users".to_owned(), "admin:test".to_owned()]).await?;
    let body = r#"{"suffix":".Example.COM."}"#;
    let created = request(
        proxy.port,
        &format!(
            "POST /mitm/api/targets HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .await?;
    assert!(created.starts_with("HTTP/1.1 201"));
    assert!(created.contains("\"suffix\":\"example.com\""));
    assert!(created.contains("\"cli_managed\":false"));

    let targets = request(
        proxy.port,
        &format!("GET /mitm/api/targets HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\n\r\n"),
    )
    .await?;
    assert!(targets.starts_with("HTTP/1.1 200"));
    assert!(targets.contains("\"suffix\":\"example.com\""));

    let settings = request(
        proxy.port,
        &format!("GET /mitm/api/settings HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Connection: close\r\n\r\n"),
    )
    .await?;
    assert!(settings.starts_with("HTTP/1.1 200"));
    assert!(settings.contains("\"ca_available\":false"));
    assert!(!settings.contains("mitm_enabled"));

    let legacy_patch = r#"{"mitm_enabled":false}"#;
    let rejected = request(
        proxy.port,
        &format!(
            "PATCH /mitm/api/settings HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{legacy_patch}",
            legacy_patch.len()
        ),
    )
    .await?;
    assert!(rejected.starts_with("HTTP/1.1 422"));

    proxy.shutdown().await
}

#[tokio::test]
async fn mitm_json_apis_honor_accept_encoding_gzip() -> Result<(), DynError> {
    let proxy = start_proxy(vec!["--users".to_owned(), "admin:test".to_owned()]).await?;
    let response = request(
        proxy.port,
        &format!(
            "GET /mitm/api/settings HTTP/1.1\r\nHost: localhost\r\n{BASIC_AUTH}Accept-Encoding: gzip\r\nConnection: close\r\n\r\n"
        ),
    )
    .await?;
    let lower = response.to_ascii_lowercase();
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(lower.contains("content-encoding: gzip"), "MITM JSON APIs should be compressed: {response}");
    proxy.shutdown().await
}

async fn request(port: u16, raw_request: &str) -> Result<String, io::Error> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    stream.write_all(raw_request.as_bytes()).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(String::from_utf8_lossy(&response).into_owned())
}
