//! Security boundaries must hold for real HTTP requests, before routing or dialing.
use std::io;

use base64::Engine as _;
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream};

use crate::DynError;
use crate::e2e_test_support::{header_value, read_response, start_proxy, timeout_step, unique_temp_dir};

async fn get(port: u16, path: &str, authorized: bool) -> Result<(String, Vec<u8>), DynError> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let auth = if authorized {
        format!("Authorization: Basic {}\r\n", base64::engine::general_purpose::STANDARD.encode("alice:fixture"))
    } else {
        String::new()
    };
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{auth}Connection: close\r\n\r\n").as_bytes())
        .await?;
    Ok(timeout_step("security response", read_response(&mut stream)).await?)
}

fn denied(head: &str) -> bool {
    head.starts_with("HTTP/1.1 400 ") || head.starts_with("HTTP/1.1 401 ") || head.starts_with("HTTP/1.1 404 ")
}

#[tokio::test]
async fn security_static_aliases_cannot_skip_path_authentication() -> Result<(), DynError> {
    let dir = unique_temp_dir("static_alias_auth")?;
    std::fs::create_dir_all(dir.join("private"))?;
    std::fs::write(dir.join("private/secret.txt"), "private-fixture")?;
    std::fs::write(dir.join("public file.txt"), "public-fixture")?;
    std::fs::write(dir.join("中文.txt"), "unicode-fixture")?;
    let proxy = start_proxy(vec![
        "--web-content-path".into(),
        dir.to_string_lossy().into_owned(),
        "--static-auth-users".into(),
        "alice:fixture".into(),
        "--static-auth-path-prefix".into(),
        "/private".into(),
    ])
    .await?;
    let mut paths = vec![
        "/private/secret.txt",
        "/./private/secret.txt",
        "//private/secret.txt",
        "/%70rivate/secret.txt",
        "/%2e/private/secret.txt",
        "/public/../private/secret.txt",
        "/private%2fsecret.txt",
    ];
    if cfg!(windows) {
        paths.extend([
            "/PRIVATE/secret.txt",
            "/private./secret.txt",
            "/private%20/secret.txt",
            "/private%5csecret.txt",
        ]);
    }
    let mut failures = Vec::new();
    for path in paths {
        let (head, body) = get(proxy.port, path, false).await?;
        if !denied(&head) || body == b"private-fixture" {
            failures.push(format!("{path}: {}", head.lines().next().unwrap_or_default()));
        }
    }
    let (public, body) = get(proxy.port, "/public%20file.txt", false).await?;
    assert!(public.starts_with("HTTP/1.1 200 "));
    assert_eq!(body, b"public-fixture");
    let (unicode, body) = get(proxy.port, "/%E4%B8%AD%E6%96%87.txt", false).await?;
    assert!(unicode.starts_with("HTTP/1.1 200 "));
    assert_eq!(body, b"unicode-fixture");
    let (private, body) = get(proxy.port, "/private/secret.txt", true).await?;
    assert!(private.starts_with("HTTP/1.1 200 "));
    assert_eq!(body, b"private-fixture");
    assert_eq!(header_value(&private, "cache-control"), Some("private, no-store"));
    if cfg!(windows) {
        let (private, body) = get(proxy.port, "/PRIVATE/secret.txt", true).await?;
        assert!(private.starts_with("HTTP/1.1 200 "));
        assert_eq!(body, b"private-fixture");
        assert_eq!(header_value(&private, "cache-control"), Some("private, no-store"));
    }
    proxy.shutdown().await?;
    std::fs::remove_dir_all(dir)?;
    assert!(failures.is_empty(), "authentication bypasses: {failures:?}");
    Ok(())
}

#[tokio::test]
async fn security_reverse_aliases_are_denied_before_dialing() -> Result<(), DynError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let dir = unique_temp_dir("reverse_alias_auth")?;
    std::fs::create_dir_all(&dir)?;
    let config = dir.join("locations.yaml");
    std::fs::write(
        &config,
        format!(
            "default_host:\n  - location: /api/\n    basic_auth_users: [alice:fixture]\n    basic_auth_path_prefixes: [/private]\n    upstream:\n      url_base: http://127.0.0.1:{port}/\n  - location: /%E4%B8%AD/\n    basic_auth_users: [alice:fixture]\n    upstream:\n      url_base: http://127.0.0.1:{port}/\n"
        ),
    )?;
    // Answer unexpected dials so the pre-fix test fails promptly instead of timing out.
    let accepts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = accepts.clone();
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await?;
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let _ = crate::e2e_test_support::read_http_head(&mut stream).await;
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), io::Error>(())
    });
    let proxy = start_proxy(vec!["--location-config-file".into(), config.to_string_lossy().into_owned()]).await?;
    let mut failures = Vec::new();
    for path in [
        "/api/private/item",
        "/api/%70rivate/item",
        "/api/./private/item",
        "/api//private/item",
        "/api/public/../private/item",
        "/%61pi/private/item",
    ] {
        let (head, _) = get(proxy.port, path, false).await?;
        if !denied(&head) {
            failures.push(path);
        }
    }
    let (head, _) = get(proxy.port, "/%e4%b8%ad/private", false).await?;
    assert!(head.starts_with("HTTP/1.1 401 "));
    proxy.shutdown().await?;
    server.abort();
    std::fs::remove_dir_all(dir)?;
    assert!(failures.is_empty(), "reverse authentication bypasses: {failures:?}");
    assert_eq!(accepts.load(std::sync::atomic::Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn security_encoded_windows_traversal_is_rejected_over_http() -> Result<(), DynError> {
    let dir = unique_temp_dir("encoded_traversal")?;
    let root = dir.join("www");
    std::fs::create_dir_all(root.join("sub"))?;
    std::fs::write(dir.join("outside.txt"), "outside-fixture")?;
    let proxy = start_proxy(vec!["--web-content-path".into(), root.to_string_lossy().into_owned()]).await?;
    let (head, body) = get(proxy.port, "/sub%5c..%5c..%5coutside.txt", false).await?;
    proxy.shutdown().await?;
    std::fs::remove_dir_all(dir)?;
    assert!(denied(&head));
    assert_ne!(body, b"outside-fixture");
    Ok(())
}

#[tokio::test]
async fn security_shortcut_keeps_configured_authority_and_query() -> Result<(), DynError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let server = tokio::spawn(async move {
        let mut requests = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await?;
            requests.push(crate::e2e_test_support::read_http_head(&mut stream).await?);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await?;
        }
        Ok::<_, io::Error>(requests)
    });
    let base = format!("http://127.0.0.1:{port}");
    let proxy = start_proxy(vec!["--append-upstream-url".into(), base.clone()]).await?;
    for suffix in ["/%69tem?q=%2f%25", ".attacker.example/item"] {
        let (head, _) = get(proxy.port, &format!("/{base}{suffix}"), false).await?;
        assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    }
    let requests = timeout_step("shortcut upstream", server).await??;
    assert!(requests[0].starts_with("GET /item?q=%2f%25 HTTP/1.1\r\n"));
    assert!(requests[1].starts_with("GET /.attacker.example/item HTTP/1.1\r\n"));
    for request in requests {
        assert_eq!(header_value(&request, "host"), Some(format!("127.0.0.1:{port}").as_str()));
    }
    proxy.shutdown().await?;
    Ok(())
}

#[cfg(windows)]
#[tokio::test]
async fn security_windows_static_location_is_case_insensitive() -> Result<(), DynError> {
    let dir = unique_temp_dir("static_location_case")?;
    let root = dir.join("root");
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("file.txt"), "protected-fixture")?;
    let config = dir.join("locations.yaml");
    std::fs::write(
        &config,
        format!(
            "default_host:\n  - location: /Private/\n    static_dir: '{}'\n    basic_auth_users: [alice:fixture]\n",
            root.display()
        ),
    )?;
    let proxy = start_proxy(vec!["--location-config-file".into(), config.to_string_lossy().into_owned()]).await?;
    let (head, _) = get(proxy.port, "/private/file.txt", false).await?;
    assert!(head.starts_with("HTTP/1.1 401 "));
    let (head, body) = get(proxy.port, "/PRIVATE/file.txt", true).await?;
    assert!(head.starts_with("HTTP/1.1 200 "));
    assert_eq!(body, b"protected-fixture");
    assert_eq!(header_value(&head, "cache-control"), Some("private, no-store"));
    proxy.shutdown().await?;
    std::fs::remove_dir_all(dir)?;
    Ok(())
}
