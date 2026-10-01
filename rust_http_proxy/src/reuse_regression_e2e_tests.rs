//! 重构前锁定的行为：父代理 CONNECT 握手、直连隧道、WebSocket 失败回包、
//! location 入口鉴权，以及 HTTP/1 连接复用。断言描述的是当前对外可观察结果。

use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine as _;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::DynError;
use crate::e2e_test_support::{
    RunningProxy, SSH_BANNER, WS_PAYLOAD, assert_ok, connect_to_mitm_target, header_value, read_exact_bytes,
    read_http_head, read_response, recv_channel, recv_connect_target, remove_temp_dir, start_fixed_response_server,
    start_forward_bypass_proxy, start_plain_http_server, start_proxy, start_tcp_banner_server, start_tcp_echo_server,
    start_tls_fixed_response_server, start_tls_http_server, test_server_tls_config, timeout_step, unique_temp_dir,
    write_test_ca,
};

const PARENT_USER: &str = "proxyuser";
const PARENT_PASSWORD: &str = "proxypass";
const ALICE_BASIC: &str = "alice:secret";
const REJECT_BODY: &[u8] = b"reject-body";
const REJECT_RESPONSE: &[u8] = b"\
HTTP/1.1 400 Bad Request\r\n\
Content-Length: 11\r\n\
Connection: close\r\n\
\r\n\
reject-body";
const KEEP_ALIVE_BODY: &[u8] = b"keep-alive-ok";

struct ObservingParent {
    addr: SocketAddr,
    head_rx: tokio::sync::mpsc::Receiver<String>,
    task: JoinHandle<Result<(), DynError>>,
}

enum ParentAction {
    /// 把 CONNECT 目标的字节原样转走，并在 200 响应里插入一个额外头。
    Tunnel,
    TunnelWithBanner,
    /// 不连接目标，直接返回非 200。
    Reject,
}

async fn start_observing_parent(action: ParentAction) -> Result<ObservingParent, DynError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let (head_tx, head_rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await?;
        let head = read_http_head(&mut client).await?;
        head_tx
            .send(head.clone())
            .await
            .map_err(|_| io::Error::new(ErrorKind::BrokenPipe, "parent CONNECT head receiver dropped"))?;
        match action {
            ParentAction::Reject => {
                client
                    .write_all(
                        b"HTTP/1.1 502 Bad Gateway\r\n\
Content-Length: 4\r\n\
Connection: close\r\n\
\r\n\
nope",
                    )
                    .await?;
            }
            ParentAction::Tunnel | ParentAction::TunnelWithBanner => {
                let target = connect_target_from_head(&head)?;
                let mut upstream = TcpStream::connect(target).await?;
                let mut response =
                    b"HTTP/1.1 200 Connection Established\r\nX-Parent-Marker: do-not-leak\r\n\r\n".to_vec();
                if matches!(action, ParentAction::TunnelWithBanner) {
                    let banner = read_exact_bytes(&mut upstream, SSH_BANNER.len()).await?;
                    response.extend_from_slice(&banner);
                }
                client.write_all(&response).await?;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            }
        }
        Ok(())
    });
    Ok(ObservingParent { addr, head_rx, task })
}

fn connect_target_from_head(head: &str) -> io::Result<String> {
    let request_line = head.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    if method != "CONNECT" || target.is_empty() {
        return Err(io::Error::new(ErrorKind::InvalidData, format!("parent expected CONNECT, got: {head}")));
    }
    Ok(target.to_owned())
}

fn basic_token(user_password: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(user_password.as_bytes())
}

fn expected_parent_connect_head(target: &str, forwarded_for: &str) -> String {
    format!(
        "CONNECT {target} HTTP/1.1\r\n\
Host: {target}\r\n\
X-Forwarded-For: {forwarded_for}\r\n\
Proxy-Authorization: Basic {}\r\n\
\r\n",
        basic_token(&format!("{PARENT_USER}:{PARENT_PASSWORD}"))
    )
}

fn bypass_url(parent: &ObservingParent) -> String {
    format!("http://{PARENT_USER}:{PARENT_PASSWORD}@127.0.0.1:{}", parent.addr.port())
}

async fn recv_parent_head(parent: &mut ObservingParent) -> io::Result<String> {
    recv_channel("parent CONNECT head", &mut parent.head_rx).await
}

struct KeepAliveUpstream {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl KeepAliveUpstream {
    async fn start() -> io::Result<Self> {
        Self::start_with_tls(None).await
    }

    async fn start_tls() -> Result<Self, DynError> {
        let acceptor = TlsAcceptor::from(Arc::new(test_server_tls_config()?));
        Ok(Self::start_with_tls(Some(acceptor)).await?)
    }

    async fn start_with_tls(acceptor: Option<TlsAcceptor>) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let accepts = Arc::new(AtomicUsize::new(0));
        let task_accepts = accepts.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let accepts = task_accepts.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    accepts.fetch_add(1, Ordering::SeqCst);
                    let _ = match acceptor {
                        Some(acceptor) => match acceptor.accept(stream).await {
                            Ok(stream) => serve_two_keep_alive_responses(stream).await,
                            Err(error) => Err(error),
                        },
                        None => serve_two_keep_alive_responses(stream).await,
                    };
                });
            }
        });
        Ok(Self { addr, accepts, task })
    }

    fn abort(self) {
        self.task.abort();
    }
}

async fn serve_two_keep_alive_responses<S>(mut stream: S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    for _ in 0..2 {
        let _ = read_http_head(&mut stream).await?;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
Content-Length: 13\r\n\
Connection: keep-alive\r\n\
\r\n\
keep-alive-ok",
            )
            .await?;
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        let mut byte = [0u8; 1];
        let _ = stream.read_exact(&mut byte).await;
    })
    .await;
    Ok(())
}

async fn proxy_keep_alive_get(proxy_port: u16, request_target: &str, host_header: &str) -> Result<Vec<u8>, DynError> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
    let request = format!(
        "\
GET {request_target} HTTP/1.1\r\n\
Host: {host_header}\r\n\
Connection: keep-alive\r\n\
\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let (head, body) = timeout_step("keep-alive response", read_response(&mut stream)).await?;
    assert_ok(&head)?;
    Ok(body)
}

struct CapturingOrigin {
    addr: SocketAddr,
    head_rx: tokio::sync::mpsc::Receiver<String>,
    task: JoinHandle<Result<(), DynError>>,
}

async fn start_capturing_origin() -> Result<CapturingOrigin, DynError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let (head_tx, head_rx) = tokio::sync::mpsc::channel(4);
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await?;
            let head_tx = head_tx.clone();
            tokio::spawn(async move {
                while let Ok(head) = read_http_head(&mut stream).await {
                    if head_tx.send(head).await.is_err() {
                        return;
                    }
                    if stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\n\
Content-Length: 11\r\n\
Connection: close\r\n\
\r\n\
upstream-ok",
                        )
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    Ok(CapturingOrigin { addr, head_rx, task })
}

async fn recv_origin_head(origin: &mut CapturingOrigin) -> io::Result<String> {
    recv_channel("upstream request head", &mut origin.head_rx).await
}

async fn origin_was_not_contacted(origin: &mut CapturingOrigin) -> bool {
    tokio::time::timeout(Duration::from_millis(200), origin.head_rx.recv())
        .await
        .is_err()
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

#[tokio::test]
async fn parent_connect_for_plain_tunnel_sends_auth_xff_and_drops_extra_headers() -> Result<(), DynError> {
    let upstream = start_tcp_echo_server().await?;
    let mut parent = start_observing_parent(ParentAction::Tunnel).await?;
    let proxy = start_proxy(vec!["--forward-bypass-url".to_owned(), bypass_url(&parent)]).await?;
    let target = format!("127.0.0.1:{}", upstream.addr.port());

    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await?;
    stream
        .write_all(
            format!(
                "\
CONNECT {target} HTTP/1.1\r\n\
Host: {target}\r\n\
X-Forwarded-For: 203.0.113.5, 198.51.100.2\r\n\
\r\n"
            )
            .as_bytes(),
        )
        .await?;
    assert_ok(&timeout_step("plain bypass CONNECT response", read_http_head(&mut stream)).await?)?;
    stream.write_all(WS_PAYLOAD).await?;
    let echoed = timeout_step("plain bypass echo", read_exact_bytes(&mut stream, WS_PAYLOAD.len())).await?;
    assert_eq!(echoed, WS_PAYLOAD);
    assert_eq!(recv_parent_head(&mut parent).await?, expected_parent_connect_head(&target, "203.0.113.5"));

    drop(stream);
    upstream.task.await??;
    parent.task.await??;
    proxy.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn parent_connect_for_mitm_https_sends_auth_xff_and_drops_extra_headers() -> Result<(), DynError> {
    let upstream = start_tls_http_server().await?;
    let mut parent = start_observing_parent(ParentAction::Tunnel).await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_parent_connect_mitm_https")?;
    let ca = write_test_ca(&temp_dir)?;
    let proxy = start_proxy(mitm_args(
        &ca.cert_path,
        &ca.key_path,
        vec!["--forward-bypass-url".to_owned(), bypass_url(&parent)],
    ))
    .await?;

    let mut tls_stream = connect_to_mitm_target(proxy.port, upstream.addr.port(), ca.cert_der).await?;
    tls_stream
        .write_all(
            format!(
                "\
GET /plain HTTP/1.1\r\n\
Host: localhost:{}\r\n\
X-Forwarded-For: 203.0.113.9, 198.51.100.8\r\n\
Connection: close\r\n\
\r\n",
                upstream.addr.port()
            )
            .as_bytes(),
        )
        .await?;
    let (head, body) = timeout_step("MITM bypass response", read_response(&mut tls_stream)).await?;
    assert_ok(&head)?;
    assert_eq!(body, b"hello-via-bypass");
    assert_eq!(
        recv_parent_head(&mut parent).await?,
        expected_parent_connect_head(&format!("localhost:{}", upstream.addr.port()), "203.0.113.9")
    );

    drop(tls_stream);
    upstream.task.await??;
    parent.task.await??;
    proxy.shutdown().await?;
    remove_temp_dir(temp_dir)?;
    Ok(())
}

#[tokio::test]
async fn parent_connect_for_mitm_non_http_sends_auth_xff_and_drops_extra_headers() -> Result<(), DynError> {
    let upstream = start_tcp_banner_server().await?;
    let mut parent = start_observing_parent(ParentAction::TunnelWithBanner).await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_parent_connect_mitm_raw")?;
    let ca = write_test_ca(&temp_dir)?;
    let proxy = start_proxy(mitm_args(
        &ca.cert_path,
        &ca.key_path,
        vec!["--forward-bypass-url".to_owned(), bypass_url(&parent)],
    ))
    .await?;
    let target = format!("localhost:{}", upstream.addr.port());

    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await?;
    stream
        .write_all(
            format!(
                "\
CONNECT {target} HTTP/1.1\r\n\
Host: {target}\r\n\
X-Forwarded-For: 203.0.113.7\r\n\
\r\n"
            )
            .as_bytes(),
        )
        .await?;
    assert_ok(&timeout_step("MITM raw CONNECT response", read_http_head(&mut stream)).await?)?;
    let banner = timeout_step("MITM raw banner", read_exact_bytes(&mut stream, SSH_BANNER.len())).await?;
    assert_eq!(banner, SSH_BANNER);
    assert_eq!(recv_parent_head(&mut parent).await?, expected_parent_connect_head(&target, "203.0.113.7"));

    drop(stream);
    upstream.task.await??;
    parent.task.await??;
    proxy.shutdown().await?;
    remove_temp_dir(temp_dir)?;
    Ok(())
}

#[tokio::test]
async fn plain_connect_bypass_rejects_non_200_parent_before_opening_tunnel() -> Result<(), DynError> {
    let parent = start_observing_parent(ParentAction::Reject).await?;
    let proxy = start_proxy(vec!["--forward-bypass-url".to_owned(), bypass_url(&parent)]).await?;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await?;
    stream
        .write_all(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
        .await?;
    let (head, body) = timeout_step("rejected parent CONNECT response", read_response(&mut stream)).await?;
    assert!(head.starts_with("HTTP/1.1 500 "), "expected gateway error, got: {head}");
    let body = String::from_utf8_lossy(&body);
    assert!(
        body.contains("unexpected response from bypass server"),
        "error page should keep the parent status failure, got: {body}"
    );
    assert!(!body.contains("do-not-leak"));

    drop(stream);
    parent.task.await??;
    proxy.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn direct_connect_tunnel_echoes_payload() -> Result<(), DynError> {
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

    drop(stream);
    upstream.task.await??;
    proxy.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn mitm_non_http_falls_back_to_direct_tunnel() -> Result<(), DynError> {
    let upstream = start_tcp_banner_server().await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_mitm_direct_raw")?;
    let ca = write_test_ca(&temp_dir)?;
    let proxy = start_proxy(mitm_args(&ca.cert_path, &ca.key_path, Vec::new())).await?;
    let target = format!("localhost:{}", upstream.addr.port());

    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await?;
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await?;
    assert_ok(&timeout_step("MITM direct CONNECT response", read_http_head(&mut stream)).await?)?;
    let banner = timeout_step("MITM direct banner", read_exact_bytes(&mut stream, SSH_BANNER.len())).await?;
    assert_eq!(banner, SSH_BANNER);

    drop(stream);
    upstream.task.await??;
    proxy.shutdown().await?;
    remove_temp_dir(temp_dir)?;
    Ok(())
}

#[tokio::test]
async fn forward_websocket_rejection_is_gateway_error() -> Result<(), DynError> {
    let upstream = start_fixed_response_server(REJECT_RESPONSE).await?;
    let proxy = start_proxy(Vec::new()).await?;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await?;
    stream
        .write_all(
            format!(
                "\
GET http://127.0.0.1:{}/ws HTTP/1.1\r\n\
Host: 127.0.0.1:{}\r\n\
Connection: Upgrade\r\n\
Upgrade: websocket\r\n\
\r\n",
                upstream.addr.port(),
                upstream.addr.port()
            )
            .as_bytes(),
        )
        .await?;
    let (head, body) = timeout_step("forward rejected websocket", read_response(&mut stream)).await?;
    assert!(head.starts_with("HTTP/1.1 500 "), "forward proxy turns a rejected upgrade into an error: {head}");
    let body = String::from_utf8_lossy(&body);
    assert!(body.contains("WebSocket upgrade failed"), "got body: {body}");
    assert!(!body.contains("reject-body"), "upstream rejection body must not be tunneled");

    drop(stream);
    upstream.task.await??;
    proxy.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn reverse_websocket_rejection_returns_upstream_response() -> Result<(), DynError> {
    let upstream = start_fixed_response_server(REJECT_RESPONSE).await?;
    let (proxy, temp_dir) = start_reverse_proxy(upstream.addr.port()).await?;

    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await?;
    stream
        .write_all(
            format!(
                "\
GET /proxy/ws HTTP/1.1\r\n\
Host: localhost:{}\r\n\
Connection: Upgrade\r\n\
Upgrade: websocket\r\n\
\r\n",
                proxy.port
            )
            .as_bytes(),
        )
        .await?;
    let (head, body) = timeout_step("reverse rejected websocket", read_response(&mut stream)).await?;
    assert!(head.starts_with("HTTP/1.1 400 "), "reverse proxy returns the upstream rejection: {head}");
    assert_eq!(body, REJECT_BODY);

    drop(stream);
    upstream.task.await??;
    proxy.shutdown().await?;
    remove_temp_dir(temp_dir)?;
    Ok(())
}

#[tokio::test]
async fn mitm_websocket_rejection_returns_upstream_response() -> Result<(), DynError> {
    let upstream = start_tls_fixed_response_server(REJECT_RESPONSE).await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_mitm_ws_reject")?;
    let ca = write_test_ca(&temp_dir)?;
    let proxy = start_proxy(mitm_args(&ca.cert_path, &ca.key_path, Vec::new())).await?;

    let mut tls_stream = connect_to_mitm_target(proxy.port, upstream.addr.port(), ca.cert_der).await?;
    tls_stream
        .write_all(
            format!(
                "\
GET /ws HTTP/1.1\r\n\
Host: localhost:{}\r\n\
Connection: Upgrade\r\n\
Upgrade: websocket\r\n\
\r\n",
                upstream.addr.port()
            )
            .as_bytes(),
        )
        .await?;
    let (head, body) = timeout_step("MITM rejected websocket", read_response(&mut tls_stream)).await?;
    assert!(head.starts_with("HTTP/1.1 400 "), "MITM returns the upstream rejection: {head}");
    assert_eq!(body, REJECT_BODY);

    drop(tls_stream);
    upstream.task.await??;
    proxy.shutdown().await?;
    remove_temp_dir(temp_dir)?;
    Ok(())
}

#[tokio::test]
async fn dynamic_mitm_stub_websocket_rejection_returns_upstream_response() -> Result<(), DynError> {
    let upstream = start_fixed_response_server(REJECT_RESPONSE).await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_dynamic_stub_ws_reject")?;
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
    let proxy = start_proxy(mitm_args(
        &ca.cert_path,
        &ca.key_path,
        vec![
            "--mitm-stub-config-file".to_owned(),
            stub_config_path.to_string_lossy().into_owned(),
        ],
    ))
    .await?;

    let mut tls_stream = connect_to_mitm_target(proxy.port, upstream.addr.port(), ca.cert_der).await?;
    tls_stream
        .write_all(
            format!(
                "\
GET /ws HTTP/1.1\r\n\
Host: localhost:{}\r\n\
Connection: Upgrade\r\n\
Upgrade: websocket\r\n\
\r\n",
                upstream.addr.port()
            )
            .as_bytes(),
        )
        .await?;
    let (head, body) = timeout_step("dynamic stub rejected websocket", read_response(&mut tls_stream)).await?;
    assert!(head.starts_with("HTTP/1.1 400 "), "dynamic stub returns the upstream rejection: {head}");
    assert_eq!(body, REJECT_BODY);

    drop(tls_stream);
    upstream.task.await??;
    proxy.shutdown().await?;
    remove_temp_dir(temp_dir)?;
    Ok(())
}

async fn start_reverse_proxy(upstream_port: u16) -> Result<(RunningProxy, std::path::PathBuf), DynError> {
    let temp_dir = unique_temp_dir("rust_http_proxy_reuse_reverse")?;
    let config_path = temp_dir.join("locations.yaml");
    std::fs::create_dir_all(&temp_dir)?;
    std::fs::write(
        &config_path,
        format!(
            "\
default_host:
  - location: /proxy/
    upstream:
      url_base: http://127.0.0.1:{upstream_port}/
      version: H1
"
        ),
    )?;
    let proxy = start_proxy(vec![
        "--location-config-file".to_owned(),
        config_path.to_string_lossy().into_owned(),
    ])
    .await?;
    Ok((proxy, temp_dir))
}

#[tokio::test]
async fn reverse_proxy_auth_challenges_protected_prefix_and_strips_credentials() -> Result<(), DynError> {
    let mut origin = start_capturing_origin().await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_reverse_auth_gate")?;
    let config_path = temp_dir.join("locations.yaml");
    std::fs::create_dir_all(&temp_dir)?;
    std::fs::write(
        &config_path,
        format!(
            "\
default_host:
  - location: /api/
    upstream:
      url_base: http://127.0.0.1:{}/
      version: H1
    basic_auth_users:
      - {ALICE_BASIC}
    basic_auth_path_prefixes:
      - /private
",
            origin.addr.port()
        ),
    )?;
    let proxy = start_proxy(vec![
        "--location-config-file".to_owned(),
        config_path.to_string_lossy().into_owned(),
    ])
    .await?;
    let token = basic_token(ALICE_BASIC);

    let (denied_head, denied_body) = request_origin_form(
        proxy.port,
        "GET /api/private/item HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await?;
    assert!(denied_head.starts_with("HTTP/1.1 401 "), "{denied_head}");
    assert_eq!(header_value(&denied_head, "www-authenticate"), Some("Basic realm=\"are you kidding me\""));
    assert_eq!(denied_body, b"auth need");
    assert!(origin_was_not_contacted(&mut origin).await, "401 must be generated before dialing upstream");

    let (public_head, public_body) = request_origin_form(
        proxy.port,
        &format!(
            "\
GET /api/public HTTP/1.1\r\n\
Host: localhost\r\n\
Authorization: Basic {token}\r\n\
Connection: close\r\n\
\r\n"
        ),
    )
    .await?;
    assert_ok(&public_head)?;
    assert_eq!(public_body, b"upstream-ok");
    let public_upstream = recv_origin_head(&mut origin).await?;
    assert!(
        header_value(&public_upstream, "authorization").is_some(),
        "unprotected path keeps the caller Authorization header: {public_upstream}"
    );

    let (private_head, private_body) = request_origin_form(
        proxy.port,
        &format!(
            "\
GET /api/private/item HTTP/1.1\r\n\
Host: localhost\r\n\
Authorization: Basic {token}\r\n\
Connection: close\r\n\
\r\n"
        ),
    )
    .await?;
    assert_ok(&private_head)?;
    assert_eq!(private_body, b"upstream-ok");
    let private_upstream = recv_origin_head(&mut origin).await?;
    assert!(
        header_value(&private_upstream, "authorization").is_none(),
        "protected path removes Authorization after a successful check: {private_upstream}"
    );

    origin.task.abort();
    proxy.shutdown().await?;
    remove_temp_dir(temp_dir)?;
    Ok(())
}

#[tokio::test]
async fn static_serving_auth_challenges_protected_prefix_and_sets_private_cache() -> Result<(), DynError> {
    let temp_dir = unique_temp_dir("rust_http_proxy_static_auth_gate")?;
    std::fs::create_dir_all(temp_dir.join("private"))?;
    std::fs::write(temp_dir.join("public.txt"), "public-file")?;
    std::fs::write(temp_dir.join("private").join("secret.txt"), "secret-file")?;
    let proxy = start_proxy(vec![
        "--web-content-path".to_owned(),
        temp_dir.to_string_lossy().into_owned(),
        "--static-auth-users".to_owned(),
        ALICE_BASIC.to_owned(),
        "--static-auth-path-prefix".to_owned(),
        "/private".to_owned(),
    ])
    .await?;
    let token = basic_token(ALICE_BASIC);

    let (public_head, public_body) =
        request_origin_form(proxy.port, "GET /public.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
    assert_ok(&public_head)?;
    assert_eq!(public_body, b"public-file");
    assert_eq!(header_value(&public_head, "cache-control"), Some("public, max-age=600"));

    let (denied_head, denied_body) = request_origin_form(
        proxy.port,
        "GET /private/secret.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await?;
    assert!(denied_head.starts_with("HTTP/1.1 401 "), "{denied_head}");
    assert_eq!(denied_body, b"auth need");

    let (private_head, private_body) = request_origin_form(
        proxy.port,
        &format!(
            "\
GET /private/secret.txt HTTP/1.1\r\n\
Host: localhost\r\n\
Authorization: Basic {token}\r\n\
Connection: close\r\n\
\r\n"
        ),
    )
    .await?;
    assert_ok(&private_head)?;
    assert_eq!(private_body, b"secret-file");
    assert_eq!(header_value(&private_head, "cache-control"), Some("private, no-store"));

    proxy.shutdown().await?;
    remove_temp_dir(temp_dir)?;
    Ok(())
}

#[tokio::test]
async fn serving_allowlist_drops_reverse_and_static_requests() -> Result<(), DynError> {
    let upstream = start_plain_http_server().await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_serving_allowlist")?;
    std::fs::create_dir_all(&temp_dir)?;
    std::fs::write(temp_dir.join("hello.txt"), "hello-static")?;
    let config_path = temp_dir.join("locations.yaml");
    std::fs::write(
        &config_path,
        format!(
            "\
default_host:
  - location: /api/
    upstream:
      url_base: http://127.0.0.1:{}/
      version: H1
",
            upstream.addr.port()
        ),
    )?;
    let proxy = start_proxy(vec![
        "--web-content-path".to_owned(),
        temp_dir.to_string_lossy().into_owned(),
        "--location-config-file".to_owned(),
        config_path.to_string_lossy().into_owned(),
        "--allow-serving-network".to_owned(),
        "10.0.0.0/8".to_owned(),
    ])
    .await?;

    assert_connection_dropped(proxy.port, "GET /hello.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    assert_connection_dropped(proxy.port, "GET /api/plain HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;

    proxy.shutdown().await?;
    upstream.task.abort();
    remove_temp_dir(temp_dir)?;
    Ok(())
}

async fn assert_connection_dropped(proxy_port: u16, request: &str) -> Result<(), DynError> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
    stream.write_all(request.as_bytes()).await?;
    match timeout_step("allowlist drop", read_http_head(&mut stream)).await {
        Ok(head) => {
            Err(io::Error::new(ErrorKind::InvalidData, format!("request should be dropped, got: {head}")).into())
        }
        Err(error) => {
            let message = error.to_string().to_ascii_lowercase();
            assert!(
                message.contains("eof")
                    || message.contains("unexpected")
                    || message.contains("reset")
                    || message.contains("closed")
                    || message.contains("broken"),
                "dropped request should close the socket, got: {error}"
            );
            Ok(())
        }
    }
}

async fn request_origin_form(proxy_port: u16, request: &str) -> Result<(String, Vec<u8>), DynError> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
    stream.write_all(request.as_bytes()).await?;
    timeout_step("origin-form response", read_response(&mut stream))
        .await
        .map_err(Into::into)
}

#[tokio::test]
async fn forward_http1_reuses_upstream_connection() -> Result<(), DynError> {
    let upstream = KeepAliveUpstream::start().await?;
    let proxy = start_proxy(Vec::new()).await?;
    let target = format!("http://127.0.0.1:{}/item", upstream.addr.port());
    let host = format!("127.0.0.1:{}", upstream.addr.port());

    let first = proxy_keep_alive_get(proxy.port, &target, &host).await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let second = proxy_keep_alive_get(proxy.port, &target, &host).await?;

    assert_eq!(first, KEEP_ALIVE_BODY);
    assert_eq!(second, KEEP_ALIVE_BODY);
    assert_eq!(upstream.accepts.load(Ordering::SeqCst), 1, "forward proxy should reuse the HTTP/1 upstream");

    upstream.abort();
    proxy.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn reverse_http1_reuses_upstream_connection() -> Result<(), DynError> {
    let upstream = KeepAliveUpstream::start().await?;
    let (proxy, temp_dir) = start_reverse_proxy(upstream.addr.port()).await?;

    let first = proxy_keep_alive_get(proxy.port, "/proxy/one", &format!("localhost:{}", proxy.port)).await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let second = proxy_keep_alive_get(proxy.port, "/proxy/two", &format!("localhost:{}", proxy.port)).await?;

    assert_eq!(first, KEEP_ALIVE_BODY);
    assert_eq!(second, KEEP_ALIVE_BODY);
    assert_eq!(upstream.accepts.load(Ordering::SeqCst), 1, "reverse proxy should reuse the HTTP/1 upstream");

    upstream.abort();
    proxy.shutdown().await?;
    remove_temp_dir(temp_dir)?;
    Ok(())
}

#[tokio::test]
async fn forward_bypass_http1_reuses_parent_connection() -> Result<(), DynError> {
    let parent = KeepAliveUpstream::start().await?;
    let proxy = start_proxy(vec![
        "--forward-bypass-url".to_owned(),
        format!("http://127.0.0.1:{}", parent.addr.port()),
    ])
    .await?;

    let first = proxy_keep_alive_get(proxy.port, "http://origin.invalid/one", "origin.invalid").await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let second = proxy_keep_alive_get(proxy.port, "http://origin.invalid/two", "origin.invalid").await?;

    assert_eq!(first, KEEP_ALIVE_BODY);
    assert_eq!(second, KEEP_ALIVE_BODY);
    assert_eq!(parent.accepts.load(Ordering::SeqCst), 1, "bypass HTTP requests should reuse the parent connection");

    parent.abort();
    proxy.shutdown().await?;
    Ok(())
}

async fn mitm_keep_alive_get(proxy_port: u16, upstream_port: u16, ca_cert_der: Vec<u8>) -> Result<Vec<u8>, DynError> {
    let mut tls_stream = connect_to_mitm_target(proxy_port, upstream_port, ca_cert_der).await?;
    tls_stream
        .write_all(format!("GET /item HTTP/1.1\r\nHost: localhost:{upstream_port}\r\n\r\n").as_bytes())
        .await?;
    let (head, body) = timeout_step("MITM keep-alive response", read_response(&mut tls_stream)).await?;
    assert_ok(&head)?;
    Ok(body)
}

#[tokio::test]
async fn mitm_https_reuses_upstream_connection_across_client_connections() -> Result<(), DynError> {
    let upstream = KeepAliveUpstream::start_tls().await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_mitm_reuse_direct")?;
    let ca = write_test_ca(&temp_dir)?;
    let proxy = start_proxy(mitm_args(&ca.cert_path, &ca.key_path, Vec::new())).await?;

    let first = mitm_keep_alive_get(proxy.port, upstream.addr.port(), ca.cert_der.clone()).await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let second = mitm_keep_alive_get(proxy.port, upstream.addr.port(), ca.cert_der).await?;

    assert_eq!(first, KEEP_ALIVE_BODY);
    assert_eq!(second, KEEP_ALIVE_BODY);
    assert_eq!(upstream.accepts.load(Ordering::SeqCst), 1, "MITM should reuse the HTTPS upstream");

    upstream.abort();
    proxy.shutdown().await?;
    remove_temp_dir(temp_dir)?;
    Ok(())
}

#[tokio::test]
async fn mitm_https_via_bypass_reuses_parent_tunnel() -> Result<(), DynError> {
    let upstream = KeepAliveUpstream::start_tls().await?;
    let mut parent = start_forward_bypass_proxy().await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_mitm_reuse_bypass")?;
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

    let first = mitm_keep_alive_get(proxy.port, upstream.addr.port(), ca.cert_der.clone()).await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    // 父代理只接受一次连接，第二个请求只有复用隧道才能成功。
    let second = mitm_keep_alive_get(proxy.port, upstream.addr.port(), ca.cert_der).await?;

    assert_eq!(first, KEEP_ALIVE_BODY);
    assert_eq!(second, KEEP_ALIVE_BODY);
    assert_eq!(recv_connect_target(&mut parent).await?, format!("localhost:{}", upstream.addr.port()));
    assert_eq!(upstream.accepts.load(Ordering::SeqCst), 1);

    upstream.abort();
    parent.task.abort();
    proxy.shutdown().await?;
    remove_temp_dir(temp_dir)?;
    Ok(())
}

struct H2CountingUpstream {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

const H2_BODY: &[u8] = b"h2-ok";

async fn start_h2_counting_upstream() -> Result<H2CountingUpstream, DynError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let mut tls_config = test_server_tls_config()?;
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let accepts = Arc::new(AtomicUsize::new(0));
    let task_accepts = accepts.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            task_accepts.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls_stream) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(|_req: hyper::Request<Incoming>| async {
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(Bytes::from_static(H2_BODY))))
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls_stream), service)
                    .await;
            });
        }
    });
    Ok(H2CountingUpstream { addr, accepts, task })
}

#[tokio::test]
async fn reverse_http2_reuses_multiplexed_upstream_connection() -> Result<(), DynError> {
    let upstream = start_h2_counting_upstream().await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_reverse_h2_reuse")?;
    std::fs::create_dir_all(&temp_dir)?;
    let config_path = temp_dir.join("locations.yaml");
    std::fs::write(
        &config_path,
        format!(
            "default_host:\n  - location: /h2/\n    upstream:\n      url_base: https://localhost:{}/\n      version: H2\n",
            upstream.addr.port()
        ),
    )?;
    let proxy = start_proxy(vec![
        "--location-config-file".to_owned(),
        config_path.to_string_lossy().into_owned(),
    ])
    .await?;

    for path in ["/h2/one", "/h2/two"] {
        let (head, body) = request_origin_form(
            proxy.port,
            &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
        )
        .await?;
        assert_ok(&head)?;
        assert_eq!(body, H2_BODY);
    }
    assert_eq!(upstream.accepts.load(Ordering::SeqCst), 1, "reverse proxy should multiplex the HTTP/2 upstream");

    upstream.task.abort();
    proxy.shutdown().await?;
    remove_temp_dir(temp_dir)?;
    Ok(())
}

#[tokio::test]
async fn mitm_h2_upstream_is_multiplexed_across_client_connections() -> Result<(), DynError> {
    let upstream = start_h2_counting_upstream().await?;
    let temp_dir = unique_temp_dir("rust_http_proxy_mitm_h2_reuse")?;
    let ca = write_test_ca(&temp_dir)?;
    let proxy = start_proxy(mitm_args(&ca.cert_path, &ca.key_path, Vec::new())).await?;

    let first = mitm_keep_alive_get(proxy.port, upstream.addr.port(), ca.cert_der.clone()).await?;
    let second = mitm_keep_alive_get(proxy.port, upstream.addr.port(), ca.cert_der).await?;

    assert_eq!(first, H2_BODY);
    assert_eq!(second, H2_BODY);
    assert_eq!(upstream.accepts.load(Ordering::SeqCst), 1, "MITM should multiplex the HTTP/2 upstream");

    upstream.task.abort();
    proxy.shutdown().await?;
    remove_temp_dir(temp_dir)?;
    Ok(())
}
