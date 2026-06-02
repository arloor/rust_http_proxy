use std::io::{self, ErrorKind};
use std::net::{Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser as _;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::pin;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::config::Param;
use crate::{DynError, create_futures};

pub(crate) const WS_PAYLOAD: &[u8] = b"hello-through-proxy";
pub(crate) const SSH_BANNER: &[u8] = b"SSH-2.0-rust-http-proxy-test\r\n";

pub(crate) struct RunningProxy {
    pub(crate) port: u16,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
    task: JoinHandle<Vec<Result<(), io::Error>>>,
}

impl RunningProxy {
    pub(crate) async fn shutdown(self) -> Result<(), DynError> {
        let _ = self.shutdown_tx.send(());
        let results = tokio::time::timeout(Duration::from_secs(5), self.task).await??;
        for result in results {
            result?;
        }
        Ok(())
    }
}

pub(crate) async fn start_proxy(extra_args: Vec<String>) -> Result<RunningProxy, DynError> {
    let port = unused_dual_stack_port()?;
    let mut args = vec![
        "rust_http_proxy".to_owned(),
        "--port".to_owned(),
        port.to_string(),
        "--ipv6-first".to_owned(),
        "false".to_owned(),
    ];
    args.extend(extra_args);
    let param = Param::parse_from(args);
    let (future, shutdown_tx) = create_futures(param)?;
    let task = tokio::spawn(future);
    wait_for_tcp(("127.0.0.1", port)).await?;
    Ok(RunningProxy {
        port,
        shutdown_tx,
        task,
    })
}

pub(crate) struct TestServer {
    pub(crate) addr: SocketAddr,
    pub(crate) task: JoinHandle<Result<(), DynError>>,
}

pub(crate) async fn start_plain_http_server() -> Result<TestServer, DynError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let request_head = read_http_head(&mut stream).await?;
        if !request_head.starts_with("GET /plain HTTP/1.1\r\n") {
            return Err(io::Error::new(ErrorKind::InvalidData, request_head).into());
        }
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
Content-Length: 16\r\n\
Connection: close\r\n\
\r\n\
hello-via-bypass",
            )
            .await?;
        Ok(())
    });
    Ok(TestServer { addr, task })
}

pub(crate) async fn start_tls_http_server() -> Result<TestServer, DynError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let acceptor = TlsAcceptor::from(Arc::new(test_server_tls_config()?));
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut stream = acceptor.accept(stream).await?;
        let request_head = read_http_head(&mut stream).await?;
        if !request_head.starts_with("GET /plain HTTP/1.1\r\n") {
            return Err(io::Error::new(ErrorKind::InvalidData, request_head).into());
        }
        let lower_request_head = request_head.to_ascii_lowercase();
        if lower_request_head.contains("\r\nte: trailers\r\n") || lower_request_head.contains("\r\nhttp2-settings:") {
            return Err(io::Error::new(ErrorKind::InvalidData, request_head).into());
        }
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
Content-Length: 16\r\n\
Connection: close\r\n\
\r\n\
hello-via-bypass",
            )
            .await?;
        Ok(())
    });
    Ok(TestServer { addr, task })
}

pub(crate) async fn start_tls_h2_http_server() -> Result<TestServer, DynError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let mut tls_config = test_server_tls_config()?;
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let tls_stream = acceptor.accept(stream).await?;
        if tls_stream.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err(io::Error::new(ErrorKind::InvalidData, "expected h2 ALPN").into());
        }

        let (done_tx, done_rx) = oneshot::channel();
        let done_tx = Arc::new(Mutex::new(Some(done_tx)));
        let service = service_fn(move |req: Request<Incoming>| {
            let done_tx = done_tx.clone();
            async move {
                let headers_are_sanitized = !req.headers().contains_key(hyper::header::CONNECTION)
                    && !req.headers().contains_key(hyper::header::TRANSFER_ENCODING)
                    && !req.headers().contains_key(hyper::header::UPGRADE)
                    && !req.headers().contains_key("x-remove-for-h2");
                let mut response =
                    if req.version() == hyper::Version::HTTP_2 && req.uri().path() == "/plain" && headers_are_sanitized
                    {
                        Response::new(Full::new(Bytes::from_static(b"hello-via-bypass")))
                    } else {
                        let mut response = Response::new(Full::new(Bytes::from_static(b"bad h2 request")));
                        *response.status_mut() = StatusCode::BAD_REQUEST;
                        response
                    };
                response
                    .headers_mut()
                    .insert(hyper::header::CONTENT_LENGTH, hyper::header::HeaderValue::from_static("16"));
                let maybe_done_tx = done_tx
                    .lock()
                    .map_err(|_| io::Error::other("h2 test done mutex poisoned"))?
                    .take();
                if let Some(done_tx) = maybe_done_tx {
                    let _ = done_tx.send(());
                }
                Ok::<_, io::Error>(response)
            }
        });

        let builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
        let connection = builder.serve_connection(TokioIo::new(tls_stream), service);
        pin!(connection);
        let result = tokio::select! {
            result = &mut connection => result,
            _ = done_rx => {
                connection.as_mut().graceful_shutdown();
                connection.await
            }
        };
        if let Err(err) = result {
            if !is_tls_unexpected_eof(&err) {
                return Err(err.into());
            }
        }
        Ok(())
    });
    Ok(TestServer { addr, task })
}

pub(crate) async fn start_tcp_echo_server() -> Result<TestServer, DynError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = vec![0u8; WS_PAYLOAD.len()];
        stream.read_exact(&mut buf).await?;
        stream.write_all(&buf).await?;
        Ok(())
    });
    Ok(TestServer { addr, task })
}

pub(crate) async fn start_tcp_banner_server() -> Result<TestServer, DynError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        stream.write_all(SSH_BANNER).await?;
        Ok(())
    });
    Ok(TestServer { addr, task })
}

pub(crate) async fn start_websocket_echo_server() -> Result<TestServer, DynError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        serve_websocket_echo(&mut stream).await
    });
    Ok(TestServer { addr, task })
}

pub(crate) async fn start_tls_websocket_echo_server() -> Result<TestServer, DynError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let acceptor = TlsAcceptor::from(Arc::new(test_server_tls_config()?));
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut stream = acceptor.accept(stream).await?;
        serve_websocket_echo(&mut stream).await
    });
    Ok(TestServer { addr, task })
}

pub(crate) struct ForwardBypassProxy {
    pub(crate) addr: SocketAddr,
    connect_rx: tokio::sync::mpsc::Receiver<String>,
    pub(crate) task: JoinHandle<Result<(), DynError>>,
}

pub(crate) async fn start_forward_bypass_proxy() -> Result<ForwardBypassProxy, DynError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let (connect_tx, connect_rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await?;
        let request_head = read_http_head(&mut client).await?;
        let request_line = request_head.lines().next().unwrap_or_default();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default();
        let target = parts.next().unwrap_or_default().to_owned();
        if method != "CONNECT" || target.is_empty() {
            return Err(io::Error::new(ErrorKind::InvalidData, request_head).into());
        }
        connect_tx
            .send(target.clone())
            .await
            .map_err(|_| io::Error::new(ErrorKind::BrokenPipe, "CONNECT target receiver dropped"))?;

        let mut upstream = TcpStream::connect(target.as_str()).await?;
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        Ok(())
    });
    Ok(ForwardBypassProxy { addr, connect_rx, task })
}

pub(crate) async fn recv_connect_target(forward_bypass: &mut ForwardBypassProxy) -> io::Result<String> {
    forward_bypass
        .connect_rx
        .recv()
        .await
        .ok_or_else(|| io::Error::new(ErrorKind::BrokenPipe, "forward bypass CONNECT target channel closed"))
}

pub(crate) struct ForwardRequestProxy {
    pub(crate) addr: SocketAddr,
    target_rx: tokio::sync::mpsc::Receiver<String>,
    pub(crate) task: JoinHandle<Result<(), DynError>>,
}

pub(crate) async fn start_forward_request_proxy() -> Result<ForwardRequestProxy, DynError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let (target_tx, target_rx) = tokio::sync::mpsc::channel(1);
    let task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await?;
        let request_head = read_http_head(&mut client).await?;
        let request_line = request_head.lines().next().unwrap_or_default();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default();
        let target = parts.next().unwrap_or_default().to_owned();
        if method != "GET" || target.is_empty() {
            return Err(io::Error::new(ErrorKind::InvalidData, request_head).into());
        }
        target_tx
            .send(target.clone())
            .await
            .map_err(|_| io::Error::new(ErrorKind::BrokenPipe, "forward request target receiver dropped"))?;

        let (authority, path) = absolute_target_authority_and_path(&target)?;
        let mut upstream = TcpStream::connect(authority.as_str()).await?;
        let is_websocket = request_head.to_ascii_lowercase().contains("upgrade: websocket");
        if is_websocket {
            upstream
                .write_all(
                    format!(
                        "\
GET {path} HTTP/1.1\r\n\
Host: {authority}\r\n\
Connection: Upgrade\r\n\
Upgrade: websocket\r\n\
Sec-WebSocket-Version: 13\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
\r\n"
                    )
                    .as_bytes(),
                )
                .await?;
            let response_head = read_http_head(&mut upstream).await?;
            client.write_all(response_head.as_bytes()).await?;
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        } else {
            upstream
                .write_all(
                    format!(
                        "\
GET {path} HTTP/1.1\r\n\
Host: {authority}\r\n\
Connection: close\r\n\
\r\n"
                    )
                    .as_bytes(),
                )
                .await?;
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
        }
        Ok(())
    });
    Ok(ForwardRequestProxy { addr, target_rx, task })
}

pub(crate) async fn recv_forward_request_target(forward_bypass: &mut ForwardRequestProxy) -> io::Result<String> {
    forward_bypass
        .target_rx
        .recv()
        .await
        .ok_or_else(|| io::Error::new(ErrorKind::BrokenPipe, "forward request target channel closed"))
}

pub(crate) struct TestCa {
    pub(crate) cert_path: PathBuf,
    pub(crate) key_path: PathBuf,
    pub(crate) cert_der: Vec<u8>,
}

pub(crate) fn write_test_ca(base_dir: &Path) -> Result<TestCa, DynError> {
    std::fs::create_dir_all(base_dir)?;
    let mut params = CertificateParams::new(Vec::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "rust-http-proxy-test-ca");
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert_path = base_dir.join("ca.pem");
    let key_path = base_dir.join("ca-key.pem");
    std::fs::write(&cert_path, cert.pem())?;
    std::fs::write(&key_path, key_pair.serialize_pem())?;
    Ok(TestCa {
        cert_path,
        key_path,
        cert_der: cert.der().to_vec(),
    })
}

pub(crate) async fn connect_to_mitm_target(
    proxy_port: u16, upstream_port: u16, ca_cert_der: Vec<u8>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, DynError> {
    connect_to_mitm_target_with_alpn(proxy_port, upstream_port, ca_cert_der, Vec::new()).await
}

pub(crate) async fn connect_to_mitm_target_h2(
    proxy_port: u16, upstream_port: u16, ca_cert_der: Vec<u8>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, DynError> {
    connect_to_mitm_target_with_alpn(proxy_port, upstream_port, ca_cert_der, vec![b"h2".to_vec()]).await
}

async fn connect_to_mitm_target_with_alpn(
    proxy_port: u16, upstream_port: u16, ca_cert_der: Vec<u8>, alpn_protocols: Vec<Vec<u8>>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, DynError> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await?;
    let connect_request = format!(
        "\
CONNECT localhost:{upstream_port} HTTP/1.1\r\n\
Host: localhost:{upstream_port}\r\n\
\r\n"
    );
    stream.write_all(connect_request.as_bytes()).await?;
    assert_ok(&timeout_step("CONNECT response", read_http_head(&mut stream)).await?)?;

    let connector = tls_connector_with_root_and_alpn(ca_cert_der, alpn_protocols)?;
    let server_name = ServerName::try_from("localhost")?.to_owned();
    timeout_step("MITM TLS handshake", connector.connect(server_name, stream))
        .await
        .map_err(Into::into)
}

pub(crate) fn unique_temp_dir(prefix: &str) -> Result<PathBuf, DynError> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(std::env::temp_dir().join(format!("{prefix}_{}_{}", std::process::id(), nanos)))
}

pub(crate) async fn timeout_step<T, E>(
    step: &'static str, future: impl std::future::Future<Output = Result<T, E>>,
) -> io::Result<T>
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    match tokio::time::timeout(Duration::from_secs(5), future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(io::Error::new(ErrorKind::InvalidData, err)),
        Err(_) => Err(io::Error::new(ErrorKind::TimedOut, format!("{step} timed out"))),
    }
}

pub(crate) async fn read_http_head<T>(stream: &mut T) -> io::Result<String>
where
    T: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return String::from_utf8(buf).map_err(|e| io::Error::new(ErrorKind::InvalidData, e));
        }
        if buf.len() > 16 * 1024 {
            return Err(io::Error::new(ErrorKind::InvalidData, "HTTP head is too large"));
        }
    }
}

pub(crate) async fn read_exact_bytes<T>(stream: &mut T, len: usize) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

pub(crate) fn assert_ok(response_head: &str) -> io::Result<()> {
    if response_head.starts_with("HTTP/1.1 200 ") || response_head.starts_with("HTTP/1.0 200 ") {
        Ok(())
    } else {
        Err(io::Error::new(ErrorKind::InvalidData, format!("expected 200 response, got: {response_head}")))
    }
}

pub(crate) fn assert_switching_protocols(response_head: &str) -> io::Result<()> {
    if response_head.starts_with("HTTP/1.1 101 ") || response_head.starts_with("HTTP/1.0 101 ") {
        Ok(())
    } else {
        Err(io::Error::new(ErrorKind::InvalidData, format!("expected 101 response, got: {response_head}")))
    }
}

pub(crate) async fn write_masked_text_frame<T>(stream: &mut T, payload: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin,
{
    if payload.len() > 125 {
        return Err(io::Error::new(ErrorKind::InvalidInput, "test payload is too large"));
    }
    let mask = [0x11, 0x22, 0x33, 0x44];
    let mut frame = Vec::with_capacity(6 + payload.len());
    frame.push(0x81);
    frame.push(0x80 | payload.len() as u8);
    frame.extend_from_slice(&mask);
    for (idx, byte) in payload.iter().enumerate() {
        frame.push(byte ^ mask[idx % mask.len()]);
    }
    stream.write_all(&frame).await
}

pub(crate) async fn read_ws_frame_payload<T>(stream: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] & 0x0f != 0x01 {
        return Err(io::Error::new(ErrorKind::InvalidData, "expected a text websocket frame"));
    }

    let masked = header[1] & 0x80 != 0;
    let len = match header[1] & 0x7f {
        len @ 0..=125 => len as usize,
        126 => {
            let mut extended = [0u8; 2];
            stream.read_exact(&mut extended).await?;
            u16::from_be_bytes(extended) as usize
        }
        127 => return Err(io::Error::new(ErrorKind::InvalidData, "test frame is too large")),
        _ => return Err(io::Error::new(ErrorKind::InvalidData, "invalid websocket frame length")),
    };

    let mut mask = [0u8; 4];
    if masked {
        stream.read_exact(&mut mask).await?;
    }

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    if masked {
        for (idx, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[idx % mask.len()];
        }
    }
    Ok(payload)
}

fn absolute_target_authority_and_path(target: &str) -> io::Result<(String, String)> {
    let uri = target
        .parse::<http::Uri>()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    let host = uri
        .host()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, format!("absolute URI has no host: {target}")))?;
    let port = uri.port_u16().unwrap_or_else(|| match uri.scheme_str() {
        Some("https" | "wss") => 443,
        _ => 80,
    });
    let path = uri
        .path_and_query()
        .map(|path| path.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    Ok((format!("{host}:{port}"), path))
}

async fn serve_websocket_echo<T>(stream: &mut T) -> Result<(), DynError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let request_head = read_http_head(stream).await?;
    if !request_head.starts_with("GET /ws HTTP/1.1\r\n") {
        return Err(io::Error::new(ErrorKind::InvalidData, request_head).into());
    }
    if !request_head.to_ascii_lowercase().contains("upgrade: websocket") {
        return Err(io::Error::new(ErrorKind::InvalidData, request_head).into());
    }

    stream
        .write_all(
            b"HTTP/1.1 101 Switching Protocols\r\n\
Connection: Upgrade\r\n\
Upgrade: websocket\r\n\
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
\r\n",
        )
        .await?;
    let payload = read_ws_frame_payload(stream).await?;
    write_unmasked_text_frame(stream, &payload).await?;
    Ok(())
}

fn test_server_tls_config() -> Result<ServerConfig, DynError> {
    let key_pair = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec!["localhost".to_owned()])?;
    params.distinguished_name.push(DnType::CommonName, "localhost");
    let cert = params.self_signed(&key_pair)?;
    let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(cert.der().to_vec())], PrivateKeyDer::Pkcs8(key_der))
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e).into())
}

fn is_tls_unexpected_eof(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(err);
    while let Some(err) = current {
        if err
            .downcast_ref::<io::Error>()
            .is_some_and(|err| err.kind() == ErrorKind::UnexpectedEof)
            || err.to_string().contains("close_notify")
        {
            return true;
        }
        current = err.source();
    }
    false
}

fn tls_connector_with_root_and_alpn(root_der: Vec<u8>, alpn_protocols: Vec<Vec<u8>>) -> Result<TlsConnector, DynError> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root_der))?;
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn_protocols;
    Ok(TlsConnector::from(Arc::new(config)))
}

fn unused_dual_stack_port() -> io::Result<u16> {
    let listener = std::net::TcpListener::bind((Ipv6Addr::UNSPECIFIED, 0))?;
    listener.local_addr().map(|addr| addr.port())
}

async fn wait_for_tcp(addr: (&str, u16)) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(addr).await {
            Ok(_) => return Ok(()),
            Err(err) if tokio::time::Instant::now() >= deadline => return Err(err),
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
}

async fn write_unmasked_text_frame<T>(stream: &mut T, payload: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin,
{
    if payload.len() > 125 {
        return Err(io::Error::new(ErrorKind::InvalidInput, "test payload is too large"));
    }
    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.push(0x81);
    frame.push(payload.len() as u8);
    frame.extend_from_slice(payload);
    stream.write_all(&frame).await
}
