use std::io::{self, ErrorKind};
use std::net::{Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser as _;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::DynError;
use crate::config::Param;
use crate::create_futures;

const WS_PAYLOAD: &[u8] = b"hello-through-proxy";

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

    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await?;
    let connect_request = format!(
        "\
CONNECT localhost:{} HTTP/1.1\r\n\
Host: localhost:{}\r\n\
\r\n",
        upstream.addr.port(),
        upstream.addr.port()
    );
    stream.write_all(connect_request.as_bytes()).await?;
    assert_ok(&timeout_step("CONNECT response", read_http_head(&mut stream)).await?)?;

    let connector = tls_connector_with_root(ca.cert_der)?;
    let server_name = ServerName::try_from("localhost")?.to_owned();
    let mut tls_stream = timeout_step("MITM TLS handshake", connector.connect(server_name, stream)).await?;
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

struct RunningProxy {
    port: u16,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
    task: JoinHandle<Vec<Result<(), io::Error>>>,
}

impl RunningProxy {
    async fn shutdown(self) -> Result<(), DynError> {
        let _ = self.shutdown_tx.send(());
        let results = tokio::time::timeout(Duration::from_secs(5), self.task).await??;
        for result in results {
            result?;
        }
        Ok(())
    }
}

async fn start_proxy(extra_args: Vec<String>) -> Result<RunningProxy, DynError> {
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

struct WebsocketEchoServer {
    addr: SocketAddr,
    task: JoinHandle<Result<(), DynError>>,
}

async fn start_websocket_echo_server() -> Result<WebsocketEchoServer, DynError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        serve_websocket_echo(&mut stream).await
    });
    Ok(WebsocketEchoServer { addr, task })
}

async fn start_tls_websocket_echo_server() -> Result<WebsocketEchoServer, DynError> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let acceptor = TlsAcceptor::from(Arc::new(test_server_tls_config()?));
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let mut stream = acceptor.accept(stream).await?;
        serve_websocket_echo(&mut stream).await
    });
    Ok(WebsocketEchoServer { addr, task })
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

struct TestCa {
    cert_path: PathBuf,
    key_path: PathBuf,
    cert_der: Vec<u8>,
}

fn write_test_ca(base_dir: &Path) -> Result<TestCa, DynError> {
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

fn tls_connector_with_root(root_der: Vec<u8>) -> Result<TlsConnector, DynError> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root_der))?;
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
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

async fn timeout_step<T, E>(
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

fn unique_temp_dir(prefix: &str) -> Result<PathBuf, DynError> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(std::env::temp_dir().join(format!("{prefix}_{}_{}", std::process::id(), nanos)))
}

async fn read_http_head<T>(stream: &mut T) -> io::Result<String>
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

fn assert_ok(response_head: &str) -> io::Result<()> {
    if response_head.starts_with("HTTP/1.1 200 ") || response_head.starts_with("HTTP/1.0 200 ") {
        Ok(())
    } else {
        Err(io::Error::new(ErrorKind::InvalidData, format!("expected 200 response, got: {response_head}")))
    }
}

fn assert_switching_protocols(response_head: &str) -> io::Result<()> {
    if response_head.starts_with("HTTP/1.1 101 ") || response_head.starts_with("HTTP/1.0 101 ") {
        Ok(())
    } else {
        Err(io::Error::new(ErrorKind::InvalidData, format!("expected 101 response, got: {response_head}")))
    }
}

async fn write_masked_text_frame<T>(stream: &mut T, payload: &[u8]) -> io::Result<()>
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

async fn read_ws_frame_payload<T>(stream: &mut T) -> io::Result<Vec<u8>>
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
