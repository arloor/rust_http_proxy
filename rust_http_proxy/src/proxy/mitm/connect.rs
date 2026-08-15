use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    time::Duration,
};

use crate::{METRICS, address::host_addr, config::ForwardBypassConfig};
use {io_x::CounterIO, prom_label::LabelImpl};

use axum::extract::Request;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::{Response, body::Bytes, http, service::service_fn};
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto;
use log::{debug, info, warn};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::pin;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types;

use crate::proxy::connect::{EitherTlsStream, HttpClientStream, build_tls_connector, connect_with_preference};
use crate::proxy::handler::ProxyHandler;
use crate::proxy::http::{empty_body, full_body, get_client_ip};
use crate::proxy::labels::{AccessLabel, TunnelHandshakeLabel};
use crate::proxy::padding::append_random_padding_headers;
use crate::proxy::tunnel::tunnel;

use super::request::{MitmRequestContext, handle_mitm_request};

const MITM_PROTOCOL_PEEK_TIMEOUT: Duration = Duration::from_millis(500);
const MITM_PROTOCOL_PEEK_MAX: usize = 5;

impl ProxyHandler {
    /// 代理CONNECT请求
    /// HTTP/1.1 CONNECT
    pub(crate) fn mitm_proxy(
        &self, req: Request<Incoming>, client_socket_addr: SocketAddr, username: String,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        let Some(addr) = host_addr(req.uri()) else {
            warn!("CONNECT host is not socket addr: {:?}", req.uri());
            let mut resp = Response::new(full_body("CONNECT must be to a socket address"));
            *resp.status_mut() = http::StatusCode::BAD_REQUEST;
            return Ok(resp);
        };
        let Some(mitm_authority) = self.config.mitm_authority.as_ref().cloned() else {
            let mut resp = Response::new(full_body("MITM is not enabled"));
            *resp.status_mut() = http::StatusCode::BAD_REQUEST;
            return Ok(resp);
        };

        let cert_host = addr.host();
        let target = addr.to_string();
        let tls_config = match mitm_authority.server_config_for(&cert_host) {
            Ok(tls_config) => tls_config,
            Err(e) => {
                warn!("[mitm cert error] [{}]: {}", target, e);
                let mut resp = Response::new(full_body("Failed to generate MITM certificate"));
                *resp.status_mut() = http::StatusCode::BAD_GATEWAY;
                return Ok(resp);
            }
        };

        let mitm_proxy_client = self.mitm_proxy_client.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let forward_bypass = self.config.forward_bypass.clone();
        let ipv6_first = self.config.ipv6_first;
        let client_ip = get_client_ip(&req, client_socket_addr);
        let mitm_request_context = MitmRequestContext {
            ipv6_first,
            forward_bypass: forward_bypass.clone(),
            stub_specs: self.config.mitm_stub_specs.clone(),
            stub_http1_client: self.reverse_proxy_http1_client.clone(),
            stub_http2_client: self.reverse_proxy_http2_client.clone(),
            manager: self.mitm_manager.clone(),
        };
        tokio::task::spawn(async move {
            let access_tag = format!("{} -> {}", client_socket_addr.ip().to_canonical(), target);
            let src_upgraded = match hyper::upgrade::on(req).await {
                Ok(src_upgraded) => src_upgraded,
                Err(e) => {
                    warn!("[mitm upgrade error] [{}]: {}", access_tag, e);
                    return;
                }
            };

            let mut src_upgraded = TokioIo::new(src_upgraded);
            let peeked = match read_mitm_protocol_peek(&mut src_upgraded).await {
                Ok(peeked) => peeked,
                Err(e) => {
                    warn!("[mitm protocol peek error] [{}]: [{}] {}", access_tag, e.kind(), e);
                    return;
                }
            };
            if !looks_like_tls_client_hello(&peeked) {
                debug!("[mitm bypass non-HTTPS CONNECT payload] [{}]", access_tag);
                let client_io = PrefixedIo::new(src_upgraded, peeked);
                if let Err(e) = tunnel_mitm_bypass(
                    client_io,
                    &target,
                    client_socket_addr,
                    username,
                    forward_bypass.as_ref(),
                    ipv6_first,
                    client_ip,
                )
                .await
                {
                    warn!("[mitm bypass tunnel error] [{}]: [{}] {}", access_tag, e.kind(), e);
                }
                return;
            }

            let tls_acceptor = TlsAcceptor::from(tls_config);
            let tls_stream = match tls_acceptor.accept(PrefixedIo::new(src_upgraded, peeked)).await {
                Ok(tls_stream) => tls_stream,
                Err(e) => {
                    warn!("[mitm tls accept error] [{}]: {}", access_tag, e);
                    return;
                }
            };

            let service = service_fn(move |req| {
                let mitm_proxy_client = mitm_proxy_client.clone();
                let mitm_request_context = mitm_request_context.clone();
                let target = target.clone();
                let username = username.clone();
                async move {
                    handle_mitm_request(
                        req,
                        mitm_proxy_client,
                        client_socket_addr,
                        target,
                        username,
                        mitm_request_context,
                    )
                    .await
                }
            });

            let mut mitm_server = auto::Builder::new(TokioExecutor::new())
                .preserve_header_case(true)
                .title_case_headers(true);
            mitm_server
                .http2()
                .max_header_list_size(crate::HTTP2_MAX_HEADER_LIST_SIZE);
            let connection = mitm_server.serve_connection_with_upgrades(TokioIo::new(tls_stream), service);
            pin!(connection);
            let result = tokio::select! {
                result = &mut connection => result,
                _ = shutdown_rx.recv() => {
                    info!("[mitm graceful shutdown] [{}]", access_tag);
                    connection.as_mut().graceful_shutdown();
                    match tokio::time::timeout(crate::IDLE_TIMEOUT, &mut connection).await {
                        Ok(result) => result,
                        Err(_) => {
                            warn!("[mitm graceful shutdown timeout] [{}]", access_tag);
                            return;
                        }
                    }
                }
            };
            if let Err(e) = result {
                warn!("[mitm connection error] [{}]: {}", access_tag, e);
            }
        });

        let mut response = Response::new(empty_body());
        append_random_padding_headers(response.headers_mut());
        Ok(response)
    }
}

async fn read_mitm_protocol_peek<T>(stream: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin,
{
    let mut peeked = Vec::with_capacity(MITM_PROTOCOL_PEEK_MAX);
    while peeked.len() < MITM_PROTOCOL_PEEK_MAX {
        let mut byte = [0u8; 1];
        match tokio::time::timeout(MITM_PROTOCOL_PEEK_TIMEOUT, stream.read(&mut byte)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => {
                peeked.push(byte[0]);
                if !could_be_tls_client_hello_prefix(&peeked) {
                    break;
                }
                if looks_like_tls_client_hello(&peeked) {
                    break;
                }
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => break,
        }
    }
    Ok(peeked)
}

fn looks_like_tls_client_hello(bytes: &[u8]) -> bool {
    bytes.len() >= MITM_PROTOCOL_PEEK_MAX && bytes[0] == 0x16 && bytes[1] == 0x03 && bytes[2] <= 0x04
}

fn could_be_tls_client_hello_prefix(bytes: &[u8]) -> bool {
    match bytes {
        [] => true,
        [0x16] => true,
        [0x16, 0x03] => true,
        [0x16, 0x03, minor] => *minor <= 0x04,
        [0x16, 0x03, minor, ..] => *minor <= 0x04,
        _ => false,
    }
}

async fn tunnel_mitm_bypass<U>(
    client_io: U, target: &str, client_socket_addr: SocketAddr, username: String,
    forward_bypass: Option<&ForwardBypassConfig>, ipv6_first: Option<bool>, client_ip: String,
) -> io::Result<()>
where
    U: AsyncRead + AsyncWrite + Unpin,
{
    let target_io = match forward_bypass {
        Some(forward_bypass_config) => {
            connect_forward_bypass_tunnel_target(target, client_socket_addr, username, forward_bypass_config, client_ip)
                .await?
        }
        None => connect_direct_tunnel_target(target, client_socket_addr, username, ipv6_first).await?,
    };
    tunnel(client_io, target_io).await
}

async fn connect_direct_tunnel_target(
    target: &str, client_socket_addr: SocketAddr, username: String, ipv6_first: Option<bool>,
) -> io::Result<CounterIO<HttpClientStream, LabelImpl<AccessLabel>>> {
    let access_label = AccessLabel {
        client: client_socket_addr.ip().to_canonical().to_string(),
        target: target.to_owned(),
        username,
        relay_over_tls: None,
    };
    let start_time = std::time::Instant::now();
    let target_stream = connect_with_preference(target, ipv6_first).await?;
    METRICS
        .tunnel_bypass_setup_duration
        .get_or_create(&LabelImpl::new(TunnelHandshakeLabel {
            target: access_label.target.clone(),
        }))
        .observe(start_time.elapsed().as_millis() as f64);
    debug!(
        "[mitm bypass tunnel {}], [true path: {} -> {}]",
        access_label,
        client_socket_addr.ip().to_canonical().to_string() + ":" + &client_socket_addr.port().to_string(),
        target_stream
            .peer_addr()
            .map(|addr| addr.ip().to_canonical().to_string() + ":" + &addr.port().to_string())
            .unwrap_or("failed".to_owned())
    );
    Ok(CounterIO::new(
        HttpClientStream::Direct {
            stream: EitherTlsStream::Tcp { stream: target_stream },
        },
        METRICS.proxy_traffic.clone(),
        LabelImpl::new(access_label),
    ))
}

async fn connect_forward_bypass_tunnel_target(
    target: &str, client_socket_addr: SocketAddr, username: String, forward_bypass_config: &ForwardBypassConfig,
    client_ip: String,
) -> io::Result<CounterIO<HttpClientStream, LabelImpl<AccessLabel>>> {
    let bypass_host = format!("{}:{}", forward_bypass_config.host, forward_bypass_config.port);
    let access_label = AccessLabel {
        client: client_socket_addr.ip().to_canonical().to_string(),
        target: bypass_host.clone(),
        username,
        relay_over_tls: Some(forward_bypass_config.is_https),
    };
    let start_time = std::time::Instant::now();
    let tcp_stream = connect_with_preference(&bypass_host, forward_bypass_config.ipv6_first).await?;
    METRICS
        .tunnel_bypass_setup_duration
        .get_or_create(&LabelImpl::new(TunnelHandshakeLabel {
            target: access_label.target.clone(),
        }))
        .observe(start_time.elapsed().as_millis() as f64);

    let parent_stream = if forward_bypass_config.is_https {
        let connector = build_tls_connector();
        let server_name = pki_types::ServerName::try_from(forward_bypass_config.host.as_str())
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, format!("Invalid DNS name: {}", e)))?
            .to_owned();
        EitherTlsStream::Tls {
            stream: connector.connect(server_name, tcp_stream).await?,
        }
    } else {
        EitherTlsStream::Tcp { stream: tcp_stream }
    };

    let mut reader = tokio::io::BufReader::new(parent_stream);
    let mut connect_request =
        format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nX-Forwarded-For: {client_ip}\r\n");
    if let (Some(username), Some(password)) = (&forward_bypass_config.username, &forward_bypass_config.password) {
        let credentials = format!("{}:{}", username, password);
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, credentials.as_bytes());
        connect_request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    connect_request.push_str("\r\n");
    reader.get_mut().write_all(connect_request.as_bytes()).await?;

    let mut response_line = String::new();
    reader.read_line(&mut response_line).await?;
    let status_code = response_line.split_whitespace().nth(1).unwrap_or("");
    if status_code != "200" {
        return Err(io::Error::other(format!("unexpected response from bypass server: {response_line}")));
    }

    loop {
        let mut header_line = String::new();
        if reader.read_line(&mut header_line).await? == 0 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "bypass server closed before CONNECT response headers completed",
            ));
        }
        if header_line == "\r\n" || header_line == "\n" {
            break;
        }
    }

    Ok(CounterIO::new(
        HttpClientStream::Direct {
            stream: reader.into_inner(),
        },
        METRICS.proxy_traffic.clone(),
        LabelImpl::new(access_label),
    ))
}

pin_project_lite::pin_project! {
    struct PrefixedIo<T> {
        prefix: std::io::Cursor<Vec<u8>>,
        #[pin]
        inner: T,
    }
}

impl<T> PrefixedIo<T> {
    fn new(inner: T, prefix: Vec<u8>) -> Self {
        Self {
            prefix: std::io::Cursor::new(prefix),
            inner,
        }
    }
}

impl<T> AsyncRead for PrefixedIo<T>
where
    T: AsyncRead,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.project();
        let prefix = this.prefix;
        let prefix_pos = prefix.position() as usize;
        let prefix_remaining = prefix.get_ref().len().saturating_sub(prefix_pos);
        if prefix_remaining > 0 && buf.remaining() > 0 {
            let copy_len = prefix_remaining.min(buf.remaining());
            buf.put_slice(&prefix.get_ref()[prefix_pos..prefix_pos + copy_len]);
            prefix.set_position((prefix_pos + copy_len) as u64);
            return std::task::Poll::Ready(Ok(()));
        }
        this.inner.poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for PrefixedIo<T>
where
    T: AsyncWrite,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}
