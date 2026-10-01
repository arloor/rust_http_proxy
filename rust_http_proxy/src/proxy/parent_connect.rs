use std::io::{self, ErrorKind};
use std::time::Duration;

use base64::Engine as _;
use log::debug;
use tokio::io::{AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, BufReader};

use crate::config::ForwardBypassConfig;

use super::connect::{EitherTlsStream, bypass_endpoint, connect_with_preference, into_bypass_stream};
use super::tunnel::dial_timed_tunnel;

pub(crate) struct ParentConnect<'a> {
    pub(crate) target: &'a str,
    pub(crate) client_ip: &'a str,
    pub(crate) username: Option<&'a str>,
    pub(crate) password: Option<&'a str>,
}

/// 只有用户名和密码都配置时才返回 `Basic ...` 凭据。
pub(crate) fn basic_credentials(username: Option<&str>, password: Option<&str>) -> Option<String> {
    let (username, password) = (username?, password?);
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
    Some(format!("Basic {encoded}"))
}

impl ForwardBypassConfig {
    pub(crate) fn proxy_authorization(&self) -> Option<String> {
        basic_credentials(self.username.as_deref(), self.password.as_deref())
    }
}

pub(crate) fn parent_connect_request(connect: ParentConnect<'_>) -> String {
    let mut request = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nX-Forwarded-For: {client_ip}\r\n",
        target = connect.target,
        client_ip = connect.client_ip,
    );
    if let Some(credentials) = basic_credentials(connect.username, connect.password) {
        request.push_str(&format!("Proxy-Authorization: {credentials}\r\n"));
    }
    request.push_str("\r\n");
    request
}

/// 失败发生在哪一步。正向 CONNECT 需要据此区分 502 和直接报错。
pub(crate) enum ParentTunnelError {
    Dial(io::Error),
    Tls(io::Error),
    Handshake(io::Error),
}

impl From<ParentTunnelError> for io::Error {
    fn from(error: ParentTunnelError) -> Self {
        match error {
            ParentTunnelError::Dial(error) | ParentTunnelError::Tls(error) | ParentTunnelError::Handshake(error) => {
                error
            }
        }
    }
}

/// 拨号父代理、按需握 TLS，再发 CONNECT。`wrap` 作用在 CONNECT 之前，
/// 因此在 `wrap` 里套上流量计数就会把握手字节一起计入。
/// `record_dial_duration` 控制是否记录 tunnel_bypass_setup_duration。
pub(crate) async fn open_parent_tunnel<S>(
    config: &ForwardBypassConfig, target: &str, client_ip: &str, record_dial_duration: bool,
    wrap: impl FnOnce(EitherTlsStream) -> S,
) -> Result<BufReader<S>, ParentTunnelError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let endpoint = bypass_endpoint(config);
    let tcp_stream = if record_dial_duration {
        dial_timed_tunnel(&endpoint, config.ipv6_first).await
    } else {
        connect_with_preference(&endpoint, config.ipv6_first).await
    }
    .map_err(ParentTunnelError::Dial)?;
    debug!(
        "[parent tunnel {client_ip} -> {target}], [true path: {endpoint} ({})]",
        tcp_stream
            .peer_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| "failed".to_owned())
    );
    let stream = into_bypass_stream(config, tcp_stream)
        .await
        .map_err(ParentTunnelError::Tls)?;
    complete_parent_connect(
        wrap(stream),
        ParentConnect {
            target,
            client_ip,
            username: config.username.as_deref(),
            password: config.password.as_deref(),
        },
    )
    .await
    .map_err(ParentTunnelError::Handshake)
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_HEAD_BYTES: u64 = 32 * 1024;

/// 保留响应头之后预读的隧道数据，调用方必须继续使用返回的缓冲流。
pub(crate) async fn complete_parent_connect<S>(stream: S, connect: ParentConnect<'_>) -> io::Result<BufReader<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(CONNECT_TIMEOUT, async {
        let mut reader = BufReader::new(stream);
        reader
            .get_mut()
            .write_all(parent_connect_request(connect).as_bytes())
            .await?;
        reader.get_mut().flush().await?;
        // Take 限制解析器可消费的字节；底层预读的隧道数据仍留在 reader 中。
        let mut head = (&mut reader).take(MAX_RESPONSE_HEAD_BYTES);
        let mut line = String::new();
        let mut first = true;
        loop {
            if head.limit() == 0 {
                return Err(io::Error::new(ErrorKind::InvalidData, "bypass CONNECT response headers exceed 32 KiB"));
            }
            line.clear();
            if head.read_line(&mut line).await? == 0 {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "bypass server closed before CONNECT response headers completed",
                ));
            }
            if first {
                if line.split_whitespace().nth(1) != Some("200") {
                    return Err(io::Error::other(format!(
                        "unexpected response from bypass server: {}",
                        line.trim_end()
                    )));
                }
                first = false;
            } else if line == "\r\n" || line == "\n" {
                break;
            }
        }
        Ok(reader)
    })
    .await
    .map_err(|_| io::Error::new(ErrorKind::TimedOut, "bypass CONNECT handshake timed out after 30 seconds"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connect() -> ParentConnect<'static> {
        ParentConnect {
            target: "example.com:443",
            client_ip: "127.0.0.1",
            username: None,
            password: None,
        }
    }

    async fn response_stream(response: &[u8]) -> tokio::io::DuplexStream {
        let (client, mut parent) = tokio::io::duplex(64 * 1024);
        parent.write_all(response).await.unwrap();
        parent.shutdown().await.unwrap();
        // Keep the read half alive until the CONNECT request is written.
        tokio::spawn(async move {
            let mut request = Vec::new();
            let _ = parent.read_to_end(&mut request).await;
        });
        client
    }

    #[tokio::test]
    async fn preserves_coalesced_payload_and_supports_writes() {
        let (client, mut parent) = tokio::io::duplex(4096);
        parent
            .write_all(b"HTTP/1.1 200 OK\r\nX-Test: yes\r\n\r\nSSH-2.0-test\r\n")
            .await
            .unwrap();
        let mut tunnel = complete_parent_connect(client, connect()).await.unwrap();
        let mut banner = [0; 14];
        tunnel.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"SSH-2.0-test\r\n");
        tunnel.write_all(b"ping").await.unwrap();
        let expected = format!("{}ping", parent_connect_request(connect()));
        let mut request = vec![0; expected.len()];
        parent.read_exact(&mut request).await.unwrap();
        assert_eq!(request, expected.as_bytes());
    }

    #[tokio::test]
    async fn rejects_truncated_and_oversized_headers() {
        for response in [
            b"".as_slice(),
            b"HTTP/1.1 200 OK\r\nX-Test: partial",
            b"HTTP/1.1 200 OK\r\n",
        ] {
            let error = complete_parent_connect(response_stream(response).await, connect())
                .await
                .unwrap_err();
            assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
        }
        let mut response = b"HTTP/1.1 200 OK\r\nX-Test: ".to_vec();
        response.resize(MAX_RESPONSE_HEAD_BYTES as usize, b'x');
        let error = complete_parent_connect(response_stream(&response).await, connect())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn header_limit_excludes_tunnel_payload() {
        let mut response = b"HTTP/1.1 200 OK\r\nX-Test: ".to_vec();
        response.resize(MAX_RESPONSE_HEAD_BYTES as usize - 4, b'x');
        response.extend_from_slice(b"\r\n\r\npayload");
        let mut tunnel = complete_parent_connect(response_stream(&response).await, connect())
            .await
            .unwrap();
        let mut payload = Vec::new();
        tunnel.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"payload");
    }

    #[tokio::test(start_paused = true)]
    async fn times_out_waiting_for_response_or_blocked_request_write() {
        for capacity in [1, 4096] {
            let (client, _parent) = tokio::io::duplex(capacity);
            let error = complete_parent_connect(client, connect()).await.unwrap_err();
            assert_eq!(error.kind(), ErrorKind::TimedOut);
        }
    }

    #[test]
    fn parent_connect_request_includes_auth_and_forwarded_for() {
        let request = parent_connect_request(ParentConnect {
            target: "example.com:443",
            client_ip: "203.0.113.5",
            username: Some("proxyuser"),
            password: Some("proxypass"),
        });
        let token = base64::engine::general_purpose::STANDARD.encode(b"proxyuser:proxypass");
        assert_eq!(
            request,
            format!(
                "CONNECT example.com:443 HTTP/1.1\r\n\
Host: example.com:443\r\n\
X-Forwarded-For: 203.0.113.5\r\n\
Proxy-Authorization: Basic {token}\r\n\
\r\n"
            )
        );
    }

    #[test]
    fn parent_connect_request_omits_partial_credentials() {
        let request = parent_connect_request(ParentConnect {
            target: "example.com:443",
            client_ip: "127.0.0.1",
            username: Some("proxyuser"),
            password: None,
        });
        assert_eq!(
            request,
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n"
        );
    }
}
