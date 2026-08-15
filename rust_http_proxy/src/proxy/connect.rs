use std::{io, io::ErrorKind, net::SocketAddr, sync::Arc, time::Duration};

use log::{debug, info, warn};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};

/// 实现 Happy Eyeballs 算法的TCP连接（RFC 6555, RFC 8305）
/// 首先尝试解析所有地址，根据 ipv6_first 参数决定优先级，但会并发尝试以提高连接速度
/// ipv6_first: None 表示使用系统默认顺序，Some(true) 表示 IPv6 优先，Some(false) 表示 IPv4 优先
pub(crate) async fn connect_with_preference(addr: &str, ipv6_first: Option<bool>) -> io::Result<TcpStream> {
    use tokio::net::lookup_host;

    // 解析所有地址
    let addrs: Vec<SocketAddr> = lookup_host(addr).await?.collect();

    if addrs.is_empty() {
        return Err(io::Error::new(ErrorKind::InvalidInput, "No addresses found"));
    }
    let prefer_ipv6 = prefer_ipv6(ipv6_first, &addrs);

    // 分离IPv4和IPv6地址
    let mut v4_addrs = Vec::new();
    let mut v6_addrs = Vec::new();

    for addr in addrs {
        match addr {
            SocketAddr::V4(_) => v4_addrs.push(addr),
            SocketAddr::V6(_) => v6_addrs.push(addr),
        }
    }

    let has_v4 = !v4_addrs.is_empty();
    let has_v6 = !v6_addrs.is_empty();

    // Happy Eyeballs: RFC6555 gives an example that Chrome and Firefox uses 300ms
    const FIXED_DELAY: Duration = Duration::from_millis(300);

    let connect_v4 = async {
        let mut result = None;

        for resolved_addr in v4_addrs {
            debug!("Trying to connect via IPv4: {}", resolved_addr);

            match TcpStream::connect(resolved_addr).await {
                Ok(stream) => {
                    debug!("Connected via IPv4: {}", resolved_addr);
                    result = Some(Ok(stream));
                    break;
                }
                Err(err) => {
                    debug!("Failed to connect to IPv4 address {}: {}", resolved_addr, err);
                    result = Some(Err(err));
                }
            }
        }
        #[allow(clippy::expect_used)]
        result.expect("impossible: v4_addrs is empty")
    };

    let connect_v6 = async {
        let mut result = None;

        for resolved_addr in v6_addrs {
            debug!("Trying to connect via IPv6: {}", resolved_addr);

            match TcpStream::connect(resolved_addr).await {
                Ok(stream) => {
                    debug!("Connected via IPv6: {}", resolved_addr);
                    result = Some(Ok(stream));
                    break;
                }
                Err(err) => {
                    debug!("Failed to connect to IPv6 address {}: {}", resolved_addr, err);
                    result = Some(Err(err));
                }
            }
        }
        #[allow(clippy::expect_used)]
        result.expect("impossible: v6_addrs is empty")
    };

    if has_v4 && !has_v6 {
        connect_v4.await
    } else if !has_v4 && has_v6 {
        connect_v6.await
    } else {
        // 显式配置优先；未配置时遵循 DNS 返回的第一个地址族。
        use futures::future::{self, Either};

        match prefer_ipv6 {
            true => {
                // IPv6 优先：先启动 IPv6，300ms 后并发启动 IPv4
                let v4_fut = async move {
                    tokio::time::sleep(FIXED_DELAY).await;
                    connect_v4.await
                };
                let v6_fut = connect_v6;

                tokio::pin!(v4_fut);
                tokio::pin!(v6_fut);

                match future::select(v4_fut, v6_fut).await {
                    Either::Left((v4_res, v6_fut)) => match v4_res {
                        Ok(stream) => Ok(stream),
                        Err(_v4_err) => v6_fut.await,
                    },
                    Either::Right((v6_res, v4_fut)) => match v6_res {
                        Ok(stream) => Ok(stream),
                        Err(_v6_err) => v4_fut.await,
                    },
                }
            }
            false => {
                // IPv4 优先：先启动 IPv4，300ms 后并发启动 IPv6
                let v6_fut = async move {
                    tokio::time::sleep(FIXED_DELAY).await;
                    connect_v6.await
                };
                let v4_fut = connect_v4;

                tokio::pin!(v4_fut);
                tokio::pin!(v6_fut);

                match future::select(v4_fut, v6_fut).await {
                    Either::Left((v4_res, v6_fut)) => match v4_res {
                        Ok(stream) => Ok(stream),
                        Err(_v4_err) => v6_fut.await,
                    },
                    Either::Right((v6_res, v4_fut)) => match v6_res {
                        Ok(stream) => Ok(stream),
                        Err(_v6_err) => v4_fut.await,
                    },
                }
            }
        }
    }
}

fn prefer_ipv6(configured: Option<bool>, addrs: &[SocketAddr]) -> bool {
    configured.unwrap_or_else(|| addrs.first().is_some_and(SocketAddr::is_ipv6))
}

/// Debug 模式：不验证证书（方便测试）
/// Release 模式：使用平台证书验证器
pub(crate) fn build_tls_connector() -> TlsConnector {
    build_tls_connector_with_alpn(Vec::new())
}

pub(crate) fn build_tls_connector_with_http_alpn() -> TlsConnector {
    build_tls_connector_with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
}

pub(crate) fn build_tls_connector_with_http1_alpn() -> TlsConnector {
    build_tls_connector_with_alpn(vec![b"http/1.1".to_vec()])
}

pub(crate) fn build_tls_connector_with_http2_alpn() -> TlsConnector {
    build_tls_connector_with_alpn(vec![b"h2".to_vec()])
}

fn build_tls_connector_with_alpn(alpn_protocols: Vec<Vec<u8>>) -> TlsConnector {
    #[cfg(debug_assertions)]
    {
        use tokio_rustls::rustls::ClientConfig;

        warn!("⚠️  DEBUG MODE: TLS certificate verification is DISABLED");
        let mut config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        config.alpn_protocols = alpn_protocols;
        TlsConnector::from(Arc::new(config))
    }

    #[cfg(not(debug_assertions))]
    {
        use rustls_platform_verifier::BuilderVerifierExt;
        #[allow(clippy::expect_used)]
        let config = tokio_rustls::rustls::ClientConfig::builder()
            .with_platform_verifier()
            .expect("Failed to create platform verifier")
            .with_no_client_auth();
        let mut config = config;
        config.alpn_protocols = alpn_protocols;
        TlsConnector::from(Arc::new(config))
    }
}

use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{DigitallySignedStruct, SignatureScheme};

#[allow(dead_code)]
#[derive(Debug)]
pub(super) struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], server_name: &ServerName<'_>,
        _ocsp_response: &[u8], _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        // 解析并打印证书信息
        use x509_cert::Certificate;
        use x509_cert::der::Decode;
        if let Ok(cert) = Certificate::from_der(end_entity.as_ref()) {
            let tbs = cert.tbs_certificate();
            info!("🔐 TLS Certificate Info:");
            info!("  Server Name: {:?}", server_name);
            info!("  Subject: {}", tbs.subject());
            info!("  Issuer: {}", tbs.issuer());
            info!("  Serial: {:?}", tbs.serial_number());
            info!("  Valid from: {:?}", tbs.validity().not_before);
            info!("  Valid until: {:?}", tbs.validity().not_after);

            // 打印 Subject Alternative Names
            if let Some(extensions) = tbs.extensions() {
                for ext in extensions.iter() {
                    if ext.extn_id.to_string() == "2.5.29.17" {
                        // SAN OID
                        debug!("  SAN extension found: {} bytes", ext.extn_value.len());
                    }
                }
            }

            info!("  Intermediate certs: {}", intermediates.len());
        } else {
            warn!("Failed to parse certificate for {:?}", server_name);
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

// 用于 forward_bypass 的流枚举，支持 TCP 和 TLS
pin_project_lite::pin_project! {
    #[project = EitherTlsStreamProj]
    pub(crate) enum EitherTlsStream {
        Tcp { #[pin] stream: TcpStream },
        Tls { #[pin] stream: TlsStream<TcpStream> },
    }
}

pin_project_lite::pin_project! {
    #[project = HttpClientStreamProj]
    pub(crate) enum HttpClientStream {
        Direct { #[pin] stream: EitherTlsStream },
        TlsOverProxy { #[pin] stream: TlsStream<EitherTlsStream> },
    }
}

impl tokio::io::AsyncRead for HttpClientStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.project() {
            HttpClientStreamProj::Direct { stream } => stream.poll_read(cx, buf),
            HttpClientStreamProj::TlsOverProxy { stream } => stream.poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for HttpClientStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.project() {
            HttpClientStreamProj::Direct { stream } => stream.poll_write(cx, buf),
            HttpClientStreamProj::TlsOverProxy { stream } => stream.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        match self.project() {
            HttpClientStreamProj::Direct { stream } => stream.poll_flush(cx),
            HttpClientStreamProj::TlsOverProxy { stream } => stream.poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.project() {
            HttpClientStreamProj::Direct { stream } => stream.poll_shutdown(cx),
            HttpClientStreamProj::TlsOverProxy { stream } => stream.poll_shutdown(cx),
        }
    }
}

impl tokio::io::AsyncRead for EitherTlsStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.project() {
            EitherTlsStreamProj::Tcp { stream } => stream.poll_read(cx, buf),
            EitherTlsStreamProj::Tls { stream } => stream.poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for EitherTlsStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.project() {
            EitherTlsStreamProj::Tcp { stream } => stream.poll_write(cx, buf),
            EitherTlsStreamProj::Tls { stream } => stream.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        match self.project() {
            EitherTlsStreamProj::Tcp { stream } => stream.poll_flush(cx),
            EitherTlsStreamProj::Tls { stream } => stream.poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match self.project() {
            EitherTlsStreamProj::Tcp { stream } => stream.poll_shutdown(cx),
            EitherTlsStreamProj::Tls { stream } => stream.poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unspecified_address_family_follows_first_dns_result() -> Result<(), std::net::AddrParseError> {
        let ipv4_first = ["127.0.0.1:80".parse()?, "[::1]:80".parse()?];
        let ipv6_first = ["[::1]:80".parse()?, "127.0.0.1:80".parse()?];

        assert!(!prefer_ipv6(None, &ipv4_first));
        assert!(prefer_ipv6(None, &ipv6_first));
        assert!(prefer_ipv6(Some(true), &ipv4_first));
        assert!(!prefer_ipv6(Some(false), &ipv6_first));
        Ok(())
    }
}
