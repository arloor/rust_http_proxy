//！ # tls_helper
// 在 OpenSSL 和其他加密库中，您可能会遇到两种格式的私钥：-----BEGIN RSA PRIVATE KEY----- 和 -----BEGIN PRIVATE KEY-----。这两种格式的主要区别在于它们的编码方式和包含的信息。
//
// -----BEGIN RSA PRIVATE KEY-----：
// 这种格式表示私钥是按照 PKCS#1 标准编码的。它仅包含用于 RSA 算法的私钥信息，不包含其他元数据。文件的内容是一个以 Base64 编码的 DER（Distinguished Encoding Rules）表示的 ASN.1（Abstract Syntax Notation One）结构。通常，这种私钥格式仅适用于 RSA 密钥。
//
// -----BEGIN PRIVATE KEY-----：
// 这种格式表示私钥是按照 PKCS#8 标准编码的。与 PKCS#1 不同，PKCS#8 可以用于多种类型的密钥（如 RSA、DSA、EC），并提供了更通用的编码结构。这种格式的私钥包含关于密钥类型和算法的附加信息。与 PKCS#1 类似，文件的内容也是一个以 Base64 编码的 DER 表示的 ASN.1 结构。
//
// 总结一下，-----BEGIN RSA PRIVATE KEY----- 是特定于 RSA 的 PKCS#1 格式的私钥，而 -----BEGIN PRIVATE KEY----- 是更通用的 PKCS#8 格式的私钥，可用于多种加密算法。尽管两者之间有区别，但在实际使用中，许多加密库和工具都可以处理这两种格式。

use std::env;
use std::fs::File;


use std::sync::Arc;
use std::time::{Duration, SystemTime};
use log::{info, warn};
use tls_listener::AsyncTls;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};


pub type Acceptor = MyTlsAcceptor;

fn tls_acceptor_impl(key: &String, cert: &String) -> Acceptor {
    info!("init TlsAcceptor {}",if timed_refresh_cert(){
        format!("which will refresh every {} hours",TIMED_REFRESH_INTERVAL_SECS/60/60)
    }else{
        "".to_string()
    });
    MyTlsAcceptor {
        tls_config: tls_config(&key, &cert).unwrap(),
        key: key.to_string(),
        cert: cert.to_string(),
        refresh_time: SystemTime::now(),
    }
}

fn tls_config(key: &String, cert: &String) -> Option<Arc<ServerConfig>> {
    use std::io::{self, BufReader};
    let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(cert).unwrap()))
        .map(|mut certs| certs.drain(..).map(Certificate).collect()).unwrap();
    // 读取私钥
    // 读取 PKCS#1 格式 -----BEGIN RSA PRIVATE KEY-----
    let mut keys: Vec<PrivateKey> = rustls_pemfile::rsa_private_keys(&mut BufReader::new(File::open(key).unwrap()))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect()).unwrap();
    // 读取 PKCS#8 格式 -----BEGIN PRIVATE KEY-----
    if keys.len() == 0 {
        keys = rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(File::open(key).unwrap()))
            .map(|mut keys| keys.drain(..).map(PrivateKey).collect()).unwrap();
    }
    if keys.len() == 0 {
        keys = rustls_pemfile::ec_private_keys(&mut BufReader::new(File::open(key).unwrap()))
            .map(|mut keys| keys.drain(..).map(PrivateKey).collect()).unwrap();
    }
    if keys.len() == 0 {
        return None;
    }

    if let Ok(mut config) = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err)) {
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        info!("current rustls config is: {:?}",config);
        Some(Arc::new(config))
    } else {
        None
    }
}

pub fn tls_acceptor(raw_key: &String, cert: &String) -> Acceptor {
    tls_acceptor_impl(raw_key, cert)
}

pub fn is_over_tls() -> bool {
    "true" == env::var("over_tls").unwrap_or("false".to_string())
}

fn timed_refresh_cert() -> bool {
    "true" == env::var("timed_refresh_cert").unwrap_or("true".to_string())
}

/// modified from `tokio_rustls::TlsAcceptor`, which is a wrapper around a `rustls::ServerConfig`, providing an async `accept` method.
/// I provide this struct to read TLS cert and key at every time of accepting.
/// I need this feature because my TLS cert is out of date every 3 months (a limit from acme.sh) and I don't want to restart my server at that situation.
#[derive(Clone)]
pub struct MyTlsAcceptor {
    tls_config: Arc<ServerConfig>,
    key: String,
    cert: String,
    refresh_time: SystemTime,
}

const TIMED_REFRESH_INTERVAL_SECS: u64 = 24 * 60 * 60;// 一天
const NEXT_REFRESH_INTERVAL_SECS: u64 = 60; // 一分钟

impl<C: AsyncRead + AsyncWrite + Unpin> AsyncTls<C> for MyTlsAcceptor {
    type Stream = tokio_rustls::server::TlsStream<C>;
    type Error = std::io::Error;
    type AcceptFuture = tokio_rustls::Accept<C>;
    fn accept(&self, conn: C) -> Self::AcceptFuture {
        let now = SystemTime::now();
        let second_since_last_refresh = now.duration_since(self.refresh_time).unwrap_or(Duration::from_secs(0)).as_secs();
        let tls_config = if timed_refresh_cert() && second_since_last_refresh >= TIMED_REFRESH_INTERVAL_SECS {
            match tls_config(&self.key, &self.cert) {
                Some(tls_config) => {
                    // 使用unsafe更新不可变对象的字段
                    unsafe {
                        let tls_config_ptr: *mut Arc<ServerConfig> = &self.tls_config as *const _ as *mut _;
                        *tls_config_ptr = tls_config.clone();
                        let refresh_time_ptr: *mut SystemTime = &self.refresh_time as *const _ as *mut _;
                        *refresh_time_ptr = now;
                    }
                    tls_config.clone()
                }
                None => {
                    warn!("error refresh cert, will refresh in {} seconds",NEXT_REFRESH_INTERVAL_SECS);
                    // 使用unsafe更新不可变对象的字段
                    unsafe {
                        let refresh_time_ptr: *mut SystemTime = &self.refresh_time as *const _ as *mut _;
                        *refresh_time_ptr = now - Duration::from_secs(TIMED_REFRESH_INTERVAL_SECS) + Duration::from_secs(NEXT_REFRESH_INTERVAL_SECS);
                    }
                    self.tls_config.clone()
                }
            }
        } else {
            self.tls_config.clone()
        };
        tokio_rustls::TlsAcceptor::accept(&tls_config.clone().into(), conn)
    }
}
