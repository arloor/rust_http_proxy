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

use std::fs::File;


use std::sync::Arc;
use log::info;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};


pub type Acceptor = tokio_rustls::TlsAcceptor;

fn tls_acceptor_impl(key: &String, cert: &String) -> Acceptor {
    tls_config(key, cert).into()
}

fn tls_config(key: &String, cert: &String) -> Arc<ServerConfig> {
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

    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    info!("tls config is {:?}",config);
    Arc::new(config)
}

pub fn tls_acceptor(raw_key: &String, cert: &String) -> Acceptor {
    tls_acceptor_impl(raw_key, cert)
}
