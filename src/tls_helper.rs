use crate::DynError;
use std::fs::File;
use std::sync::Arc;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::ServerConfig;

pub fn _rust_tls_acceptor(
    key: &String,
    cert: &String,
) -> Result<tokio_rustls::TlsAcceptor, DynError> {
    Ok(tls_config(key, cert)?.into())
}

pub fn tls_config(key: &String, cert: &String) -> Result<Arc<ServerConfig>, DynError> {
    use std::io::{self, BufReader};
    let key_file = File::open(key).map_err(|_| "open private key failed")?;
    let cert_file = File::open(cert).map_err(|_| "open cert failed")?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<io::Result<Vec<CertificateDer<'static>>>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))?
        .ok_or("can not find any pem in key file")?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    config.alpn_protocols = vec![
        b"h2".to_vec(),       // http2
        b"http/1.1".to_vec(), // http1.1
    ];
    Ok(Arc::new(config))
}
