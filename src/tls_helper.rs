use rustls_pemfile::Item;
use std::fs::File;
use std::sync::Arc;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};

// wrap error
type Error = Box<dyn std::error::Error>;

pub fn rust_tls_acceptor(key: &String, cert: &String) -> Result<tokio_rustls::TlsAcceptor, Error> {
    return Ok(tls_config(key, cert)?.into());
}

pub fn tls_config(key: &String, cert: &String) -> Result<Arc<ServerConfig>, Error> {
    use std::io::{self, BufReader};
    let key_file =
        File::open(key).map_err(|_| <&str as Into<Error>>::into("open private key failed"))?;
    let cert_file =
        File::open(cert).map_err(|_| <&str as Into<Error>>::into("open cert failed"))?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())?;
    let key_option = rustls_pemfile::read_one(&mut BufReader::new(key_file))?;
    let key = if let Some(key_item) = key_option {
        match key_item {
            Item::PKCS8Key(bytes) => PrivateKey(bytes),
            Item::ECKey(bytes) => PrivateKey(bytes),
            Item::RSAKey(bytes) => PrivateKey(bytes),
            Item::X509Certificate(_) => return Err("cert in private key file".into()),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "error read private key".to_string(),
                )
                .into())
            }
        }
    } else {
        return Err("can not find any pem in key file".into());
    };

    match ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
    {
        Ok(mut config) => {
            config.alpn_protocols = vec![
                b"h2".to_vec(),       // http2
                b"http/1.1".to_vec(), // http1.1
            ];
            Ok(Arc::new(config))
        }
        Err(e) => Err(e.into()),
    }
}
