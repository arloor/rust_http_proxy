use std::fs::File;

use std::sync::Arc;
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};


pub type Acceptor = tokio_rustls::TlsAcceptor;

fn tls_acceptor_impl(key: &String, cert: &String) -> Acceptor {
    tls_config(key, cert).into()
}

fn tls_config(key:&String, cert: &String ) -> Arc<ServerConfig> {
    use std::io::{self, BufReader};
    let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(cert).unwrap()))
        .map(|mut certs| certs.drain(..).map(Certificate).collect()).unwrap();
    let mut keys: Vec<PrivateKey> = rustls_pemfile::rsa_private_keys(&mut BufReader::new(File::open(key).unwrap()))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect()).unwrap();
    if keys.len()==0 {
        keys = rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(File::open(key).unwrap()))
            .map(|mut keys| keys.drain(..).map(PrivateKey).collect()).unwrap();
    }
    if keys.len()==0 {
        keys = rustls_pemfile::ec_private_keys(&mut BufReader::new(File::open(key).unwrap()))
            .map(|mut keys| keys.drain(..).map(PrivateKey).collect()).unwrap();
    }

    Arc::new(
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, keys.remove(0))
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
            .unwrap(),
    )
}

pub fn tls_acceptor(raw_key:&String,cert:&String) -> Acceptor {
    tls_acceptor_impl(raw_key, cert)
}
