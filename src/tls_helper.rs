use std::env;
use std::fs::File;
use std::sync::Arc;
use log::{warn};
use rustls_pemfile::Item;
use tls_listener::AsyncTls;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
use tokio_rustls::TlsAcceptor;


pub type Acceptor = TlsAcceptorAdaptor;

// wrap error
type Error = Box<dyn std::error::Error>;

fn tls_config(key: &String, cert: &String) -> Result<Arc<ServerConfig>, Error> {
    use std::io::{self, BufReader};
    let key_file = File::open(key)?;
    let cert_file = File::open(cert)?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())?;
    let key_option = rustls_pemfile::read_one(&mut BufReader::new(key_file))?;
    let key = if let Some(key_item) = key_option {
        match key_item {
            Item::PKCS8Key(bytes) => PrivateKey(bytes),
            Item::ECKey(bytes) => PrivateKey(bytes),
            Item::RSAKey(bytes) => PrivateKey(bytes),
            Item::X509Certificate(_) => return Err("cert in private key file".into()),
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "error read private key".to_string()).into()),
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
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            // info!("new config is {:?}",config);
            Ok(Arc::new(config))
        }
        Err(e) => {
            Err(e.into())
        }
    }
}

pub fn tls_acceptor(raw_key: &String, cert: &String) -> Result<Acceptor, Error> {
    let tls_config = tls_config(&raw_key, &cert)?;
    let tls_acceptor_adaptor = TlsAcceptorAdaptor {
        tls_acceptor: tls_config.into(),
        key: raw_key.to_string(),
        cert: cert.to_string(),
    };
    Ok(tls_acceptor_adaptor)
}

pub fn is_over_tls() -> bool {
    "true" == env::var("over_tls").unwrap_or("false".to_string())
}


/// modified from `tokio_rustls::TlsAcceptor`, which is a wrapper around a `rustls::ServerConfig`, providing an async `accept` method.
/// I provide this struct to read TLS cert and key at every time of accepting.
/// I need this feature because my TLS cert is out of date every 3 months (a limit from acme.sh) and I don't want to restart my server at that situation.
#[derive(Clone)]
pub struct TlsAcceptorAdaptor {
    tls_acceptor: TlsAcceptor,
    key: String,
    cert: String,
}

impl<C: AsyncRead + AsyncWrite + Unpin> AsyncTls<C> for TlsAcceptorAdaptor {
    type Stream = tokio_rustls::server::TlsStream<C>;
    type Error = std::io::Error;
    type AcceptFuture = tokio_rustls::Accept<C>;
    fn accept(&self, conn: C) -> Self::AcceptFuture {
        match tls_config(&self.key, &self.cert) {
            Ok(tls_config) => TlsAcceptor::accept(&tls_config.clone().into(), conn),
            Err(e) => {
                warn!("error read current cert, {:?}",e);
                TlsAcceptor::accept(&self.tls_acceptor, conn)
            }
        }
    }
}
