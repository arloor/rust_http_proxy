use std::env;
use std::fs::File;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use log::{info, warn};
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
            Item::X509Certificate(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, "cert in private key file!".to_string()).into()),
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "error read private key".to_string()).into()),
        }
    } else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "error read private key".to_string()).into());
    };


    match ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
    {
        Ok(mut config) => {
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            info!("new config is {:?}",config);
            Ok(Arc::new(config))
        }
        Err(e) => {
            Err(e.into())
        }
    }
}

pub fn tls_acceptor(raw_key: &String, cert: &String) -> Result<Acceptor, Error> {
    info!("init TlsAcceptor {}",if timed_refresh_cert(){
        format!("which will refresh every {} hours",TIMED_REFRESH_INTERVAL_SECS/60/60)
    }else{
        "".to_string()
    });
    let tls_config = tls_config(&raw_key, &cert)?;
    let tls_acceptor_adaptor = TlsAcceptorAdaptor {
        tls_acceptor: tls_config.into(),
        key: raw_key.to_string(),
        cert: cert.to_string(),
        refresh_time: SystemTime::now(),
    };
    Ok(tls_acceptor_adaptor)
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
pub struct TlsAcceptorAdaptor {
    tls_acceptor: TlsAcceptor,
    key: String,
    cert: String,
    refresh_time: SystemTime,
}

const TIMED_REFRESH_INTERVAL_SECS: u64 = 8 * 60 * 60;
const NEXT_REFRESH_INTERVAL_SECS: u64 = 5 * 60;

impl<C: AsyncRead + AsyncWrite + Unpin> AsyncTls<C> for TlsAcceptorAdaptor {
    type Stream = tokio_rustls::server::TlsStream<C>;
    type Error = std::io::Error;
    type AcceptFuture = tokio_rustls::Accept<C>;
    fn accept(&self, conn: C) -> Self::AcceptFuture {
        let now = SystemTime::now();
        let second_since_last_refresh = now.duration_since(self.refresh_time).unwrap_or(Duration::from_secs(0)).as_secs();
        let tls_acceptor = if timed_refresh_cert() && second_since_last_refresh >= TIMED_REFRESH_INTERVAL_SECS {
            self.refresh_and_return_tls_config(now)
        } else {
            self.tls_acceptor.clone()
        };
        TlsAcceptor::accept(&tls_acceptor, conn)
    }
}

impl TlsAcceptorAdaptor {
    fn refresh_and_return_tls_config(&self, now: SystemTime) -> TlsAcceptor {
        match tls_config(&self.key, &self.cert) {
            Ok(tls_config) => {
                // 使用unsafe更新不可变对象的字段
                unsafe {
                    let tls_config_ptr: *mut TlsAcceptor = &self.tls_acceptor as *const _ as *mut _;
                    *tls_config_ptr = tls_config.clone().into();
                    let refresh_time_ptr: *mut SystemTime = &self.refresh_time as *const _ as *mut _;
                    *refresh_time_ptr = now;
                }
                tls_config.into()
            }
            Err(e) => {
                warn!("error refresh cert, error: {}, will refresh in {} seconds",e,NEXT_REFRESH_INTERVAL_SECS);
                // 使用unsafe更新不可变对象的字段
                unsafe {
                    let refresh_time_ptr: *mut SystemTime = &self.refresh_time as *const _ as *mut _;
                    *refresh_time_ptr = now - Duration::from_secs(TIMED_REFRESH_INTERVAL_SECS) + Duration::from_secs(NEXT_REFRESH_INTERVAL_SECS);
                }
                self.tls_acceptor.clone()
            }
        }
    }
}
