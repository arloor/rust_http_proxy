use std::fs;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lru_time_cache::LruCache;
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub(crate) struct MitmAuthority {
    ca_issuer: Issuer<'static, KeyPair>,
    cert_cache: Mutex<LruCache<String, Arc<ServerConfig>>>,
}

impl MitmAuthority {
    pub(crate) fn load(ca_cert_path: &str, ca_key_path: &str) -> Result<Self, crate::DynError> {
        let ca_cert_pem = fs::read_to_string(ca_cert_path)
            .map_err(|e| format!("failed to read MITM CA certificate {ca_cert_path}: {e}"))?;
        let ca_key_pem =
            fs::read_to_string(ca_key_path).map_err(|e| format!("failed to read MITM CA key {ca_key_path}: {e}"))?;
        let ca_key =
            KeyPair::from_pem(&ca_key_pem).map_err(|e| format!("failed to parse MITM CA key {ca_key_path}: {e}"))?;
        let ca_issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key)
            .map_err(|e| format!("failed to parse MITM CA certificate {ca_cert_path}: {e}"))?;

        Ok(Self {
            ca_issuer,
            cert_cache: Mutex::new(LruCache::with_expiry_duration(Duration::from_secs(60 * 60))),
        })
    }

    pub(crate) fn server_config_for(&self, host: &str) -> io::Result<Arc<ServerConfig>> {
        let mut cache = self
            .cert_cache
            .lock()
            .map_err(|_| io::Error::other("MITM certificate cache lock poisoned"))?;
        if let Some(config) = cache.get(host).cloned() {
            return Ok(config);
        }

        let config = Arc::new(self.build_server_config(host)?);
        cache.insert(host.to_owned(), config.clone());
        Ok(config)
    }

    fn build_server_config(&self, host: &str) -> io::Result<ServerConfig> {
        let key_pair = KeyPair::generate().map_err(to_io_error)?;
        let mut params = CertificateParams::new(vec![host.to_owned()]).map_err(to_io_error)?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, host);
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;

        let cert = params.signed_by(&key_pair, &self.ca_issuer).map_err(to_io_error)?;
        let key_der = PrivatePkcs8KeyDer::from(key_pair.serialize_der());
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert.der().to_vec())], PrivateKeyDer::Pkcs8(key_der))
            .map_err(to_io_error)
    }
}

fn to_io_error(err: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err.to_string())
}
