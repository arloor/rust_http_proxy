use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::{HeaderName, HeaderValue, StatusCode};
use hyper::body::Bytes;
use lru_time_cache::LruCache;
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use serde::Deserialize;
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
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert.der().to_vec())], PrivateKeyDer::Pkcs8(key_der))
            .map_err(to_io_error)?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(config)
    }
}

fn to_io_error(err: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err.to_string())
}

#[derive(Clone, Default)]
pub(crate) struct MitmStubSpecs {
    stubs: Arc<HashMap<String, Vec<MitmStubRule>>>,
}

#[derive(Clone)]
pub(crate) struct MitmStubRule {
    path: String,
    response: MitmStubResponse,
}

#[derive(Clone)]
pub(crate) struct MitmStubResponse {
    pub(crate) status: StatusCode,
    pub(crate) headers: Vec<(HeaderName, HeaderValue)>,
    pub(crate) body: Bytes,
}

#[derive(Deserialize)]
struct MitmStubConfig {
    path: String,
    #[serde(default = "default_status")]
    status: u16,
    #[serde(default)]
    headers: HashMap<String, String>,
    body_file: String,
}

fn default_status() -> u16 {
    200
}

pub(crate) fn parse_mitm_stub_specs(config_file: &Option<String>) -> Result<MitmStubSpecs, crate::DynError> {
    let Some(config_file) = config_file else {
        return Ok(MitmStubSpecs::default());
    };

    let content = fs::read_to_string(config_file)
        .map_err(|e| format!("failed to read MITM stub config file {config_file}: {e}"))?;
    let raw_stubs: HashMap<String, Vec<MitmStubConfig>> = serde_yaml_bw::from_str(&content)
        .map_err(|e| format!("failed to parse MITM stub config file {config_file}: {e}"))?;
    let base_dir = Path::new(config_file).parent().unwrap_or_else(|| Path::new("."));
    let mut stubs = HashMap::new();

    for (authority, rules) in raw_stubs {
        let authority = normalize_authority(&authority);
        if authority.is_empty() {
            return Err("MITM stub authority must not be empty".into());
        }

        let mut parsed_rules = Vec::new();
        for rule in rules {
            let body_path = resolve_relative_path(base_dir, &rule.body_file);
            let body = fs::read(&body_path)
                .map_err(|e| format!("failed to read MITM stub body file {}: {e}", body_path.display()))?;
            let status = StatusCode::from_u16(rule.status)
                .map_err(|e| format!("invalid MITM stub status {} for {authority}{}: {e}", rule.status, rule.path))?;
            let mut headers = Vec::new();
            for (name, value) in rule.headers {
                let header_name = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|e| format!("invalid MITM stub response header name {name}: {e}"))?;
                let header_value = HeaderValue::from_str(&value)
                    .map_err(|e| format!("invalid MITM stub response header value for {name}: {e}"))?;
                headers.push((header_name, header_value));
            }

            parsed_rules.push(MitmStubRule {
                path: rule.path,
                response: MitmStubResponse {
                    status,
                    headers,
                    body: Bytes::from(body),
                },
            });
        }
        stubs.insert(authority, parsed_rules);
    }

    Ok(MitmStubSpecs { stubs: Arc::new(stubs) })
}

impl MitmStubSpecs {
    pub(crate) fn is_empty(&self) -> bool {
        self.stubs.is_empty()
    }

    pub(crate) fn find(&self, authority: &str, path: &str) -> Option<MitmStubResponse> {
        self.stubs
            .get(&normalize_authority(authority))
            .and_then(|rules| rules.iter().find(|rule| rule.path == path))
            .map(|rule| rule.response.clone())
    }
}

fn normalize_authority(authority: &str) -> String {
    authority.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn resolve_relative_path(base_dir: &Path, file_path: &str) -> PathBuf {
    let path = Path::new(file_path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parses_mitm_stub_specs_with_relative_body_file() -> Result<(), crate::DynError> {
        let base_dir = std::env::temp_dir().join(format!(
            "rust_http_proxy_mitm_stub_test_{}_{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&base_dir)?;
        let body_path = base_dir.join("validate.json");
        let config_path = base_dir.join("mitm-stubs.yaml");
        fs::write(&body_path, r#"{"ok":true}"#)?;
        fs::write(
            &config_path,
            r#"
AdminMaxApi.KnowHub.Cloud:443:
  - path: /access-tokens/validate
    status: 201
    headers:
      content-type: application/json
    body_file: validate.json
"#,
        )?;

        let specs = parse_mitm_stub_specs(&Some(config_path.to_string_lossy().into_owned()))?;
        let response = match specs.find("adminmaxapi.knowhub.cloud:443.", "/access-tokens/validate") {
            Some(response) => response,
            None => return Err("expected MITM stub response".into()),
        };

        assert_eq!(response.status, StatusCode::CREATED);
        assert_eq!(response.body, Bytes::from_static(br#"{"ok":true}"#));
        assert_eq!(response.headers.len(), 1);
        assert!(specs.find("adminmaxapi.knowhub.cloud:443", "/other").is_none());

        fs::remove_dir_all(base_dir)?;
        Ok(())
    }

    #[test]
    fn generated_mitm_server_config_advertises_h2_and_http1() -> Result<(), crate::DynError> {
        let base_dir = std::env::temp_dir().join(format!(
            "rust_http_proxy_mitm_alpn_test_{}_{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&base_dir)?;
        let cert_path = base_dir.join("ca.pem");
        let key_path = base_dir.join("ca-key.pem");

        let mut params = CertificateParams::new(Vec::new())?;
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "rust-http-proxy-test-ca");
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;
        fs::write(&cert_path, cert.pem())?;
        fs::write(&key_path, key_pair.serialize_pem())?;

        let authority = MitmAuthority::load(&cert_path.to_string_lossy(), &key_path.to_string_lossy())?;
        let config = authority.server_config_for("example.com")?;
        assert_eq!(config.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);

        fs::remove_dir_all(base_dir)?;
        Ok(())
    }
}
