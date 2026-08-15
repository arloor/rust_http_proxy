use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::{HeaderName, HeaderValue, StatusCode, Uri};
use hyper::body::Bytes;
use lru_time_cache::LruCache;
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use serde::Deserialize;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::location::{Upstream, Version, validate_tls_server_name};

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
    action: MitmStubAction,
}

#[derive(Clone)]
pub(crate) enum MitmStubAction {
    Static(MitmStubResponse),
    Dynamic(MitmDynamicStub),
}

#[derive(Clone)]
pub(crate) struct MitmStubResponse {
    pub(crate) status: StatusCode,
    pub(crate) headers: Vec<(HeaderName, HeaderValue)>,
    pub(crate) body: Bytes,
}

#[derive(Clone)]
pub(crate) struct MitmDynamicStub {
    pub(crate) upstream: Upstream,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum MitmStubUpstreamConfig {
    Url(String),
    Detailed(Upstream),
}

#[derive(Deserialize)]
struct MitmStubConfig {
    path: String,
    status: Option<u16>,
    #[serde(default)]
    headers: HashMap<String, String>,
    body_file: Option<String>,
    upstream: Option<MitmStubUpstreamConfig>,
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
            if !rule.path.starts_with('/') {
                return Err(format!("MITM stub path must start with '/' for {authority}: {}", rule.path).into());
            }
            let action = match (rule.body_file, rule.upstream) {
                (Some(body_file), None) => {
                    let body_path = resolve_relative_path(base_dir, &body_file);
                    let body = fs::read(&body_path)
                        .map_err(|e| format!("failed to read MITM stub body file {}: {e}", body_path.display()))?;
                    let status_code = rule.status.unwrap_or(200);
                    let status = StatusCode::from_u16(status_code).map_err(|e| {
                        format!("invalid MITM stub status {status_code} for {authority}{}: {e}", rule.path)
                    })?;
                    let mut headers = Vec::new();
                    for (name, value) in rule.headers {
                        let header_name = HeaderName::from_bytes(name.as_bytes())
                            .map_err(|e| format!("invalid MITM stub response header name {name}: {e}"))?;
                        let header_value = HeaderValue::from_str(&value)
                            .map_err(|e| format!("invalid MITM stub response header value for {name}: {e}"))?;
                        headers.push((header_name, header_value));
                    }
                    MitmStubAction::Static(MitmStubResponse {
                        status,
                        headers,
                        body: Bytes::from(body),
                    })
                }
                (None, Some(upstream)) => {
                    if rule.status.is_some() || !rule.headers.is_empty() {
                        return Err(format!(
                            "dynamic MITM stub for {authority}{} must not set status or headers",
                            rule.path
                        )
                        .into());
                    }
                    let upstream = parse_dynamic_stub_upstream(upstream, &authority, &rule.path)?;
                    MitmStubAction::Dynamic(MitmDynamicStub { upstream })
                }
                (Some(_), Some(_)) => {
                    return Err(format!(
                        "MITM stub for {authority}{} must set exactly one of body_file or upstream",
                        rule.path
                    )
                    .into());
                }
                (None, None) => {
                    return Err(format!(
                        "MITM stub for {authority}{} must set exactly one of body_file or upstream",
                        rule.path
                    )
                    .into());
                }
            };

            parsed_rules.push(MitmStubRule {
                path: rule.path,
                action,
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

    pub(crate) fn find(&self, authority: &str, path: &str) -> Option<MitmStubAction> {
        self.stubs
            .get(&normalize_authority(authority))
            .and_then(|rules| rules.iter().find(|rule| rule.path == path))
            .map(|rule| rule.action.clone())
    }
}

fn parse_dynamic_stub_upstream(
    upstream: MitmStubUpstreamConfig, authority: &str, path: &str,
) -> Result<Upstream, crate::DynError> {
    let mut upstream = match upstream {
        MitmStubUpstreamConfig::Url(url_base) => Upstream {
            url_base,
            // Preserve the original dynamic-stub behavior for the shorthand:
            // plaintext H1 with the intercepted request's virtual host.
            version: Version::H1,
            connect_to: None,
            tls_server_name: None,
            authority: Some("#{host}".to_owned()),
            headers: None,
        },
        MitmStubUpstreamConfig::Detailed(upstream) => upstream,
    };
    let uri = upstream
        .url_base
        .parse::<Uri>()
        .map_err(|e| format!("invalid dynamic MITM stub upstream {} for {authority}{path}: {e}", upstream.url_base))?;
    if !matches!(uri.scheme_str(), Some("http" | "https")) {
        return Err(format!(
            "dynamic MITM stub upstream for {authority}{path} must use http or https: {}",
            upstream.url_base
        )
        .into());
    }
    if uri.authority().is_none() {
        return Err(format!(
            "dynamic MITM stub upstream for {authority}{path} must have an authority: {}",
            upstream.url_base
        )
        .into());
    }
    if uri.query().is_some() {
        return Err(format!(
            "dynamic MITM stub upstream for {authority}{path} must not contain a query: {}",
            upstream.url_base
        )
        .into());
    }
    if upstream.connect_to.as_deref() == Some("#{host}") {
        return Err(format!(
            "dynamic MITM stub connect_to must be a static host or IP for {authority}{path}; #{{host}} is not allowed"
        )
        .into());
    }
    if let Some(connect_to) = upstream.connect_to.as_deref() {
        connect_to
            .parse::<http::uri::Authority>()
            .map_err(|error| format!("invalid dynamic MITM stub connect_to for {authority}{path}: {error}"))?;
    }
    if let Some(configured_authority) = upstream.authority.as_deref().filter(|value| *value != "#{host}") {
        configured_authority
            .parse::<http::uri::Authority>()
            .map_err(|error| format!("invalid dynamic MITM stub authority for {authority}{path}: {error}"))?;
    }
    if upstream.tls_server_name.as_deref() == Some("#{host}") {
        return Err(format!(
            "dynamic MITM stub tls_server_name must be static for {authority}{path}; #{{host}} is not allowed"
        )
        .into());
    }
    if let Some(tls_server_name) = upstream.tls_server_name.as_deref() {
        validate_tls_server_name(tls_server_name)
            .map_err(|error| format!("invalid dynamic MITM stub tls_server_name for {authority}{path}: {error}"))?;
    }
    // build_upstream_req appends the original path, so normalize the prefix to
    // avoid producing a double slash when url_base ends in '/'.
    upstream.url_base = upstream.url_base.trim_end_matches('/').to_owned();
    Ok(upstream)
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
            Some(MitmStubAction::Static(response)) => response,
            Some(MitmStubAction::Dynamic(_)) => return Err("expected static MITM stub response".into()),
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
    fn parses_dynamic_mitm_stub_upstream() -> Result<(), crate::DynError> {
        let base_dir = std::env::temp_dir().join(format!(
            "rust_http_proxy_dynamic_mitm_stub_test_{}_{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&base_dir)?;
        let config_path = base_dir.join("mitm-stubs.yaml");
        fs::write(
            &config_path,
            r#"
api.example.com:443:
  - path: /v1/profile
    upstream: http://127.0.0.1:9010/stub
"#,
        )?;

        let specs = parse_mitm_stub_specs(&Some(config_path.to_string_lossy().into_owned()))?;
        let upstream = match specs.find("api.example.com:443", "/v1/profile") {
            Some(MitmStubAction::Dynamic(stub)) => stub.upstream,
            Some(MitmStubAction::Static(_)) => return Err("expected dynamic MITM stub".into()),
            None => return Err("expected MITM stub".into()),
        };
        assert_eq!(upstream.url_base, "http://127.0.0.1:9010/stub");
        assert_eq!(upstream.version, Version::H1);
        assert_eq!(upstream.authority.as_deref(), Some("#{host}"));

        fs::remove_dir_all(base_dir)?;
        Ok(())
    }

    #[test]
    fn parses_detailed_https_dynamic_mitm_stub_upstream() -> Result<(), crate::DynError> {
        let base_dir = std::env::temp_dir().join(format!(
            "rust_http_proxy_dynamic_mitm_stub_https_test_{}_{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&base_dir)?;
        let config_path = base_dir.join("mitm-stubs.yaml");
        fs::write(
            &config_path,
            r#"
api.example.com:443:
  - path: /v1/profile
    upstream:
      url_base: https://physical.invalid:9443/stub/
      connect_to: 127.0.0.1:9010
      tls_server_name: localhost
      authority: virtual.example.test
      version: H2
      headers:
        x-stub: detailed
"#,
        )?;

        let specs = parse_mitm_stub_specs(&Some(config_path.to_string_lossy().into_owned()))?;
        let upstream = match specs.find("api.example.com:443", "/v1/profile") {
            Some(MitmStubAction::Dynamic(stub)) => stub.upstream,
            Some(MitmStubAction::Static(_)) => return Err("expected dynamic MITM stub".into()),
            None => return Err("expected MITM stub".into()),
        };
        assert_eq!(upstream.url_base, "https://physical.invalid:9443/stub");
        assert_eq!(upstream.connect_to.as_deref(), Some("127.0.0.1:9010"));
        assert_eq!(upstream.tls_server_name.as_deref(), Some("localhost"));
        assert_eq!(upstream.authority.as_deref(), Some("virtual.example.test"));
        assert_eq!(upstream.version, Version::H2);
        assert_eq!(
            upstream
                .headers
                .as_ref()
                .and_then(|headers| headers.get("x-stub"))
                .map(String::as_str),
            Some("detailed")
        );

        fs::remove_dir_all(base_dir)?;
        Ok(())
    }

    #[test]
    fn rejects_dynamic_mitm_request_host_as_connection_or_tls_target() {
        for (field, value) in [("connect_to", "#{host}"), ("tls_server_name", "#{host}")] {
            let upstream = MitmStubUpstreamConfig::Detailed(Upstream {
                url_base: "https://backend.example/".to_owned(),
                version: Version::H1,
                connect_to: (field == "connect_to").then(|| value.to_owned()),
                tls_server_name: (field == "tls_server_name").then(|| value.to_owned()),
                authority: None,
                headers: None,
            });

            let error = match parse_dynamic_stub_upstream(upstream, "api.example:443", "/") {
                Ok(_) => panic!("request Host must not control connection routing"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("is not allowed"));
        }
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
