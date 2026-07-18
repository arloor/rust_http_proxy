use base64::Engine;
use base64::engine::general_purpose;
use clap::Parser;
use http::Uri;
use ipnetwork::IpNetwork;
use log::{info, warn};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use crate::location::{LocationSpecs, parse_location_specs};
use crate::mitm::{MitmAuthority, MitmStubSpecs, parse_mitm_stub_specs};
use crate::{DynError, IDLE_TIMEOUT};

/// A HTTP proxy server based on Hyper and Rustls, which features TLS proxy and static file serving.
#[derive(Parser)]
#[command(author, version=None, about, long_about = None)]
pub struct Param {
    #[arg(long, value_name = "LOG_DIR", default_value = "/tmp")]
    pub log_dir: String,
    #[arg(long, value_name = "LOG_FILE", default_value = "proxy.log")]
    pub log_file: String,
    #[arg(
        short,
        long,
        value_name = "PORT",
        default_value = "3128",
        help = "可以多次指定来实现多端口\n"
    )]
    port: Vec<u16>,
    #[arg(
        long,
        value_name = "IP",
        help = "指定监听 IP，例如 127.0.0.1、0.0.0.0、::1。未指定时默认监听 [::]"
    )]
    host: Option<IpAddr>,
    #[arg(short, long, value_name = "CERT", default_value = "cert.pem")]
    cert: String,
    #[arg(short, long, value_name = "KEY", default_value = "privkey.pem")]
    key: String,
    #[arg(
        short,
        long,
        value_name = "USER",
        help = "默认为空，表示不鉴权。\n\
    格式为 'username:password'\n\
    可以多次指定来实现多用户"
    )]
    users: Vec<String>,
    #[arg(short, long, value_name = "WEB_CONTENT_PATH", help = "静态文件托管的根目录")]
    web_content_path: Option<String>,
    #[arg(
        long,
        value_name = "USER",
        help = "--web-content-path 默认静态资源受保护路径的 Basic 认证用户，独立于 --users。\n\
    格式为 'username:password'\n\
    可以多次指定来实现多用户。不指定 --static-auth-path-prefix 时保护整个默认静态目录"
    )]
    static_auth_users: Vec<String>,
    #[arg(
        long,
        value_name = "PATH_PREFIX",
        help = "静态资源需要 Basic 认证的 URL 路径前缀，例如 /private 或 /downloads/secret\n\
        可以多次指定，命中任意前缀都会要求认证。需要配合 --static-auth-users 使用"
    )]
    static_auth_path_prefix: Vec<String>,
    #[arg(
        long,
        value_name = "SECONDS",
        default_value = "600",
        help = "未被 Basic 认证保护的静态资源响应的 Cache-Control max-age 秒数。\n\
        被认证保护的路径始终返回 Cache-Control: private, no-store，防止 CDN 等共享缓存缓存认证内容"
    )]
    static_cache_max_age: u32,
    #[arg(
        short,
        long,
        value_name = "REFERER",
        help = "Http Referer请求头处理 \n\
        1. 图片资源的防盗链：针对png/jpeg/jpg等文件的请求，要求Request的Referer header要么为空，要么包含配置的值\n\
        2. 外链访问监控：如果Referer不包含配置的值，并且访问html资源时，Prometheus counter req_from_out++，用于外链访问监控\n\
        可以多次指定，也可以不指定"
    )]
    referer_keywords_to_self: Vec<String>,
    #[arg(
        long,
        help = "if enable, never send '407 Proxy Authentication Required' to client。\n\
        当作为正向代理使用时建议开启，否则有被嗅探的风险。"
    )]
    never_ask_for_auth: bool,
    #[arg(
        long,
        value_name = "CIDR",
        help = "允许访问静态文件托管的网段白名单，格式为CIDR，例如: 192.168.1.0/24, 10.0.0.0/8\n\
        可以多次指定来允许多个网段\n\
        如未设置任何网段，则允许所有IP访问静态文件"
    )]
    allow_serving_network: Vec<String>,
    #[arg(short, long, help = "if enable, proxy server will listen on https")]
    over_tls: bool,
    #[arg(long, value_name = "FILE_PATH", help = r#"静态文件托管和反向代理的配置文件"#)]
    location_config_file: Option<String>,
    #[arg(long, help = r#"是否开启github proxy"#)]
    enable_github_proxy: bool,
    #[arg(
        long,
        value_name = "https://example.com",
        help = "便捷反向代理配置\n\
        例如：--append-upstream-url=https://cdnjs.cloudflare.com\n\
        则访问 https://your_domain/https://cdnjs.cloudflare.com 会被代理到 https://cdnjs.cloudflare.com"
    )]
    append_upstream_url: Vec<String>,
    #[arg(
        long,
        value_name = "https://username:password@example.com:123",
        help = "指定上游代理服务器"
    )]
    forward_bypass_url: Option<Uri>,
    #[arg(
        long,
        help = "优先使用 IPv6 进行连接。true表示IPv6优先，false表示IPv4优先，不设置则保持DNS原始顺序"
    )]
    ipv6_first: Option<bool>,
    #[arg(
        long,
        value_name = "SUFFIX",
        help = "允许进行 HTTPS MITM 的域名后缀，可以多次指定。例如 example.com 会匹配 example.com 和 *.example.com"
    )]
    mitm_domain_suffix: Vec<String>,
    #[arg(long, value_name = "CERT", help = "MITM 动态签发证书使用的 CA 证书 PEM 文件")]
    mitm_ca_cert: Option<String>,
    #[arg(long, value_name = "KEY", help = "MITM 动态签发证书使用的 CA 私钥 PEM 文件")]
    mitm_ca_key: Option<String>,
    #[arg(long, help = "打印 MITM 解密后的请求/响应头和 body 前 16KB。仅用于调试")]
    mitm_dump_plaintext: bool,
    #[arg(
        long,
        value_name = "FILE_PATH",
        help = "MITM stub YAML 配置文件，按 authority + path 固定返回响应"
    )]
    mitm_stub_config_file: Option<String>,
}

pub(crate) struct Config {
    pub(crate) cert: String,
    pub(crate) key: String,
    pub(crate) basic_auth: HashMap<String, String>,
    pub(crate) referer_keywords_to_self: Vec<String>,
    pub(crate) static_cache_max_age: u32,
    pub(crate) never_ask_for_auth: bool,
    pub(crate) allow_cidrs: AllowCIRRS,
    pub(crate) over_tls: bool,
    pub(crate) port: Vec<u16>,
    pub(crate) host: Option<IpAddr>,
    pub(crate) location_specs: LocationSpecs,
    pub(crate) forward_bypass: Option<ForwardBypassConfig>,
    pub(crate) ipv6_first: Option<bool>,
    pub(crate) mitm_authority: Option<Arc<MitmAuthority>>,
    pub(crate) mitm_domain_suffixes: Vec<String>,
    pub(crate) mitm_dump_plaintext: bool,
    pub(crate) mitm_stub_specs: MitmStubSpecs,
}

#[derive(Clone)]
pub(crate) struct ForwardBypassConfig {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) is_https: bool,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) ipv6_first: Option<bool>,
}

impl std::fmt::Display for ForwardBypassConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}:{}", if self.is_https { "https" } else { "http" }, self.host, self.port)
    }
}

pub(crate) struct AllowCIRRS(pub(crate) Vec<IpNetwork>);

impl AllowCIRRS {
    pub(crate) fn check_serving_control(&self, client_socket_addr: std::net::SocketAddr) -> Result<(), std::io::Error> {
        use std::io::{Error, ErrorKind};
        // 检查是否有网段限制及客户端IP是否在允许的网段内
        let client_ip = client_socket_addr.ip().to_canonical();
        let allow_cidrs = &self.0;

        if !allow_cidrs.is_empty() {
            let ip_allowed = allow_cidrs.iter().any(|network| network.contains(client_ip));
            if !ip_allowed {
                log::info!("Dropping request from {client_ip} as it's not in allowed networks");
                return Err(Error::new(ErrorKind::PermissionDenied, "IP not in allowed networks"));
            }
        }
        Ok(())
    }
}

impl TryFrom<Param> for Config {
    type Error = DynError;
    fn try_from(mut param: Param) -> Result<Self, Self::Error> {
        // 检测 forward_bypass 的合法性
        if let Some(forward_bypass) = param.forward_bypass_url.as_ref() {
            if forward_bypass.scheme_str() != Some("http") && forward_bypass.scheme_str() != Some("https") {
                return Err("forward_bypass only support http or https scheme".into());
            }
            if forward_bypass.host().is_none() {
                return Err("forward_bypass must have host".into());
            }
        }
        let forward_bypass = param.forward_bypass_url.as_ref().map(|uri| {
            // 从 authority 中提取 username 和 password
            // authority 格式: [userinfo@]host[:port]
            // userinfo 格式: username[:password]
            let (username, password) = uri
                .authority()
                .and_then(|auth| {
                    let auth_str = auth.as_str();
                    if let Some(at_pos) = auth_str.find('@') {
                        let userinfo = &auth_str[..at_pos];
                        if let Some(colon_pos) = userinfo.find(':') {
                            Some((Some(userinfo[..colon_pos].to_string()), Some(userinfo[colon_pos + 1..].to_string())))
                        } else {
                            Some((Some(userinfo.to_string()), None))
                        }
                    } else {
                        None
                    }
                })
                .unwrap_or((None, None));

            ForwardBypassConfig {
                #[allow(clippy::expect_used)]
                host: uri.host().expect("host").to_string(),
                port: uri
                    .port_u16()
                    .unwrap_or_else(|| if uri.scheme_str() == Some("https") { 443 } else { 80 }),
                is_https: uri.scheme_str() == Some("https"),
                username,
                password,
                ipv6_first: param.ipv6_first,
            }
        });
        let basic_auth = parse_basic_auth_users(param.users);
        let static_basic_auth = parse_basic_auth_users(param.static_auth_users.clone());
        if !param.static_auth_path_prefix.is_empty() && static_basic_auth.is_empty() {
            return Err(
                "--static-auth-path-prefix requires at least one valid --static-auth-users username:password".into()
            );
        }
        if (!param.static_auth_users.is_empty() || !param.static_auth_path_prefix.is_empty())
            && param.web_content_path.is_none()
        {
            return Err("--static-auth-users/--static-auth-path-prefix only apply to --web-content-path".into());
        }
        let location_specs = parse_location_specs(
            &param.location_config_file,
            &param.web_content_path,
            param.static_auth_users,
            param.static_auth_path_prefix,
            &mut param.append_upstream_url,
            param.enable_github_proxy,
        )?;
        let mitm_stub_specs = parse_mitm_stub_specs(&param.mitm_stub_config_file)?;

        let mitm_domain_suffixes = normalize_mitm_domain_suffixes(param.mitm_domain_suffix);
        let mitm_authority =
            match (mitm_domain_suffixes.is_empty(), param.mitm_ca_cert.as_ref(), param.mitm_ca_key.as_ref()) {
                (false, Some(ca_cert), Some(ca_key)) => Some(Arc::new(MitmAuthority::load(ca_cert, ca_key)?)),
                (false, _, _) => {
                    return Err("--mitm-domain-suffix requires both --mitm-ca-cert and --mitm-ca-key".into());
                }
                (true, Some(_), _) | (true, _, Some(_)) => {
                    return Err("--mitm-ca-cert/--mitm-ca-key require --mitm-domain-suffix".into());
                }
                (true, None, None) => None,
            };

        let mut allowed_networks = Vec::new();
        if !param.allow_serving_network.is_empty() {
            for network_str in &param.allow_serving_network {
                match IpNetwork::from_str(network_str) {
                    Ok(network) => {
                        allowed_networks.push(network);
                    }
                    Err(e) => {
                        warn!("Invalid network CIDR format: {network_str} - {e}");
                    }
                }
            }
        }

        Ok(Config {
            cert: param.cert,
            key: param.key,
            basic_auth,
            referer_keywords_to_self: param.referer_keywords_to_self,
            static_cache_max_age: param.static_cache_max_age,
            never_ask_for_auth: param.never_ask_for_auth,
            allow_cidrs: AllowCIRRS(allowed_networks),
            over_tls: param.over_tls,
            port: param.port,
            host: param.host,
            location_specs,
            forward_bypass,
            ipv6_first: param.ipv6_first,
            mitm_authority,
            mitm_domain_suffixes,
            mitm_dump_plaintext: param.mitm_dump_plaintext,
            mitm_stub_specs,
        })
    }
}

pub(crate) fn parse_basic_auth_users(raw_users: Vec<String>) -> HashMap<String, String> {
    let mut basic_auth = HashMap::new();
    for raw_user in raw_users {
        let mut user = raw_user.split(':');
        let username = user.next().unwrap_or("").to_string();
        let password = user.next().unwrap_or("").to_string();
        if !username.is_empty() && !password.is_empty() {
            let base64 = general_purpose::STANDARD.encode(raw_user);
            basic_auth.insert(format!("Basic {base64}"), username);
        }
    }
    basic_auth
}

pub(crate) fn normalize_static_auth_path_prefixes(path_prefixes: Vec<String>) -> Vec<String> {
    let mut normalized = Vec::new();
    for raw_path_prefix in path_prefixes {
        let raw_path_prefix = raw_path_prefix.trim();
        if raw_path_prefix.is_empty() {
            warn!("skip empty static auth path prefix");
            continue;
        }
        let path_prefix = if raw_path_prefix.starts_with('/') {
            raw_path_prefix.to_string()
        } else {
            format!("/{raw_path_prefix}")
        };
        if !normalized.contains(&path_prefix) {
            normalized.push(path_prefix);
        }
    }
    normalized
}

fn normalize_mitm_domain_suffixes(suffixes: Vec<String>) -> Vec<String> {
    let mut normalized = Vec::new();
    for suffix in suffixes {
        let suffix = suffix
            .trim()
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if suffix.is_empty() {
            warn!("skip empty MITM domain suffix");
        } else if !normalized.contains(&suffix) {
            normalized.push(suffix);
        }
    }
    normalized
}

pub(crate) fn load_config(param: Param) -> Result<Config, DynError> {
    info!("build time: {}", crate::BUILD_TIME);
    #[cfg(all(feature = "ring", not(feature = "aws_lc_rs")))]
    {
        info!("use ring as default crypto provider");
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    }
    #[cfg(all(feature = "aws_lc_rs", not(feature = "ring")))]
    {
        info!("use aws_lc_rs as default crypto provider");
        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
    let config = Config::try_from(param)?;
    log_config(&config);
    info!("auto close connection after idle for {IDLE_TIMEOUT:?}");
    Ok(config)
}

fn log_config(config: &Config) {
    if !config.allow_cidrs.0.is_empty() {
        info!("Only allowing static content access from networks: {:?}", config.allow_cidrs.0);
    }
    if !config.referer_keywords_to_self.is_empty() {
        info!("Referer header to images must contain {:?}", config.referer_keywords_to_self);
    }
    if config.mitm_authority.is_some() {
        info!("HTTPS MITM is enabled for suffixes: {:?}", config.mitm_domain_suffixes);
    }
    if config.mitm_dump_plaintext {
        info!("MITM plaintext dump is enabled");
    }
    if !config.mitm_stub_specs.is_empty() {
        info!("MITM stubs are enabled");
    }
    if let Some(host) = config.host {
        info!("listen host is {host}");
    }
    info!("basic auth is {:?}", config.basic_auth);
    if !config.location_specs.locations.is_empty() {
        info!("location configs: ");
    }
    config.location_specs.locations.iter().for_each(|reverse_proxy_config| {
        for ele in reverse_proxy_config.1 {
            match ele {
                crate::location::LocationConfig::ReverseProxy { location, upstream, .. } => {
                    info!(
                        "    {:<70} -> {}**",
                        format!("http(s)://{}:port{}**", reverse_proxy_config.0, location),
                        upstream.url_base,
                    );
                }
                crate::location::LocationConfig::Serving {
                    location, static_dir, ..
                } => {
                    info!(
                        "    {:<70} -> static_dir: {}",
                        format!("http(s)://{}:port{}**", reverse_proxy_config.0, location),
                        static_dir,
                    );
                }
            }
        }
    });
}
