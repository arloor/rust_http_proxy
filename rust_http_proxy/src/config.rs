use base64::engine::general_purpose;
use base64::Engine;
use clap::Parser;
use http::Uri;
use ipnetwork::IpNetwork;
use log::{info, warn};
use log_x::init_log;
use std::collections::HashMap;
use std::str::FromStr;

use crate::location::{parse_location_specs, LocationSpecs};
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
    #[arg(short, long, value_name = "WEB_CONTENT_PATH")]
    web_content_path: Option<String>,
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
    #[arg(long, help = "禁止所有静态文件托管/反向代理，避免被嗅探")]
    prohibit_serving: bool,
    #[arg(
        long,
        value_name = "CIDR",
        help = "允许访问静态文件托管的网段白名单，格式为CIDR，例如: 192.168.1.0/24, 10.0.0.0/8\n\
        可以多次指定来允许多个网段\n\
        如设置了prohibit_serving，则此参数无效\n\
        如未设置任何网段，且未设置prohibit_serving，则允许所有IP访问静态文件"
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
}

pub(crate) struct Config {
    pub(crate) cert: String,
    pub(crate) key: String,
    pub(crate) basic_auth: HashMap<String, String>,
    pub(crate) referer_keywords_to_self: Vec<String>,
    pub(crate) never_ask_for_auth: bool,
    pub(crate) serving_control: ServingControl,
    pub(crate) over_tls: bool,
    pub(crate) port: Vec<u16>,
    pub(crate) location_specs: LocationSpecs,
    pub(crate) forward_bypass: Option<ForwardBypassConfig>,
}

pub(crate) struct ForwardBypassConfig {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) is_https: bool,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
}

impl std::fmt::Display for ForwardBypassConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}:{}", if self.is_https { "https" } else { "http" }, self.host, self.port)
    }
}

pub(crate) struct ServingControl {
    pub(crate) prohibit_serving: bool,
    pub(crate) allowed_networks: Vec<IpNetwork>,
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
            }
        });
        let mut basic_auth = HashMap::new();
        for raw_user in param.users {
            let mut user = raw_user.split(':');
            let username = user.next().unwrap_or("").to_string();
            let password = user.next().unwrap_or("").to_string();
            if !username.is_empty() && !password.is_empty() {
                let base64 = general_purpose::STANDARD.encode(raw_user);
                basic_auth.insert(format!("Basic {base64}"), username);
            }
        }
        let location_specs = parse_location_specs(
            &param.location_config_file,
            &param.web_content_path,
            &mut param.append_upstream_url,
            param.enable_github_proxy,
        )?;

        // 处理静态文件托管控制
        // 1. 如果设置了prohibit_serving，则禁止所有静态文件托管
        // 2. 如果会主动询问用户鉴权，且没有设置never_ask_for_auth，也禁止所有静态文件托管
        // 3. 否则根据allow_serving_network参数确定允许的网段
        let prohibit_serving = param.prohibit_serving;
        let mut allowed_networks = Vec::new();

        // 只有在不全局禁止的情况下才解析允许的网段
        if !prohibit_serving && !param.allow_serving_network.is_empty() {
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
            never_ask_for_auth: param.never_ask_for_auth,
            serving_control: ServingControl {
                prohibit_serving,
                allowed_networks,
            },
            over_tls: param.over_tls,
            port: param.port,
            location_specs,
            forward_bypass,
        })
    }
}

pub(crate) fn load_config(param: Param) -> Result<Config, DynError> {
    if let Err(log_init_error) = init_log(&param.log_dir, &param.log_file, "info") {
        return Err(format!("init log error:{log_init_error}").into());
    }
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
    if config.serving_control.prohibit_serving {
        warn!("do not serve web content to avoid being detected!");
    } else {
        info!("Static file serving enabled");
        if !config.serving_control.allowed_networks.is_empty() {
            info!("Only allowing static content access from networks: {:?}", config.serving_control.allowed_networks);
        } else {
            info!("Allowing static content access from all networks");
        }
        if !config.referer_keywords_to_self.is_empty() {
            info!("Referer header to images must contain {:?}", config.referer_keywords_to_self);
        }
    }
    info!("basic auth is {:?}", config.basic_auth);
    if !config.location_specs.locations.is_empty() {
        info!("reverse proxy config: ");
    }
    config.location_specs.locations.iter().for_each(|reverse_proxy_config| {
        for ele in reverse_proxy_config.1 {
            match ele {
                crate::location::LocationConfig::ReverseProxy { location, upstream } => {
                    info!(
                        "    {:<70} -> {}**",
                        format!("http(s)://{}:port{}**", reverse_proxy_config.0, location),
                        upstream.url_base,
                    );
                }
                crate::location::LocationConfig::Serving { location, static_dir } => {
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
