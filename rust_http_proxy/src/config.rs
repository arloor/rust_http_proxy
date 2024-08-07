use base64::engine::general_purpose;
use base64::Engine;
use clap::Parser;
use http::Version;
use log::{info, warn};
use log_x::init_log;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time;
use tokio_rustls::rustls::ServerConfig;

use crate::tls_helper::tls_config;
use crate::{IDLE_SECONDS, REFRESH_SECONDS};

/// A HTTP proxy server based on Hyper and Rustls, which features TLS proxy and static file serving.
#[derive(Parser)]
#[command(author, version=None, about, long_about = None)]
pub struct Param {
    #[arg(long, value_name = "LOG_DIR", default_value = "/tmp")]
    log_dir: String,
    #[arg(long, value_name = "LOG_FILE", default_value = "proxy.log")]
    log_file: String,
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
        default_value = "",
        help = "默认为空，表示不鉴权。\n\
    格式为 'username:password'\n\
    可以多次指定来实现多用户\n"
    )]
    users: Vec<String>,
    #[arg(
        short,
        long,
        value_name = "WEB_CONTENT_PATH",
        default_value = "/usr/share/nginx/html"
    )]
    web_content_path: String,
    #[arg(
        short,
        long,
        value_name = "REFERER",
        default_value = "",
        help = "Http Referer请求头处理 \n\
    1. 图片资源的防盗链：针对png/jpeg/jpg等文件的请求，要求Request的Referer header要么为空，要么配置的值\n\
    2. 外链访问监控：如果Referer不包含配置的值，并且访问html资源时，Prometheus counter req_from_out++，用于外链访问监控\n"
    )]
    referer: String,
    #[arg(
        long,
        value_name = "ASK_FOR_AUTH",
        help = "if enable, never send '407 Proxy Authentication Required' to client。\n\
    不建议开启，否则有被嗅探的风险\n"
    )]
    never_ask_for_auth: bool,
    #[arg(
        short,
        long,
        value_name = "OVER_TLS",
        help = "if enable, proxy server will listen on https"
    )]
    over_tls: bool,
    #[arg(long, value_name = "HOSTNAME", default_value = "unknown")]
    hostname: String,
    #[arg(
        long,
        value_name = "HOST=>URL[=>VERSION]",
        help = r#"特定的HOST转发到特定的URL，并且使用特定的VERSION。
其中URL必须包含scheme和host。
其中VERSION可以填写HTTP11或者HTTP2，如果不填，则自动推断。一般来说，只在Https网站只支持http/1.1的时候，例如反代https://www.baidu.com，才需要显式设置为HTTP11，其他时候不需要设置。
例如：--reverse-proxy=localhost:7788=>http://example.com # http(s)://localhost:7788转发到http://example.com
例如：--reverse-proxy=localhost:7788=>https://example.com # http(s)://localhost:7788转发到https://example.com
例如：--reverse-proxy=localhost:7788=>https://example.com=>HTTP11 # http(s)://localhost:7788转发到https://example.com，并且使用HTTP/1.1
例如：--reverse-proxy=localhost:7788=>https://example.com/path/to/ # http(s)://localhost:7788/index.html转发到https://example.com/path/to/index.html
"#
    )]
    reverse_proxy: Vec<String>,
}

pub(crate) struct Upstream {
    pub(crate) uri: String,
    pub(crate) version: Option<Version>,
}
pub(crate) struct Config {
    pub(crate) cert: String,
    pub(crate) key: String,
    pub(crate) basic_auth: HashMap<String, String>,
    pub(crate) web_content_path: String,
    pub(crate) referer: String,
    pub(crate) never_ask_for_auth: bool,
    pub(crate) over_tls: bool,
    pub(crate) hostname: String,
    pub(crate) port: Vec<u16>,
    pub(crate) reverse_proxy_map: HashMap<String, Upstream>,
    pub(crate) tls_config_broadcast: Option<broadcast::Sender<Arc<ServerConfig>>>,
}

impl From<Param> for Config {
    fn from(param: Param) -> Self {
        let mut basic_auth = HashMap::new();
        for raw_user in param.users {
            let mut user = raw_user.split(':');
            let username = user.next().unwrap_or("").to_string();
            let password = user.next().unwrap_or("").to_string();
            if !username.is_empty() && !password.is_empty() {
                let base64 = general_purpose::STANDARD.encode(raw_user);
                basic_auth.insert(format!("Basic {}", base64), username);
            }
        }
        let reverse_proxy_map: HashMap<String, Upstream> = param
            .reverse_proxy
            .iter()
            .map(|wrap| {
                let mut wrap = wrap.split("=>");
                let ingress_host = wrap.next().unwrap_or("").to_string();
                let mut upstream = wrap.next().unwrap_or("").to_string();
                if upstream.ends_with('/') {
                    upstream.truncate(upstream.len() - 1);
                }
                let upstream_uri = match http::uri::Uri::from_maybe_shared(upstream) {
                    Ok(uri) => {
                        if uri.scheme().is_none() || uri.authority().is_none() {
                            warn!("invalid reverse proxy target: {}", uri);
                            return (ingress_host, None);
                        }
                        uri
                    }
                    Err(_invalid) => {
                        warn!("invalid reverse proxy target: {}", _invalid);
                        return (ingress_host, None);
                    }
                };
                let version = wrap.next().unwrap_or("").to_string();
                let version = match version.as_str() {
                    "HTTP11" => Some(Version::HTTP_11),
                    "HTTP2" => Some(Version::HTTP_2),
                    _ => None,
                };
                let mut uri = upstream_uri.to_string();
                if uri.ends_with('/') {
                    uri.truncate(uri.len() - 1);
                }
                (ingress_host, Some(Upstream { uri, version }))
            })
            .filter(|(_, upstrea)| upstrea.is_some())
            .map(|entry| {
                (
                    entry.0,
                    entry.1.unwrap_or(Upstream {
                        uri: "".to_string(),
                        version: None,
                    }),
                )
            })
            .collect();
        let tls_config_broadcast = if param.over_tls {
            let (tx, _rx) = broadcast::channel::<Arc<ServerConfig>>(10);
            let tx_clone = tx.clone();
            let key_clone = param.key.clone();
            let cert_clone = param.cert.clone();
            tokio::spawn(async move {
                info!("update tls config every {} seconds", REFRESH_SECONDS);
                loop {
                    time::sleep(Duration::from_secs(REFRESH_SECONDS)).await;
                    if let Ok(new_acceptor) = tls_config(&key_clone, &cert_clone) {
                        info!("update tls config");
                        if let Err(e) = tx_clone.send(new_acceptor) {
                            warn!("send tls config error:{}", e);
                        }
                    }
                }
            });
            Some(tx)
        } else {
            None
        };
        Config {
            cert: param.cert,
            key: param.key,
            basic_auth,
            web_content_path: param.web_content_path,
            referer: param.referer,
            never_ask_for_auth: param.never_ask_for_auth,
            over_tls: param.over_tls,
            hostname: param.hostname,
            port: param.port,
            reverse_proxy_map,
            tls_config_broadcast,
        }
    }
}

pub(crate) fn load_config() -> &'static Config {
    let mut param = Param::parse();
    param.hostname = get_hostname();
    if let Err(log_init_error) = init_log(&param.log_dir, &param.log_file) {
        panic!("init log error:{}", log_init_error);
    }
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
    info!("hostname seems to be {}", param.hostname);
    let config = Config::from(param);
    log_config(&config);
    info!("auto close connection after idle for {IDLE_SECONDS} seconds",);
    return Box::leak(Box::new(config));
}

fn log_config(config: &Config) {
    if !config.basic_auth.is_empty() && !config.never_ask_for_auth {
        warn!("do not serve web content to avoid being detected!");
    } else {
        info!("serve web content of \"{}\"", config.web_content_path);
        if !config.referer.is_empty() {
            info!(
                "Referer header to images must contain \"{}\"",
                config.referer
            );
        }
    }
    info!("basic auth is {:?}", config.basic_auth);
    config
        .reverse_proxy_map
        .iter()
        .for_each(|(ingress, egress)| {
            info!(
                "reverse proxy [{}] => [{}] version: {:?}",
                ingress, egress.uri, egress.version
            );
        });
}

#[cfg(unix)]
fn get_hostname() -> String {
    use std::process::Command;
    let result = Command::new("sh")
        .arg("-c")
        .arg(
            r#"
                hostname
                "#,
        )
        .output();
    match result {
        Ok(output) => {
            let hostname = String::from_utf8(output.stdout)
                .unwrap_or("unknown".to_string())
                .trim()
                .to_owned();
            if hostname.is_empty() {
                get_hostname_from_env()
            } else {
                hostname
            }
        }
        Err(e) => {
            warn!("get hostname error: {}", e);
            "unknown".to_string()
        }
    }
}

#[cfg(windows)]
fn get_hostname() -> String {
    get_hostname_from_env()
}

fn get_hostname_from_env() -> String {
    use std::env;
    env::var("HOSTNAME").unwrap_or("unknown".to_string())
}
