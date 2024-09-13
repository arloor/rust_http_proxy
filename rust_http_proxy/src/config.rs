use base64::engine::general_purpose;
use base64::Engine;
use clap::Parser;
use log::{info, warn};
use log_x::init_log;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::time;
use tokio_rustls::rustls::ServerConfig;

use crate::reverse::LocationConfig;
use crate::tls_helper::tls_config;
use crate::{DynError, IDLE_TIMEOUT, REFRESH_INTERVAL};

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
    #[arg(long, value_name = "REVERSE_PROXY", help = r#"反向代理配置文件"#)]
    reverse_proxy_config_file: Option<String>,
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
    pub(crate) reverse_proxy_config: HashMap<String, Vec<LocationConfig>>,
    pub(crate) tls_config_broadcast: Option<broadcast::Sender<Arc<ServerConfig>>>,
}

impl TryFrom<Param> for Config {
    type Error = DynError;
    fn try_from(param: Param) -> Result<Self, Self::Error> {
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
        let tls_config_broadcast = if param.over_tls {
            let (tx, _rx) = broadcast::channel::<Arc<ServerConfig>>(10);
            let tx_clone = tx.clone();
            let key_clone = param.key.clone();
            let cert_clone = param.cert.clone();
            tokio::spawn(async move {
                info!("update tls config every {:?}", REFRESH_INTERVAL);
                loop {
                    time::sleep(REFRESH_INTERVAL).await;
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
        let reverse_proxy_config: HashMap<String, Vec<LocationConfig>> =
            match param.reverse_proxy_config_file {
                Some(path) => {
                    let mut result: HashMap<String, Vec<LocationConfig>> =
                        serde_yaml::from_str(&std::fs::read_to_string(path)?)?;
                    result
                        .iter_mut()
                        .for_each(|(_, reverse_proxy_configs)| reverse_proxy_configs.sort());
                    result
                }
                None => HashMap::new(),
            };
        Ok(Config {
            cert: param.cert,
            key: param.key,
            basic_auth,
            web_content_path: param.web_content_path,
            referer: param.referer,
            never_ask_for_auth: param.never_ask_for_auth,
            over_tls: param.over_tls,
            hostname: param.hostname,
            port: param.port,
            reverse_proxy_config,
            tls_config_broadcast,
        })
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
    let config = Config::try_from(param).unwrap();
    log_config(&config);
    info!("auto close connection after idle for {:?}", IDLE_TIMEOUT);
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
    if !config.reverse_proxy_config.is_empty() {
        info!("reverse proxy config: ");
    }
    config
        .reverse_proxy_config
        .iter()
        .for_each(|reverse_proxy_config| {
            for ele in reverse_proxy_config.1 {
                info!(
                    "     {:40} -> {}{}...",
                    format!("{}{}...", reverse_proxy_config.0, ele.location),
                    ele.upstream.scheme_and_authority,
                    ele.upstream.replacement
                );
            }
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
