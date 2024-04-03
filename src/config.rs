use crate::log_x::init_log;
use base64::engine::general_purpose;
use base64::Engine;
use clap::Parser;
use log::{info, warn};
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
pub struct ProxyConfig {
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
    建议开启，否则有被嗅探的风险\n"
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
    pub(crate) tls_config_broadcast: Option<broadcast::Sender<Arc<ServerConfig>>>,
}

impl From<ProxyConfig> for Config {
    fn from(config: ProxyConfig) -> Self {
        let mut basic_auth = HashMap::new();
        for raw_user in config.users {
            let mut user = raw_user.split(':');
            let username = user.next().unwrap_or("").to_string();
            let password = user.next().unwrap_or("").to_string();
            if !username.is_empty() && !password.is_empty() {
                let base64 = general_purpose::STANDARD.encode(raw_user);
                basic_auth.insert(format!("Basic {}", base64), username);
            }
        }
        let tls_config_broadcast = if config.over_tls {
            let (tx, _rx) = broadcast::channel::<Arc<ServerConfig>>(10);
            let tx_clone = tx.clone();
            let key_clone = config.key.clone();
            let cert_clone = config.cert.clone();
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
            cert: config.cert,
            key: config.key,
            basic_auth,
            web_content_path: config.web_content_path,
            referer: config.referer,
            never_ask_for_auth: config.never_ask_for_auth,
            over_tls: config.over_tls,
            hostname: config.hostname,
            port: config.port,
            tls_config_broadcast,
        }
    }
}

pub(crate) fn load_config() -> &'static Config {
    let mut config = ProxyConfig::parse();
    config.hostname = get_hostname();
    if let Err(log_init_error) = init_log(&config.log_dir, &config.log_file) {
        println!("init log error:{}", log_init_error);
        std::process::exit(1);
    }
    info!("log is output to {}/{}", config.log_dir, config.log_file);
    info!("hostname seems to be {}", config.hostname);
    let config = Config::from(config);
    log_config(&config);
    info!(
        "auto close connection after idle for {} seconds",
        IDLE_SECONDS
    );
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
        Ok(output) => String::from_utf8(output.stdout)
            .unwrap_or("unknown".to_string())
            .trim()
            .to_owned(),
        Err(e) => {
            warn!("get hostname error: {}",e);
            "unknown".to_string()
        }
    }
}

#[cfg(windows)]
fn get_hostname() -> String {
    use std::env;
    env::var("HOSTNAME").unwrap_or("unknown".to_string())
}
