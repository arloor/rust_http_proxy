use http::header::LOCATION;
use http::{header, HeaderValue, Request, Response, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt as _;
use hyper::body::Bytes;
use hyper::body::Incoming;
use hyper_util::client::legacy::{self, connect::HttpConnector};
use log::info;
use log::warn;
use prom_label::LabelImpl;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::LazyLock;
use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
};

use crate::config::{Config, Param};
use crate::ip_x::SocketAddrFormat;
use crate::proxy::ReverseProxyReqLabel;
use crate::proxy::SchemeHostPort;
use crate::METRICS;

pub(crate) struct RedirectBackpaths {
    pub(crate) redirect_url: String,
    pub(crate) host: String,
    pub(crate) location: String,
}

pub(crate) const DEFAULT_HOST: &str = "default_host";
const GITHUB_URL_BASE: [&str; 5] = [
    "https://github.com",
    "https://gist.githubusercontent.com",
    "https://gist.github.com",
    "https://objects.githubusercontent.com",
    "https://raw.githubusercontent.com",
];

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub(crate) struct LocationConfig {
    #[serde(default = "root")]
    pub(crate) location: String,
    pub(crate) upstream: Upstream,
}

impl std::cmp::PartialOrd for LocationConfig {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for LocationConfig {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.location.cmp(&other.location).reverse() // 越长越优先
    }
}

impl LocationConfig {
    pub(crate) async fn handle(
        &self, req: Request<hyper::body::Incoming>, client_socket_addr: SocketAddr,
        original_scheme_host_port: &SchemeHostPort,
        reverse_client: &legacy::Client<hyper_rustls::HttpsConnector<HttpConnector>, Incoming>,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        let upstream_req = self.build_upstream_req(req)?;
        info!(
            "[reverse] {:^35} ==> {} {:?} {:?} <== [{}{}]",
            SocketAddrFormat(&client_socket_addr).to_string(),
            upstream_req.method(),
            &upstream_req.uri(),
            upstream_req.version(),
            original_scheme_host_port,
            self.location,
        );
        METRICS
            .reverse_proxy_req
            .get_or_create(&LabelImpl::new(ReverseProxyReqLabel {
                client: client_socket_addr.ip().to_canonical().to_string(),
                origin: original_scheme_host_port.to_string() + self.location.as_str(),
                upstream: self.upstream.url_base.clone(),
            }))
            .inc();
        METRICS.reverse_proxy_req.get_or_create(&ALL_REVERSE_PROXY_REQ).inc();
        match reverse_client.request(upstream_req).await {
            Ok(mut resp) => {
                if resp.status().is_redirection() && resp.headers().contains_key(LOCATION) {
                    normalize302(original_scheme_host_port, resp.headers_mut())?;
                    //修改302的location
                }
                Ok(resp.map(|body| {
                    body.map_err(|e| {
                        let e = e;
                        io::Error::new(ErrorKind::InvalidData, e)
                    })
                    .boxed()
                }))
            }
            Err(e) => {
                warn!("reverse_proxy error: {e:?}");
                Err(io::Error::new(ErrorKind::InvalidData, e))
            }
        }
    }

    fn build_upstream_req(&self, req: Request<Incoming>) -> io::Result<Request<Incoming>> {
        let method = req.method().clone();
        let path_and_query = match req.uri().path_and_query() {
            Some(path_and_query) => path_and_query.as_str(),
            None => "",
        };
        let upstream_url = self.upstream.url_base.clone() + &path_and_query[self.location.len()..]; // upstream.url_base + 原始url去除location的部分

        let mut builder = Request::builder()
            .method(method)
            .uri(upstream_url)
            .version(match self.upstream.version {
                Version::H1 => http::Version::HTTP_11,
                Version::H2 => http::Version::HTTP_2,
                Version::Auto => {
                    if self.upstream.url_base.starts_with("https:") {
                        req.version()
                    } else {
                        http::Version::HTTP_11
                    }
                }
            });
        let header_map = match builder.headers_mut() {
            Some(header_map) => header_map,
            None => {
                return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "new_req.headers_mut() is None, which means error occurs in new request build. Check URL, method, version...",
                    ));
            }
        };
        for ele in req.headers() {
            if ele.0 != header::HOST {
                header_map.append(ele.0.clone(), ele.1.clone());
            } else {
                info!("skip host header: {:?}", ele.1);
            }
        }

        // 如果配置了authority_override，则设置Host头
        if let Some(ref authority_override) = self.upstream.authority_override {
            if let Some(old_host) = header_map.insert(
                header::HOST,
                HeaderValue::from_str(authority_override).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
            ) {
                info!("override host header from {old_host:?} to: {authority_override}");
            }
        }
        builder
            .body(req.into_body())
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
    }
}

fn normalize302(
    original_scheme_host_port: &SchemeHostPort, resp_headers: &mut http::HeaderMap,
) -> Result<(), io::Error> {
    let redirect_url = resp_headers
        .get_mut(LOCATION)
        .ok_or(io::Error::new(ErrorKind::InvalidData, "LOCATION absent when 30x"))?
        .to_str()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?
        .parse::<Uri>()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    if redirect_url.scheme_str().is_none() {
        info!("normalize302: redirect_url is relative, don't touch it");
        return Ok(());
    }
    if let Some(replacement) = lookup_replacement(
        original_scheme_host_port,
        redirect_url.to_string(),
        &crate::CONFIG.reverse_proxy_config.redirect_bachpaths,
    ) {
        let origin = resp_headers.insert(
            LOCATION,
            HeaderValue::from_str(replacement.as_str()).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
        );
        info!("normalize302: result is [{replacement}], before is [{origin:?}]");
    };
    Ok(())
}

#[derive(Serialize, Deserialize, Eq, PartialEq, PartialOrd)]
pub(crate) struct Upstream {
    pub(crate) url_base: String, // https://google.com
    #[serde(default = "default_version")]
    pub(crate) version: Version,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) authority_override: Option<String>, // 可选的Host头覆盖
}

// 定义默认值函数
fn default_version() -> Version {
    Version::Auto
}

fn root() -> String {
    "/".to_owned()
}

#[derive(PartialEq, PartialOrd, Copy, Clone, Eq, Ord, Hash, Serialize, Deserialize)]
pub(crate) enum Version {
    #[serde(rename = "H1")]
    H1,
    #[serde(rename = "H2")]
    H2,
    #[serde(rename = "AUTO")]
    Auto,
}

fn lookup_replacement(
    origin_scheme_host_port: &SchemeHostPort, absolute_redirect_url: String, redirect_bachpaths: &[RedirectBackpaths],
) -> Option<String> {
    for backpath in redirect_bachpaths.iter() {
        if absolute_redirect_url.starts_with(backpath.redirect_url.as_str()) {
            info!(
                "redirect back path for {}** is http(s)://{}:port{}**",
                backpath.redirect_url, backpath.host, backpath.location,
            );
            let host = match backpath.host.as_str() {
                DEFAULT_HOST => &origin_scheme_host_port.host, // 如果是default_host，就用当前host
                other => other,
            };
            let port_part = if let Some(port) = origin_scheme_host_port.port {
                format!(":{port}")
            } else {
                String::new()
            };
            return Some(
                origin_scheme_host_port.scheme.to_owned() // use raw request's scheme
                + "://"
                + host // if it's default_host, use raw request's host
                + &port_part // use raw request's port if available
                + &backpath.location
                + &absolute_redirect_url[backpath.redirect_url.len()..],
            );
        }
    }
    None
}

static ALL_REVERSE_PROXY_REQ: LazyLock<prom_label::LabelImpl<ReverseProxyReqLabel>> = LazyLock::new(|| {
    LabelImpl::new(ReverseProxyReqLabel {
        client: "all".to_string(),
        origin: "all".to_string(),
        upstream: "all".to_string(),
    })
});

pub(crate) struct ReverseProxyConfig {
    pub(crate) locations: HashMap<String, Vec<LocationConfig>>,
    pub(crate) redirect_bachpaths: Vec<RedirectBackpaths>,
}

fn truncate_string(s: &str, n: usize) -> &str {
    let len = s.len();
    if n >= len {
        ""
    } else {
        &s[..len - n]
    }
}

pub(crate) fn parse_reverse_proxy_config(
    reverse_proxy_config_file: &Option<String>, append_upstream_url: &mut Vec<String>, enable_github_proxy: bool,
) -> Result<ReverseProxyConfig, <Config as TryFrom<Param>>::Error> {
    let mut locations: HashMap<String, Vec<LocationConfig>> = match reverse_proxy_config_file {
        Some(path) => toml::from_str(&std::fs::read_to_string(path)?)?,
        None => HashMap::new(),
    };
    if enable_github_proxy {
        GITHUB_URL_BASE.iter().for_each(|domain| {
            append_upstream_url.push((*domain).to_owned());
        });
    }
    if !append_upstream_url.is_empty() {
        if !locations.contains_key(DEFAULT_HOST) {
            locations.insert(DEFAULT_HOST.to_string(), vec![]);
        }
        if let Some(vec) = locations.get_mut(DEFAULT_HOST) {
            append_upstream_url.iter().for_each(|upstream_url| {
                match upstream_url.parse::<Uri>() {
                    Ok(upstream_url) => {
                        if upstream_url.query().is_some() {
                            warn!("query is not supported in upstream_url:{upstream_url}");
                            return;
                        }
                        let upstream_url_tmp = upstream_url.to_string();
                        let upstream_url_base = truncate_string(upstream_url_tmp.as_str(), upstream_url.path().len());
                        // 如果path==/，则去掉path
                        let path = match upstream_url.path() {
                            "/" => "",
                            other => other,
                        };

                        vec.push(LocationConfig {
                            location: "/".to_string() + upstream_url_base + path,
                            upstream: crate::reverse::Upstream {
                                url_base: (*upstream_url_base).to_owned() + path,
                                version: crate::reverse::Version::Auto,
                                authority_override: None,
                            },
                        });
                    }
                    Err(err) => {
                        warn!("parse upstream_url error:{err}");
                    }
                };
            });
        }
    }
    locations
        .iter_mut()
        .for_each(|(_, reverse_proxy_configs)| reverse_proxy_configs.sort());
    for ele in &mut locations {
        for location_config in ele.1 {
            if !location_config.location.starts_with('/') {
                return Err("location should start with '/'".into());
            }
            match location_config.upstream.url_base.parse::<Uri>() {
                Ok(upstream_url_base) => {
                    if upstream_url_base.scheme().is_none() {
                        return Err(format!(
                            "wrong upstream_url_base: {} --- scheme is empty",
                            location_config.upstream.url_base
                        )
                        .into());
                    }
                    if upstream_url_base.authority().is_none() {
                        return Err(format!(
                            "wrong upstream_url_base: {} --- authority is empty",
                            location_config.upstream.url_base
                        )
                        .into());
                    }
                    if upstream_url_base.query().is_some() {
                        return Err(format!(
                            "wrong upstream_url_base: {} --- query is not empty",
                            location_config.upstream.url_base
                        )
                        .into());
                    }
                    // 在某些情况下，补全upstream.url_base最后的/
                    if location_config.location.ends_with('/')
                        && upstream_url_base.path() == "/"
                        && !location_config.upstream.url_base.ends_with('/')
                    {
                        location_config.upstream.url_base = upstream_url_base.to_string()
                    }
                }
                Err(e) => return Err(format!("parse upstream upstream_url_base error:{e}").into()),
            }
        }
    }
    let mut redirect_bachpaths = Vec::<RedirectBackpaths>::new();
    for (host, location_configs) in &locations {
        for location_config in location_configs {
            if let Some(authority_override) = location_config.upstream.authority_override.as_ref() {
                // 如果配置了authority_override，则使用它来构建重定向路径
                let url_base = location_config.upstream.url_base.parse::<Uri>()?;
                let mut parts = http::uri::Parts::from(url_base);
                parts.authority = Some(
                    authority_override
                        .parse()
                        .map_err(|e| format!("parse host override error: {e}"))?,
                );
                let new_url_base = Uri::from_parts(parts)
                    .map_err(|e| format!("build uri error: {e}"))?
                    .to_string();
                redirect_bachpaths.push(RedirectBackpaths {
                    redirect_url: new_url_base,
                    host: host.clone(),
                    location: location_config.location.clone(),
                });
            }

            // 使用原始的url_base构造重定向路径
            redirect_bachpaths.push(RedirectBackpaths {
                redirect_url: location_config.upstream.url_base.clone(),
                host: host.clone(),
                location: location_config.location.clone(),
            });
        }
    }
    redirect_bachpaths.sort_by(|a, b| a.redirect_url.cmp(&b.redirect_url).reverse());
    for ele in redirect_bachpaths.iter() {
        log::info!("find redirect back path for: {}**", ele.redirect_url);
    }
    // println!("{}",toml::to_string_pretty(&locations)?);
    Ok(ReverseProxyConfig {
        locations,
        redirect_bachpaths,
    })
}
