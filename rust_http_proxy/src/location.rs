use http::header::LOCATION;
use http::{HeaderName, HeaderValue, Request, Response, Uri, header};
use http_body_util::BodyExt as _;
use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::body::Incoming;
use hyper::upgrade::Upgraded;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioIo;
use log::info;
use log::warn;
use percent_encoding::percent_decode_str;
use prom_label::LabelImpl;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::LazyLock;
use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
};

use crate::axum_handler::AXUM_PATHS;
use crate::config::{Config, Param};
use crate::dns_resolver::CustomGaiDNSResolver;
use crate::hyper_x::{CountWriteHyperIO, CounterBody};
use crate::ip_x::SocketAddrFormat;
use crate::proxy::AccessLabel;
use crate::proxy::ReverseProxyReqLabel;
use crate::proxy::SchemeHostPort;
use crate::{METRICS, static_serve};

pub(crate) struct RedirectBackpaths {
    pub(crate) redirect_url: String,
    pub(crate) host: String,
    pub(crate) location: String,
}

pub(crate) const DEFAULT_HOST: &str = "default_host";
const GITHUB_URL_BASE: [&str; 6] = [
    "https://github.com",
    "https://gist.githubusercontent.com",
    "https://gist.github.com",
    "https://objects.githubusercontent.com",
    "https://raw.githubusercontent.com",
    "https://release-assets.githubusercontent.com",
];

#[derive(Serialize, Deserialize, Eq, PartialEq)]
#[serde(untagged)]
pub(crate) enum LocationConfig {
    ReverseProxy {
        #[serde(default = "root")]
        location: String,
        upstream: Upstream,
    },
    Serving {
        #[serde(default = "root")]
        location: String,
        static_dir: String,
    },
}

impl std::cmp::PartialOrd for LocationConfig {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for LocationConfig {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.location().cmp(other.location()).reverse() // 越长越优先
    }
}

impl LocationConfig {
    /// 获取 location 路径
    pub(crate) fn location(&self) -> &str {
        match self {
            LocationConfig::ReverseProxy { location, .. } => location,
            LocationConfig::Serving { location, .. } => location,
        }
    }
}

pub(crate) enum RequestSpec<'a> {
    ForServing {
        request: &'a Request<Incoming>,
        client_socket_addr: SocketAddr,
        location: &'a String,
        static_dir: &'a String,
        config: &'a Config,
    },
    ForReverseProxy {
        request: Box<Request<Incoming>>,
        client_socket_addr: SocketAddr,
        original_scheme_host_port: &'a SchemeHostPort,
        location: &'a String,
        upstream: &'a Upstream,
        reverse_client: &'a legacy::Client<
            HttpsConnector<HttpConnector<CustomGaiDNSResolver>>,
            http_body_util::combinators::BoxBody<axum::body::Bytes, std::io::Error>,
        >,
        config: &'a Config,
    },
}

impl<'a> RequestSpec<'a> {
    async fn handle_websocket_upgrade(
        upstream_req: Request<Incoming>, client_upgrade_fut: hyper::upgrade::OnUpgrade, traffic_label: AccessLabel,
        reverse_client: &legacy::Client<
            HttpsConnector<HttpConnector<CustomGaiDNSResolver>>,
            http_body_util::combinators::BoxBody<axum::body::Bytes, std::io::Error>,
        >,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        // 客户端的升级 future 已经在调用前准备好了

        // 将 Incoming body 转换为 BoxBody
        let upstream_req = upstream_req.map(|body| body.map_err(|e| io::Error::new(ErrorKind::InvalidData, e)).boxed());

        // 发送升级请求到上游
        let mut upstream_resp = reverse_client
            .request(upstream_req)
            .await
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;

        // 检查上游是否返回 101 Switching Protocols
        if upstream_resp.status() != http::StatusCode::SWITCHING_PROTOCOLS {
            warn!("WebSocket upgrade failed, upstream returned: {}", upstream_resp.status());
            return Ok(upstream_resp.map(|body| body.map_err(|e| io::Error::new(ErrorKind::InvalidData, e)).boxed()));
        }

        info!("[reverse] WebSocket upgrade successful, status: {}", upstream_resp.status());

        // 准备上游的升级
        let upstream_upgrade_fut = hyper::upgrade::on(&mut upstream_resp);

        // 构造 101 响应给客户端，复制上游的响应头
        let mut client_response_builder = Response::builder().status(http::StatusCode::SWITCHING_PROTOCOLS);

        // 复制所有响应头
        if let Some(headers) = client_response_builder.headers_mut() {
            for (key, value) in upstream_resp.headers() {
                headers.insert(key.clone(), value.clone());
            }
        }

        let client_response = client_response_builder
            .body(http_body_util::Empty::<Bytes>::new().map_err(|e| match e {}).boxed())
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;

        // 启动异步任务进行双向数据转发
        tokio::spawn(async move {
            match (upstream_upgrade_fut.await, client_upgrade_fut.await) {
                (Ok(upstream_upgraded), Ok(client_upgraded)) => {
                    if let Err(e) = Self::tunnel_websocket(upstream_upgraded, client_upgraded, traffic_label).await {
                        warn!("WebSocket tunnel error: {e:?}");
                    }
                }
                (Err(e), _) | (_, Err(e)) => {
                    warn!("WebSocket upgrade error: {e:?}");
                }
            }
        });

        Ok(client_response)
    }

    async fn tunnel_websocket(upstream: Upgraded, client: Upgraded, traffic_label: AccessLabel) -> io::Result<()> {
        let mut upstream_io = TokioIo::new(CountWriteHyperIO::new(
            upstream,
            METRICS.proxy_traffic.clone(),
            LabelImpl::new(traffic_label.clone()),
        ));
        let mut client_io = TokioIo::new(CountWriteHyperIO::new(
            client,
            METRICS.proxy_traffic.clone(),
            LabelImpl::new(traffic_label.clone()),
        ));

        // 双向数据转发
        let _ = tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await?;

        Ok(())
    }

    pub(crate) async fn handle(self) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        match self {
            RequestSpec::ForReverseProxy {
                location,
                upstream,
                mut request,
                client_socket_addr,
                original_scheme_host_port,
                reverse_client,
                config,
            } => {
                config.allow_cidrs.check_serving_control(client_socket_addr)?;
                // 创建流量统计标签
                let traffic_label = AccessLabel {
                    client: client_socket_addr.ip().to_canonical().to_string(),
                    target: upstream.url_base.clone(),
                    username: "reverse_proxy".to_owned(),
                    relay_over_tls: None,
                };

                // 先检测是否是 WebSocket 升级请求（在 request 被消费之前）
                let is_websocket = request
                    .headers()
                    .get(header::UPGRADE)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.eq_ignore_ascii_case("websocket"))
                    .unwrap_or(false);

                // 记录指标
                METRICS
                    .reverse_proxy_req
                    .get_or_create(&LabelImpl::new(ReverseProxyReqLabel {
                        client: client_socket_addr.ip().to_canonical().to_string(),
                        origin: original_scheme_host_port.to_string() + location.as_str(),
                        upstream: upstream.url_base.clone(),
                    }))
                    .inc();
                METRICS.reverse_proxy_req.get_or_create(&ALL_REVERSE_PROXY_REQ).inc();

                if is_websocket {
                    info!(
                        "[reverse] {:^35} ==> wss {} {:?} <== [{}{}]",
                        SocketAddrFormat(&client_socket_addr).to_string(),
                        request.uri(),
                        request.version(),
                        original_scheme_host_port,
                        location,
                    );
                    // 在消费 request 之前，先获取客户端的 upgrade future
                    let client_upgrade_fut = hyper::upgrade::on(&mut *request);
                    let upstream_req =
                        Self::build_upstream_req(location, upstream, *request, original_scheme_host_port)?;
                    return Self::handle_websocket_upgrade(
                        upstream_req,
                        client_upgrade_fut,
                        traffic_label,
                        reverse_client,
                    )
                    .await;
                }

                let upstream_req = Self::build_upstream_req(location, upstream, *request, original_scheme_host_port)?;
                let upstream_req = upstream_req.map(|body| {
                    // 使用 CounterBody 包装 body 来统计请求流量
                    let counter_body =
                        CounterBody::new(body, METRICS.proxy_traffic.clone(), LabelImpl::new(traffic_label.clone()));
                    counter_body
                        .map_err(|e| {
                            let e = e;
                            io::Error::new(ErrorKind::InvalidData, e)
                        })
                        .boxed()
                });
                info!(
                    "[reverse] {:^35} ==> {} {:?} {:?} <== [{}{}]",
                    SocketAddrFormat(&client_socket_addr).to_string(),
                    upstream_req.method(),
                    &upstream_req.uri(),
                    upstream_req.version(),
                    original_scheme_host_port,
                    location,
                );

                match reverse_client.request(upstream_req).await {
                    Ok(mut resp) => {
                        if resp.status().is_redirection() && resp.headers().contains_key(LOCATION) {
                            normalize302(original_scheme_host_port, resp.headers_mut(), config)?;
                            //修改302的location
                        }

                        Ok(resp.map(|body| {
                            // 使用 CounterBody 包装 body 来统计响应流量
                            let counter_body =
                                CounterBody::new(body, METRICS.proxy_traffic.clone(), LabelImpl::new(traffic_label));
                            counter_body
                                .map_err(|e| {
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
            RequestSpec::ForServing {
                location,
                request,
                client_socket_addr,
                static_dir,
                config,
            } => {
                config.allow_cidrs.check_serving_control(client_socket_addr)?;

                if AXUM_PATHS.contains(&request.uri().path()) {
                    return static_serve::not_found().map_err(|e| io::Error::new(ErrorKind::InvalidData, e));
                }

                // 创建流量统计标签
                let traffic_label = AccessLabel {
                    client: client_socket_addr.ip().to_canonical().to_string(),
                    target: static_dir.clone(),
                    username: "static_serving".to_owned(),
                    relay_over_tls: None,
                };

                let raw_path = request.uri().path();
                let path = percent_decode_str(raw_path)
                    .decode_utf8()
                    .unwrap_or(Cow::from(raw_path));
                #[allow(clippy::expect_used)]
                let path = path.strip_prefix(location).expect("should start with location");
                let path = "/".to_string() + path;
                let resp = static_serve::serve_http_request(request, client_socket_addr, &path, static_dir, config)
                    .await
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;

                // 使用 CounterBody 包装响应 body 来统计响应流量
                Ok(resp.map(|body| {
                    let counter_body =
                        CounterBody::new(body, METRICS.proxy_traffic.clone(), LabelImpl::new(traffic_label));
                    counter_body.boxed()
                }))
            }
        }
    }

    fn build_upstream_req(
        location: &str, upstream: &Upstream, req: Request<Incoming>, original_scheme_host_port: &SchemeHostPort,
    ) -> io::Result<Request<Incoming>> {
        let method = req.method().clone();
        let path_and_query = match req.uri().path_and_query() {
            Some(path_and_query) => path_and_query.as_str(),
            None => "",
        };
        let upstream_url = upstream.url_base.clone() + &path_and_query[location.len()..]; // upstream.url_base + 原始url去除location的部分

        // 先解析 URI 以提取 authority，然后再移动 upstream_url
        let upstream_uri = upstream_url
            .parse::<Uri>()
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        // let upstream_authority = upstream_uri.authority().cloned();

        let mut builder = Request::builder()
            .method(method)
            .uri(upstream_uri)
            .version(match upstream.version {
                Version::H1 => http::Version::HTTP_11,
                Version::H2 => http::Version::HTTP_2,
                Version::Auto => {
                    if upstream.url_base.starts_with("https:") {
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

        // // 为上游请求添加正确的 Host 头部
        // if let Some(authority) = upstream_authority {
        //     if let Ok(host_value) = HeaderValue::from_str(authority.as_str()) {
        //         header_map.insert(header::HOST, host_value);
        //     }
        // }

        if let Some(ref headers) = upstream.headers {
            for (key, value) in headers {
                if value.is_empty() || key.is_empty() {
                    warn!("skip empty header value for key: {}", key);
                    continue;
                }
                let mut header_value = value.clone();
                if value == "#{host}" {
                    // TIPS: 即使本程序在反向代理的request中增加Host头部，如果upstream在H2协议中不读取Host头部，则仍然会使用uri中的host进行跨域检测，容易出现origin not allowed的问题
                    if let Some(port) = original_scheme_host_port.port {
                        header_value = format!("{}:{port}", original_scheme_host_port.host);
                    } else {
                        header_value = original_scheme_host_port.host.clone();
                    }
                }
                if let Some(old_value) = header_map.insert(
                    HeaderName::from_str(key).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
                    HeaderValue::from_str(&header_value).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
                ) {
                    info!("override header {} from {old_value:?} to: {}", key, value);
                }
            }
        }
        builder
            .body(req.into_body())
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
    }
}

fn normalize302(
    original_scheme_host_port: &SchemeHostPort, resp_headers: &mut http::HeaderMap, config: &Config,
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
        &config.location_specs.redirect_bachpaths,
    ) {
        let origin = resp_headers.insert(
            LOCATION,
            HeaderValue::from_str(replacement.as_str()).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
        );
        info!("normalize302: result is [{replacement}], before is [{origin:?}]");
    };
    Ok(())
}

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub(crate) struct Upstream {
    pub(crate) url_base: String, // https://google.com
    #[serde(default = "default_version")]
    pub(crate) version: Version,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) headers: Option<HashMap<String, String>>, // 可选的头部覆盖
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

pub(crate) struct LocationSpecs {
    pub(crate) locations: HashMap<String, Vec<LocationConfig>>,
    pub(crate) redirect_bachpaths: Vec<RedirectBackpaths>,
}

fn truncate_string(s: &str, n: usize) -> &str {
    let len = s.len();
    if n >= len { "" } else { &s[..len - n] }
}

pub(crate) fn parse_location_specs(
    location_config_file: &Option<String>, default_static_dir: &Option<String>, append_upstream_url: &mut Vec<String>,
    enable_github_proxy: bool,
) -> Result<LocationSpecs, <Config as TryFrom<Param>>::Error> {
    let mut locations: HashMap<String, Vec<LocationConfig>> = match location_config_file {
        Some(path) => {
            let content = std::fs::read_to_string(path)?;
            // 根据文件后缀决定使用哪种解析器，默认使用 YAML
            if path.ends_with(".toml") {
                info!("parsing location config as TOML format");
                toml::from_str(&content)?
            } else {
                // 默认或 .yaml/.yml 后缀都使用 YAML 解析
                info!("parsing location config as YAML format");
                serde_yaml_bw::from_str(&content)?
            }
        }
        None => HashMap::new(),
    };

    // 如果设置了 static_dir，则在 default_host 的根目录添加 Serving 类型的 LocationConfig
    if let Some(static_dir) = &default_static_dir {
        if !locations.contains_key(crate::location::DEFAULT_HOST) {
            locations.insert(crate::location::DEFAULT_HOST.to_string(), vec![]);
        }
        if let Some(vec) = locations.get_mut(crate::location::DEFAULT_HOST) {
            // 检查是否已存在 location 为 "/" 的配置
            if vec.iter().any(|config| {
                    matches!(config, crate::location::LocationConfig::Serving { location, .. } | crate::location::LocationConfig::ReverseProxy { location, .. } if location == "/")
                }) {
                    log::error!("Location '/' already exists in reverse proxy config for DEFAULT_HOST. Cannot add static_dir.");
                    std::process::exit(1);
                }
            vec.push(crate::location::LocationConfig::Serving {
                location: "/".to_string(),
                static_dir: static_dir.clone(),
            });
        }
    }
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

                        vec.push(LocationConfig::ReverseProxy {
                            location: "/".to_string() + upstream_url_base + path,
                            upstream: crate::location::Upstream {
                                url_base: (*upstream_url_base).to_owned() + path,
                                version: crate::location::Version::Auto,
                                headers: None,
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
        .for_each(|(_, location_configs)| location_configs.sort());
    info!("parsed location specs: \n{}", serde_yaml_bw::to_string(&locations)?);
    for ele in &mut locations {
        for location_config in ele.1 {
            if !location_config.location().starts_with('/') {
                return Err("location should start with '/'".into());
            }
            // 对于 Serving 配置，验证 location以 / 结束
            if let LocationConfig::Serving { location, .. } = location_config {
                if !location.ends_with('/') {
                    return Err(format!("serving location should end with '/': {}", location).into());
                }
            }

            // 对于反向代理配置，验证 upstream
            if let LocationConfig::ReverseProxy { location, upstream } = location_config {
                match upstream.url_base.parse::<Uri>() {
                    Ok(upstream_url_base) => {
                        if upstream_url_base.scheme().is_none() {
                            return Err(
                                format!("wrong upstream_url_base: {} --- scheme is empty", upstream.url_base).into()
                            );
                        }
                        if upstream_url_base.authority().is_none() {
                            return Err(format!(
                                "wrong upstream_url_base: {} --- authority is empty",
                                upstream.url_base
                            )
                            .into());
                        }
                        if upstream_url_base.query().is_some() {
                            return Err(format!(
                                "wrong upstream_url_base: {} --- query is not empty",
                                upstream.url_base
                            )
                            .into());
                        }
                        // 在某些情况下，补全upstream.url_base最后的/
                        if location.ends_with('/')
                            && upstream_url_base.path() == "/"
                            && !upstream.url_base.ends_with('/')
                        {
                            upstream.url_base = upstream_url_base.to_string()
                        }
                    }
                    Err(e) => return Err(format!("parse upstream upstream_url_base error:{e}").into()),
                }
            }
        }
    }
    let mut redirect_bachpaths = Vec::<RedirectBackpaths>::new();
    for (host, location_configs) in &locations {
        for location_config in location_configs {
            // 只为反向代理配置构造重定向路径
            if let LocationConfig::ReverseProxy { location, upstream } = location_config {
                redirect_bachpaths.push(RedirectBackpaths {
                    redirect_url: upstream.url_base.clone(),
                    host: host.clone(),
                    location: location.clone(),
                });
            }
        }
    }
    redirect_bachpaths.sort_by(|a, b| a.redirect_url.cmp(&b.redirect_url).reverse());
    for ele in redirect_bachpaths.iter() {
        log::info!("find redirect back path for: {}**", ele.redirect_url);
    }
    // println!("{}",toml::to_string_pretty(&locations)?);
    Ok(LocationSpecs {
        locations,
        redirect_bachpaths,
    })
}
