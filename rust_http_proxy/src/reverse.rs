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
use std::sync::LazyLock;
use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    str::FromStr,
};

use crate::ip_x::SocketAddrFormat;
use crate::proxy::ReverseProxyReqLabel;
use crate::METRICS;
use crate::{config, proxy::SchemeHostPort};

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

#[derive(Serialize, Deserialize, Eq, PartialEq, PartialOrd)]
pub(crate) struct Upstream {
    pub(crate) url_base: String, // https://google.com
    #[serde(default = "default_version")]
    pub(crate) version: Version,
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

struct ReverseReqContext<'a> {
    upstream: &'a Upstream,
    origin_scheme_host_port: &'a SchemeHostPort,
}

fn build_upstream_req(req: Request<Incoming>, location_config: &LocationConfig) -> io::Result<Request<Incoming>> {
    let method = req.method().clone();
    let path_and_query = match req.uri().path_and_query() {
        Some(path_and_query) => path_and_query.as_str(),
        None => "",
    };
    let url = location_config.upstream.url_base.clone() + &path_and_query[location_config.location.len()..];

    let mut builder = Request::builder().method(method).uri(url).version(
        if !location_config.upstream.url_base.starts_with("https:") {
            match location_config.upstream.version {
                Version::H1 => http::Version::HTTP_11,
                Version::H2 => http::Version::HTTP_2,
                Version::Auto => http::Version::HTTP_11,
            }
        } else {
            match location_config.upstream.version {
                Version::H1 => http::Version::HTTP_11,
                Version::H2 => http::Version::HTTP_2,
                Version::Auto => req.version(),
            }
        },
    );
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
    builder
        .body(req.into_body())
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
}

fn lookup_replacement(
    origin_scheme_host_port: &SchemeHostPort, absolute_redirect_location: String,
    redirect_bachpaths: &[config::RedirectBackpaths],
) -> Option<String> {
    for ele in redirect_bachpaths.iter() {
        if absolute_redirect_location.starts_with(ele.redirect_url.as_str()) {
            info!("redirect back path for {}** is http(s)://{}:port{}**", ele.redirect_url, ele.host, ele.location,);
            let host = match ele.host.as_str() {
                config::DEFAULT_HOST => &origin_scheme_host_port.host, // 如果是default_host，就用当前host
                other => other,
            };
            let port_part = if let Some(port) = origin_scheme_host_port.port {
                format!(":{}", port)
            } else {
                String::new()
            };
            return Some(
                origin_scheme_host_port.scheme.to_owned() // use raw request's scheme
                + "://"
                + host // if it's default_host, use raw request's host
                + &port_part // use raw request's port if available
                + &ele.location
                + &absolute_redirect_location[ele.redirect_url.len()..],
            );
        }
    }
    None
}

fn ensure_absolute(location_header: &mut HeaderValue, context: &ReverseReqContext<'_>) -> io::Result<String> {
    let location = location_header
        .to_str()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    let redirect_url = location
        .parse::<Uri>()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    if redirect_url.scheme_str().is_none() {
        let url_base =
            Uri::from_str(&context.upstream.url_base).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        let base = if url_base.path().ends_with("/") && location.starts_with("/") {
            let mut base = url_base.to_string();
            base.truncate(url_base.to_string().len() - 1);
            base
        } else {
            url_base.to_string()
        };
        let absolute_url = format!("{}{}", base, location);
        Ok(absolute_url)
    } else {
        Ok(location.to_string())
    }
}

pub(crate) fn pick_location<'b>(path: &str, locations: &'b [LocationConfig]) -> Option<&'b LocationConfig> {
    // let path = match path {
    //     "" => "/",
    //     path => path,
    // };
    locations.iter().find(|&ele| path.starts_with(&ele.location))
}

pub(crate) async fn handle(
    req: Request<hyper::body::Incoming>, location_config: &LocationConfig, client_socket_addr: SocketAddr,
    origin_scheme_host_port: &SchemeHostPort,
    reverse_client: &legacy::Client<hyper_rustls::HttpsConnector<HttpConnector>, Incoming>,
) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
    let upstream_req = build_upstream_req(req, location_config)?;
    info!(
        "[reverse proxy] {:^35} => {}{}** ==> [{}] {:?} [{:?}]",
        SocketAddrFormat(&client_socket_addr).to_string(),
        origin_scheme_host_port,
        location_config.location,
        upstream_req.method(),
        &upstream_req.uri(),
        upstream_req.version(),
    );
    METRICS
        .reverse_proxy_req
        .get_or_create(&LabelImpl::new(ReverseProxyReqLabel {
            client: client_socket_addr.ip().to_canonical().to_string(),
            origin: origin_scheme_host_port.to_string() + location_config.location.as_str(),
            upstream: location_config.upstream.url_base.clone(),
        }))
        .inc();
    METRICS.reverse_proxy_req.get_or_create(&ALL_REVERSE_PROXY_REQ).inc();
    let context = ReverseReqContext {
        upstream: &location_config.upstream,
        origin_scheme_host_port,
    };
    match reverse_client.request(upstream_req).await {
        Ok(mut resp) => {
            if resp.status().is_redirection() && resp.headers().contains_key(LOCATION) {
                let headers = resp.headers_mut();
                let redirect_location = headers
                    .get_mut(LOCATION)
                    .ok_or(io::Error::new(ErrorKind::InvalidData, "LOCATION absent when 30x"))?;

                let absolute_redirect_location = ensure_absolute(redirect_location, &context)?;
                if let Some(replacement) = lookup_replacement(
                    context.origin_scheme_host_port,
                    absolute_redirect_location,
                    &crate::CONFIG.reverse_proxy_config.redirect_bachpaths,
                ) {
                    let origin = headers.insert(
                        LOCATION,
                        HeaderValue::from_str(replacement.as_str())
                            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
                    );
                    info!("redirect to [{}], origin is [{:?}]", replacement, origin);
                }
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
            warn!("reverse_proxy error: {:?}", e);
            Err(io::Error::new(ErrorKind::InvalidData, e))
        }
    }
}

static ALL_REVERSE_PROXY_REQ: LazyLock<prom_label::LabelImpl<ReverseProxyReqLabel>> = LazyLock::new(|| {
    LabelImpl::new(ReverseProxyReqLabel {
        client: "all".to_string(),
        origin: "all".to_string(),
        upstream: "all".to_string(),
    })
});
