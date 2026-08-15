use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
    io::{self, ErrorKind},
    net::SocketAddr,
};

use axum::extract::Request;
use http::{HeaderMap, Uri, header::HeaderValue};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{Response, Version, body::Bytes, body::Incoming};

use crate::axum_handler;

pub(crate) struct SchemeHostPort {
    pub(crate) scheme: String,
    pub(crate) host: String,
    pub(crate) port: Option<u16>,
}

impl Display for SchemeHostPort {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let host = format_uri_host(&self.host);
        match self.port {
            Some(port) => write!(f, "{}://{}:{}", self.scheme, host, port),
            None => write!(f, "{}://{}", self.scheme, host),
        }
    }
}

fn format_uri_host(host: &str) -> String {
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(super) struct RequestDomain(pub(super) String);

pub(super) fn extract_scheme_host_port(
    req: &Request<Incoming>, default_scheme: &str,
) -> io::Result<(SchemeHostPort, RequestDomain)> {
    let uri = req.uri();
    let scheme = uri.scheme_str().unwrap_or(default_scheme);
    if req.version() == Version::HTTP_2 {
        //H2，信息全在uri中
        let host_in_url = uri
            .host()
            .ok_or(io::Error::new(ErrorKind::InvalidData, "authority is absent in HTTP/2"))?
            .to_string();
        let host_in_header = req
            .headers()
            .get(http::header::HOST)
            .and_then(|host| host.to_str().ok())
            .and_then(|host| host.parse::<http::uri::Authority>().ok())
            .map(|authority| authority.host().to_owned());
        Ok((
            SchemeHostPort {
                scheme: scheme.to_owned(),
                host: host_in_url.clone(),
                port: uri.port_u16(),
            },
            RequestDomain(match host_in_header {
                Some(host) => host,  // 优先使用H2协议的Host头
                None => host_in_url, // 其次使用H2协议的uri中的host
            }),
        ))
    } else {
        let authority = req
            .headers()
            .get(http::header::HOST)
            .ok_or(io::Error::new(ErrorKind::InvalidData, "Host Header is absent in HTTP/1.1"))?
            .to_str()
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?
            .parse::<http::uri::Authority>()
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        let host = authority.host().to_owned();
        let port = authority.port_u16();
        Ok((
            SchemeHostPort {
                scheme: scheme.to_owned(),
                host: host.clone(),
                port,
            },
            RequestDomain(host),
        ))
    }
}

pub(super) fn is_schema_secure(uri: &Uri) -> bool {
    uri.scheme_str()
        .map(|scheme_str| matches!(scheme_str, "wss" | "https"))
        .unwrap_or_default()
}

/// 获取客户端 IP 地址
/// 优先从 x-forwarded-for 请求头获取（取第一个 IP），否则使用 socket 地址
pub(super) fn get_client_ip(req: &Request<Incoming>, client_socket_addr: SocketAddr) -> String {
    req.headers()
        .get("x-forwarded-for")
        .and_then(|forwarded_for| {
            forwarded_for
                .to_str()
                .ok()
                .and_then(|s| s.split(',').next())
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| client_socket_addr.ip().to_canonical().to_string())
}

/// 检测请求是否为 WebSocket 升级请求
pub(super) fn is_websocket_upgrade<B>(req: &Request<B>) -> bool {
    let has_upgrade_token = req
        .headers()
        .get_all(http::header::CONNECTION)
        .iter()
        .flat_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .any(|v| v.eq_ignore_ascii_case("upgrade"));
    if !has_upgrade_token {
        return false;
    }

    req.headers()
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

pub(super) fn origin_form(uri: &mut Uri) -> io::Result<()> {
    let path = match uri.path_and_query() {
        Some(path) if path.as_str() != "/" => {
            let mut parts = ::http::uri::Parts::default();
            parts.path_and_query = Some(path.clone());
            Uri::from_parts(parts).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?
        }
        _none_or_just_slash => {
            debug_assert!(Uri::default() == "/");
            Uri::default()
        }
    };
    *uri = path;
    Ok(())
}

pub(super) fn check_static_basic_auth(
    headers: &HeaderMap, request_path: &str, basic_auth: &HashMap<String, String>, basic_auth_path_prefixes: &[String],
) -> Result<Option<String>, io::Error> {
    if basic_auth_path_prefixes
        .iter()
        .any(|path_prefix| request_path.starts_with(path_prefix))
    {
        return axum_handler::check_auth(headers, http::header::AUTHORIZATION, basic_auth);
    }

    Ok(None)
}

pub(crate) fn build_authenticate_resp(for_proxy: bool) -> Response<BoxBody<Bytes, io::Error>> {
    let mut resp = Response::new(full_body("auth need"));
    resp.headers_mut().append(
        if for_proxy {
            http::header::PROXY_AUTHENTICATE
        } else {
            http::header::WWW_AUTHENTICATE
        },
        HeaderValue::from_static("Basic realm=\"are you kidding me\""),
    );
    if for_proxy {
        *resp.status_mut() = http::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
    } else {
        *resp.status_mut() = http::StatusCode::UNAUTHORIZED;
    }
    resp
}

pub fn empty_body() -> BoxBody<Bytes, io::Error> {
    Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}

pub fn full_body<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, io::Error> {
    Full::new(chunk.into()).map_err(|never| match never {}).boxed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_upgrade_requires_connection_upgrade_token() -> Result<(), http::Error> {
        let req = Request::builder()
            .uri("/ws")
            .header(http::header::CONNECTION, "keep-alive, Upgrade")
            .header(http::header::UPGRADE, "websocket")
            .body(())?;

        assert!(is_websocket_upgrade(&req));
        Ok(())
    }

    #[test]
    fn websocket_upgrade_ignores_upgrade_header_without_connection_token() -> Result<(), http::Error> {
        let req = Request::builder()
            .uri("/plain")
            .header(http::header::CONNECTION, "close, x-remove-for-h2")
            .header(http::header::UPGRADE, "websocket")
            .body(())?;

        assert!(!is_websocket_upgrade(&req));
        Ok(())
    }

    #[test]
    fn scheme_host_port_formats_ipv6_authority() {
        let origin = SchemeHostPort {
            scheme: "https".to_owned(),
            host: "::1".to_owned(),
            port: Some(8443),
        };
        assert_eq!(origin.to_string(), "https://[::1]:8443");
    }
}
