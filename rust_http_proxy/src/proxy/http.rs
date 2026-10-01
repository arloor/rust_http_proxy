use std::{
    borrow::Cow,
    collections::HashMap,
    fmt::{Display, Formatter},
    io::{self, ErrorKind},
    net::SocketAddr,
};

use axum::extract::Request;
use http::{HeaderMap, Uri, header::HeaderValue};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{Response, Version, body::Bytes, body::Incoming};
use log::warn;

use crate::axum_handler;
use crate::config::AllowCIRRS;
use crate::ip_x::SocketAddrFormat;
use crate::location::LocationAuth;

pub(crate) struct SchemeHostPort {
    pub(crate) scheme: String,
    pub(crate) host: String,
    pub(crate) port: Option<u16>,
}

impl Display for SchemeHostPort {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let host = bracket_ipv6_host(&self.host);
        match self.port {
            Some(port) => write!(f, "{}://{}:{}", self.scheme, host, port),
            None => write!(f, "{}://{}", self.scheme, host),
        }
    }
}

/// URI authority 里的 IPv6 字面量必须带方括号；已带括号或非 IPv6 时原样返回。
pub(crate) fn bracket_ipv6_host(host: &str) -> Cow<'_, str> {
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        Cow::Owned(format!("[{host}]"))
    } else {
        Cow::Borrowed(host)
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

/// X-Forwarded-For 中最左侧（最初客户端）的地址。
pub(super) fn first_forwarded_for(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-forwarded-for")
        .and_then(|forwarded_for| forwarded_for.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
}

/// 获取客户端 IP 地址
/// 优先从 x-forwarded-for 请求头获取（取第一个 IP），否则使用 socket 地址
pub(super) fn get_client_ip(req: &Request<Incoming>, client_socket_addr: SocketAddr) -> String {
    first_forwarded_for(req.headers())
        .map(str::to_owned)
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

/// 把 absolute-form 改成 origin-form（只保留 path?query），没有路径时为 `/`。
pub(crate) fn origin_form(uri: &mut Uri) {
    *uri = uri
        .path_and_query()
        .cloned()
        .and_then(|path| {
            let mut parts = ::http::uri::Parts::default();
            parts.path_and_query = Some(path);
            Uri::from_parts(parts).ok()
        })
        .unwrap_or_else(|| Uri::from_static("/"));
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

pub(super) enum LocationAccess {
    Allowed(Option<String>),
    Challenge(Response<BoxBody<Bytes, io::Error>>),
}

/// 先做网段门禁，再做路径 Basic 认证。网段拒绝保持 PermissionDenied，交给调用方丢连接；认证失败返回 401。
pub(super) fn authorize_location(
    allow_cidrs: &AllowCIRRS, client_socket_addr: SocketAddr, headers: &HeaderMap, request_path: &str,
    auth: &LocationAuth, scenario: &str,
) -> io::Result<LocationAccess> {
    allow_cidrs.check_serving_control(client_socket_addr)?;
    match check_static_basic_auth(headers, request_path, &auth.basic_auth, &auth.basic_auth_path_prefixes) {
        Ok(username) => Ok(LocationAccess::Allowed(username)),
        Err(error) => {
            warn!(
                "{scenario} basic auth failed from {} for {}: {}",
                SocketAddrFormat(&client_socket_addr),
                request_path,
                error
            );
            Ok(LocationAccess::Challenge(build_authenticate_resp(false)))
        }
    }
}

pub(crate) fn boxed_io_body<B, E>(body: B) -> BoxBody<Bytes, io::Error>
where
    B: http_body::Body<Data = Bytes, Error = E> + Send + Sync + 'static,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    body.map_err(|error| io::Error::new(ErrorKind::InvalidData, error))
        .boxed()
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

pub(super) fn text_response(status: http::StatusCode, body: &'static str) -> Response<BoxBody<Bytes, io::Error>> {
    let mut resp = Response::new(full_body(body));
    *resp.status_mut() = status;
    resp
}

pub(super) fn invalid_connect_target(uri: &Uri) -> Response<BoxBody<Bytes, io::Error>> {
    warn!("CONNECT host is not socket addr: {uri:?}");
    text_response(http::StatusCode::BAD_REQUEST, "CONNECT must be to a socket address")
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
    fn origin_form_keeps_only_path_and_query() -> Result<(), crate::DynError> {
        for (input, expected) in [
            ("http://example.com/a/b?c=1", "/a/b?c=1"),
            ("http://example.com", "/"),
            ("http://example.com/", "/"),
            ("/already?x", "/already?x"),
        ] {
            let mut uri = input.parse::<Uri>()?;
            origin_form(&mut uri);
            assert_eq!(uri.to_string(), expected, "input {input}");
        }
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
