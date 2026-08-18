use std::{io, io::ErrorKind, net::SocketAddr, sync::Arc};

use axum::extract::Request;
use http::{
    Uri,
    header::{CONTENT_LENGTH, HOST, TRANSFER_ENCODING},
};
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::{
    Response,
    body::{Bytes, Incoming},
    header::HeaderValue,
};
use io_x::CounterIO;
use log::{debug, info, warn};
use prom_label::LabelImpl;

use crate::{
    METRICS,
    config::ForwardBypassConfig,
    forward_proxy_client::{DirectProtocol, ForwardProxyClient},
    hyper_x::CounterBody,
    ip_x::SocketAddrFormat,
    location::{BuiltUpstreamRequest, build_upstream_req},
    mitm::{MitmDynamicStub, MitmStubAction, MitmStubResponse, MitmStubSpecs},
    mitm_manager::{MitmManager, RecordMetadata, ResponseHead, headers_json, version_label},
    proxy::{
        connect::HttpClientStream,
        http::{SchemeHostPort, full_body, get_client_ip, is_websocket_upgrade, origin_form},
        labels::AccessLabel,
        tunnel::spawn_websocket_tunnel,
    },
    reverse_proxy_client::ReverseProxyClient,
};

use super::capture::{
    capture_and_drain_mitm_request_body, map_boxed_mitm_response_body, map_mitm_request_body, map_mitm_response_body,
};

#[derive(Clone)]
pub(super) struct MitmRequestContext {
    pub(super) ipv6_first: Option<bool>,
    pub(super) forward_bypass: Option<ForwardBypassConfig>,
    pub(super) stub_specs: MitmStubSpecs,
    pub(super) stub_http1_client: ReverseProxyClient<BoxBody<Bytes, io::Error>>,
    pub(super) stub_http2_client: ReverseProxyClient<BoxBody<Bytes, io::Error>>,
    pub(super) manager: Arc<MitmManager>,
}

pub(super) async fn handle_mitm_request(
    mut req: Request<Incoming>, mitm_proxy_client: ForwardProxyClient<BoxBody<Bytes, io::Error>>,
    client_socket_addr: SocketAddr, target: String, username: String, context: MitmRequestContext,
) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
    let access_label = AccessLabel {
        client: client_socket_addr.ip().to_canonical().to_string(),
        target,
        username,
        relay_over_tls: Some(true),
    };
    let is_websocket = is_websocket_upgrade(&req);
    let request_authority = request_authority(&req, &access_label.target);
    mod_mitm_proxy_req(&mut req, &request_authority)?;
    let request_host = request_authority
        .parse::<http::uri::Authority>()
        .map(|authority| authority.host().to_ascii_lowercase())
        .unwrap_or_else(|_| request_authority.to_ascii_lowercase());
    let request_path = req.uri().path().to_owned();
    // 面板自己的 /mitm 流量如果也落库，会把留存窗口和 URL 分类挤满。
    let record_id = if crate::mitm_web::is_management_path(&request_path) {
        None
    } else {
        context.manager.begin_record(RecordMetadata {
            client_ip: access_label.client.clone(),
            client_port: client_socket_addr.port(),
            proxy_username: access_label.username.clone(),
            authority: request_authority.clone(),
            host: request_host,
            path: request_path,
            query: req.uri().query().map(str::to_owned),
            method: req.method().to_string(),
            request_version: req.version(),
            request_headers: req.headers(),
        })
    };

    info!(
        "[mitm] {:^35} ==> {} authority={} {:?} {:?}",
        SocketAddrFormat(&client_socket_addr).to_string(),
        req.method(),
        request_authority,
        req.uri(),
        req.version(),
    );

    if let Some(stub_action) = context.stub_specs.find(&access_label.target, req.uri().path()) {
        match stub_action {
            MitmStubAction::Static(stub_response) => {
                info!("[mitm static stub] returning configured response for {access_label}{}", req.uri().path());
                let request_headers = req.headers().clone();
                capture_and_drain_mitm_request_body(
                    req.body_mut(),
                    &request_headers,
                    context.manager.clone(),
                    record_id.clone(),
                )
                .await?;
                return build_mitm_stub_response(stub_response, access_label, context.manager.clone(), record_id);
            }
            MitmStubAction::Dynamic(dynamic_stub) => {
                let client_upgrade = is_websocket.then(|| hyper::upgrade::on(&mut req));
                info!(
                    "[mitm dynamic stub] forwarding plaintext request for {access_label}{} to {}",
                    req.uri().path(),
                    dynamic_stub.upstream.url_base
                );
                return forward_to_dynamic_mitm_stub(
                    req,
                    dynamic_stub,
                    &context.stub_http1_client,
                    &context.stub_http2_client,
                    access_label,
                    request_authority,
                    context.manager.clone(),
                    record_id,
                    client_upgrade,
                    context.ipv6_first,
                )
                .await;
            }
        }
    }

    if is_websocket {
        let client_ip = get_client_ip(&req, client_socket_addr);
        return handle_mitm_websocket_upgrade(req, mitm_proxy_client, access_label, client_ip, context, record_id)
            .await;
    }

    let client_ip = get_client_ip(&req, client_socket_addr);
    let req = map_mitm_request_body(req, context.manager.clone(), record_id.clone());
    let response_result = if let Some(forward_bypass) = context.forward_bypass.as_ref() {
        mitm_proxy_client
            .send_request_via_forward_bypass(
                req,
                &access_label,
                forward_bypass,
                &client_ip,
                |stream: HttpClientStream, access_label: AccessLabel| {
                    CounterIO::new(stream, METRICS.proxy_traffic.clone(), LabelImpl::new(access_label))
                },
            )
            .await
    } else {
        mitm_proxy_client
            .send_request(
                req,
                &access_label,
                context.ipv6_first,
                |stream: HttpClientStream, access_label: AccessLabel| {
                    CounterIO::new(stream, METRICS.proxy_traffic.clone(), LabelImpl::new(access_label))
                },
            )
            .await
    };
    let resp = match response_result {
        Ok(response) => response,
        Err(error) => {
            if let Some(id) = record_id.as_ref() {
                context.manager.record_error(id, error.to_string());
            }
            return Err(error);
        }
    };
    record_response_head(&context.manager, record_id.as_deref(), &resp, None);
    Ok(map_mitm_response_body(resp, context.manager, record_id))
}

fn build_mitm_stub_response(
    stub_response: MitmStubResponse, access_label: AccessLabel, manager: Arc<MitmManager>, record_id: Option<String>,
) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
    let mut builder = Response::builder().status(stub_response.status);
    let headers = builder
        .headers_mut()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "MITM stub response builder has no headers"))?;
    for (name, value) in stub_response.headers {
        headers.insert(name, value);
    }
    headers.remove(TRANSFER_ENCODING);
    headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&stub_response.body.len().to_string())
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
    );
    let body =
        CounterBody::new(full_body(stub_response.body), METRICS.proxy_traffic.clone(), LabelImpl::new(access_label))
            .boxed();
    let response = builder
        .body(body)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    record_response_head(&manager, record_id.as_deref(), &response, None);
    Ok(map_boxed_mitm_response_body(response, manager, record_id))
}

#[allow(clippy::too_many_arguments)]
async fn forward_to_dynamic_mitm_stub(
    req: Request<Incoming>, dynamic_stub: MitmDynamicStub,
    stub_http1_client: &ReverseProxyClient<BoxBody<Bytes, io::Error>>,
    stub_http2_client: &ReverseProxyClient<BoxBody<Bytes, io::Error>>, access_label: AccessLabel,
    request_authority: String, manager: Arc<MitmManager>, record_id: Option<String>,
    client_upgrade: Option<hyper::upgrade::OnUpgrade>, ipv6_first: Option<bool>,
) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
    let original = mitm_original_origin(&request_authority)
        .map_err(|error| record_mitm_error(&manager, record_id.as_deref(), error))?;
    let BuiltUpstreamRequest {
        request: req,
        connection_key,
    } = build_upstream_req("", &dynamic_stub.upstream, req, &original)
        .map_err(|error| record_mitm_error(&manager, record_id.as_deref(), error))?;
    let request_is_upgrade = client_upgrade.is_some();
    if request_is_upgrade && connection_key.protocol != DirectProtocol::Http1 {
        return Err(record_mitm_error(
            &manager,
            record_id.as_deref(),
            io::Error::new(ErrorKind::InvalidInput, "WebSocket Upgrade dynamic MITM stub requires an H1 upstream"),
        ));
    }
    let stub_client = if connection_key.protocol == DirectProtocol::Http2 {
        stub_http2_client
    } else {
        stub_http1_client
    };
    let req = map_mitm_request_body(req, manager.clone(), record_id.clone());
    let response_result = if request_is_upgrade {
        stub_client
            .send_request_uncached(req, &connection_key, &access_label, ipv6_first)
            .await
    } else {
        stub_client
            .send_request(req, &connection_key, &access_label, ipv6_first)
            .await
    };
    let mut response = match response_result {
        Ok(response) => response,
        Err(error) => {
            let error = io::Error::new(
                ErrorKind::ConnectionRefused,
                format!("dynamic MITM stub upstream {} request failed: {error}", dynamic_stub.upstream.url_base),
            );
            return Err(record_mitm_error(&manager, record_id.as_deref(), error));
        }
    };
    record_response_head(&manager, record_id.as_deref(), &response, None);

    if let Some(client_upgrade) = client_upgrade {
        if response.status() == http::StatusCode::SWITCHING_PROTOCOLS {
            info!("[mitm dynamic stub] WebSocket upgrade successful for {access_label}");
            let upstream_upgrade = hyper::upgrade::on(&mut response);
            spawn_websocket_tunnel(client_upgrade, upstream_upgrade, None, "mitm dynamic stub");
            if let Some(id) = record_id.as_ref() {
                manager.finish_record(id, "upgraded");
            }
        } else {
            warn!("[mitm dynamic stub] WebSocket upgrade failed, upstream returned: {}", response.status());
        }
    }

    Ok(map_mitm_response_body(response, manager, record_id))
}

fn record_mitm_error(manager: &MitmManager, record_id: Option<&str>, error: io::Error) -> io::Error {
    if let Some(id) = record_id {
        manager.record_error(id, error.to_string());
    }
    error
}

fn mitm_original_origin(authority: &str) -> io::Result<SchemeHostPort> {
    let authority = authority
        .parse::<http::uri::Authority>()
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, format!("invalid MITM request authority: {error}")))?;
    Ok(SchemeHostPort {
        scheme: "https".to_owned(),
        host: authority.host().to_owned(),
        port: authority.port_u16(),
    })
}

async fn handle_mitm_websocket_upgrade(
    mut req: Request<Incoming>, mitm_proxy_client: ForwardProxyClient<BoxBody<Bytes, io::Error>>,
    access_label: AccessLabel, client_ip: String, context: MitmRequestContext, record_id: Option<String>,
) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
    debug!("[mitm] WebSocket upgrade request to {}", access_label.target);
    let client_upgrade = hyper::upgrade::on(&mut req);
    let req = map_mitm_request_body(req, context.manager.clone(), record_id.clone());
    let response_result = if let Some(forward_bypass) = context.forward_bypass.as_ref() {
        mitm_proxy_client
            .send_request_via_forward_bypass_http1_only(
                req,
                &access_label,
                forward_bypass,
                &client_ip,
                |stream: HttpClientStream, access_label: AccessLabel| {
                    CounterIO::new(stream, METRICS.proxy_traffic.clone(), LabelImpl::new(access_label))
                },
            )
            .await
    } else {
        mitm_proxy_client
            .send_request_http1_only(
                req,
                &access_label,
                context.ipv6_first,
                |stream: HttpClientStream, access_label: AccessLabel| {
                    CounterIO::new(stream, METRICS.proxy_traffic.clone(), LabelImpl::new(access_label))
                },
            )
            .await
    };
    let mut upstream_response = match response_result {
        Ok(response) => response,
        Err(error) => {
            if let Some(id) = record_id.as_ref() {
                context.manager.record_error(id, error.to_string());
            }
            return Err(error);
        }
    };
    record_response_head(
        &context.manager,
        record_id.as_deref(),
        &upstream_response,
        Some("WebSocket payload frames are not captured".to_owned()),
    );

    if upstream_response.status() != http::StatusCode::SWITCHING_PROTOCOLS {
        warn!("[mitm] WebSocket upgrade failed, upstream returned: {}", upstream_response.status());
        return Ok(map_mitm_response_body(upstream_response, context.manager, record_id));
    }

    let upstream_upgrade = hyper::upgrade::on(&mut upstream_response);
    spawn_websocket_tunnel(client_upgrade, upstream_upgrade, None, "mitm");
    if let Some(id) = record_id.as_ref() {
        context.manager.finish_record(id, "upgraded");
    }
    Ok(map_mitm_response_body(upstream_response, context.manager, record_id))
}

fn request_authority(request: &Request<Incoming>, fallback: &str) -> String {
    request
        .uri()
        .authority()
        .map(|authority| authority.as_str().to_owned())
        .or_else(|| {
            request
                .headers()
                .get(HOST)
                .and_then(|host| host.to_str().ok())
                .filter(|host| !host.is_empty())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| fallback.to_owned())
}

fn record_response_head<B>(
    manager: &MitmManager, record_id: Option<&str>, response: &Response<B>, body_note: Option<String>,
) {
    if let Some(id) = record_id {
        manager.response_head(
            id,
            ResponseHead {
                status: response.status().as_u16(),
                version: version_label(response.version()).to_owned(),
                headers_json: headers_json(response.headers()),
                body_note,
            },
        );
    }
}

fn mod_mitm_proxy_req<B>(req: &mut Request<B>, request_authority: &str) -> io::Result<()> {
    req.headers_mut().remove(http::header::PROXY_AUTHORIZATION.to_string());
    req.headers_mut().remove("Proxy-Connection");
    if req.version() == http::Version::HTTP_2 {
        if req.uri().scheme().is_none() || req.uri().authority().is_none() {
            let mut parts = req.uri().clone().into_parts();
            parts.scheme = Some(http::uri::Scheme::HTTPS);
            parts.authority = Some(
                request_authority
                    .parse()
                    .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?,
            );
            *req.uri_mut() = Uri::from_parts(parts).map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
        }
        return Ok(());
    }
    if !req.headers().contains_key(HOST) {
        let host_header =
            HeaderValue::from_str(request_authority).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        req.headers_mut().insert(HOST, host_header);
    }
    if req.uri().scheme().is_some() || req.uri().authority().is_some() {
        origin_form(req.uri_mut())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mitm_original_origin() -> Result<(), crate::DynError> {
        let origin = mitm_original_origin("api.example.com:8443")?;
        assert_eq!(origin.scheme, "https");
        assert_eq!(origin.host, "api.example.com");
        assert_eq!(origin.port, Some(8443));
        Ok(())
    }

    #[test]
    fn mitm_http2_request_preserves_original_authority_without_host() -> Result<(), crate::DynError> {
        let mut request = Request::builder()
            .uri("https://api.bilibili.com/space")
            .version(http::Version::HTTP_2)
            .body(())?;

        mod_mitm_proxy_req(&mut request, "api.bilibili.com")?;

        assert_eq!(request.uri().scheme_str(), Some("https"));
        assert_eq!(request.uri().authority().map(http::uri::Authority::as_str), Some("api.bilibili.com"));
        assert!(!request.headers().contains_key(HOST));
        Ok(())
    }

    #[test]
    fn mitm_http2_origin_form_uses_captured_authority_without_host() -> Result<(), crate::DynError> {
        let mut request = Request::builder()
            .uri("/space")
            .version(http::Version::HTTP_2)
            .body(())?;

        mod_mitm_proxy_req(&mut request, "api.bilibili.com")?;

        assert_eq!(request.uri().to_string(), "https://api.bilibili.com/space");
        assert!(!request.headers().contains_key(HOST));
        Ok(())
    }
}
