use std::{io, io::ErrorKind, net::SocketAddr};

use axum::extract::Request;
use http::{
    Uri,
    header::{CONTENT_LENGTH, HOST, TRANSFER_ENCODING},
};
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::{
    Response, Version,
    body::{Bytes, Incoming},
    header::HeaderValue,
};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{self, connect::HttpConnector};
use io_x::CounterIO;
use log::{debug, info, warn};
use prom_label::LabelImpl;

use crate::{
    METRICS,
    config::ForwardBypassConfig,
    dns_resolver::CustomGaiDNSResolver,
    forward_proxy_client::ForwardProxyClient,
    hyper_x::CounterBody,
    ip_x::SocketAddrFormat,
    mitm::{MitmDynamicStub, MitmStubAction, MitmStubResponse, MitmStubSpecs},
    proxy::{
        connect::HttpClientStream,
        http::{full_body, get_client_ip, is_websocket_upgrade, origin_form},
        labels::AccessLabel,
        tunnel::spawn_websocket_tunnel,
    },
};

use super::dump::{
    dump_mitm_request_body, log_mitm_request_head, log_mitm_response_head, map_mitm_request_body,
    map_mitm_response_body, request_authority_for_log,
};

#[derive(Clone)]
pub(super) struct MitmRequestContext {
    pub(super) ipv6_first: Option<bool>,
    pub(super) forward_bypass: Option<ForwardBypassConfig>,
    pub(super) stub_specs: MitmStubSpecs,
    pub(super) stub_client:
        legacy::Client<HttpsConnector<HttpConnector<CustomGaiDNSResolver>>, BoxBody<Bytes, io::Error>>,
    pub(super) dump_plaintext: bool,
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
    let request_authority = request_authority_for_log(&req, &access_label).into_owned();
    mod_mitm_proxy_req(&mut req, &access_label.target)?;
    if context.dump_plaintext {
        log_mitm_request_head(&req, &access_label);
    }

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
                if context.dump_plaintext {
                    dump_mitm_request_body(req.body_mut(), &access_label).await?;
                }
                return build_mitm_stub_response(stub_response, access_label);
            }
            MitmStubAction::Dynamic(dynamic_stub) => {
                let client_upgrade = is_websocket.then(|| hyper::upgrade::on(&mut req));
                info!(
                    "[mitm dynamic stub] forwarding plaintext request for {access_label}{} to {}",
                    req.uri().path(),
                    dynamic_stub.upstream
                );
                return forward_to_dynamic_mitm_stub(
                    req,
                    dynamic_stub,
                    &context.stub_client,
                    access_label,
                    context.dump_plaintext,
                    client_upgrade,
                )
                .await;
            }
        }
    }

    if is_websocket {
        let client_ip = get_client_ip(&req, client_socket_addr);
        return handle_mitm_websocket_upgrade(
            req,
            mitm_proxy_client,
            access_label,
            context.ipv6_first,
            context.forward_bypass.as_ref(),
            client_ip,
            context.dump_plaintext,
        )
        .await;
    }

    let client_ip = get_client_ip(&req, client_socket_addr);
    let req = map_mitm_request_body(req, access_label.clone(), context.dump_plaintext);
    let resp = if let Some(forward_bypass) = context.forward_bypass.as_ref() {
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
            .await?
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
            .await?
    };
    if context.dump_plaintext {
        log_mitm_response_head(&resp, &access_label);
    }

    Ok(map_mitm_response_body(resp, access_label, context.dump_plaintext))
}

fn build_mitm_stub_response(
    stub_response: MitmStubResponse, access_label: AccessLabel,
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
    builder
        .body(body)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
}

async fn forward_to_dynamic_mitm_stub(
    mut req: Request<Incoming>, dynamic_stub: MitmDynamicStub,
    stub_client: &legacy::Client<HttpsConnector<HttpConnector<CustomGaiDNSResolver>>, BoxBody<Bytes, io::Error>>,
    access_label: AccessLabel, dump_plaintext: bool, client_upgrade: Option<hyper::upgrade::OnUpgrade>,
) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
    let upstream_uri = dynamic_stub_request_uri(&dynamic_stub.upstream, req.uri())?;
    *req.uri_mut() = upstream_uri;
    *req.version_mut() = Version::HTTP_11;
    let req = map_mitm_request_body(req, access_label.clone(), dump_plaintext);
    let mut response = stub_client.request(req).await.map_err(|e| {
        io::Error::new(
            ErrorKind::ConnectionRefused,
            format!("dynamic MITM stub upstream {} request failed: {e}", dynamic_stub.upstream),
        )
    })?;
    if dump_plaintext {
        log_mitm_response_head(&response, &access_label);
    }

    if let Some(client_upgrade) = client_upgrade {
        if response.status() == http::StatusCode::SWITCHING_PROTOCOLS {
            info!("[mitm dynamic stub] WebSocket upgrade successful for {access_label}");
            let upstream_upgrade = hyper::upgrade::on(&mut response);
            spawn_websocket_tunnel(client_upgrade, upstream_upgrade, None, "mitm dynamic stub");
        } else {
            warn!("[mitm dynamic stub] WebSocket upgrade failed, upstream returned: {}", response.status());
        }
    }

    Ok(map_mitm_response_body(response, access_label, dump_plaintext))
}

fn dynamic_stub_request_uri(upstream: &Uri, original: &Uri) -> io::Result<Uri> {
    let scheme = upstream
        .scheme_str()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "dynamic MITM stub upstream has no scheme"))?;
    let authority = upstream
        .authority()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "dynamic MITM stub upstream has no authority"))?;
    let upstream_path = upstream.path().trim_end_matches('/');
    let original_path = original.path();
    let path = if upstream_path.is_empty() {
        original_path.to_owned()
    } else if original_path == "/" {
        format!("{upstream_path}/")
    } else {
        format!("{upstream_path}{original_path}")
    };
    let path_and_query = match original.query() {
        Some(query) => format!("{path}?{query}"),
        None => path,
    };
    Uri::builder()
        .scheme(scheme)
        .authority(authority.clone())
        .path_and_query(path_and_query)
        .build()
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
}

async fn handle_mitm_websocket_upgrade(
    mut req: Request<Incoming>, mitm_proxy_client: ForwardProxyClient<BoxBody<Bytes, io::Error>>,
    access_label: AccessLabel, ipv6_first: Option<bool>, forward_bypass: Option<&ForwardBypassConfig>,
    client_ip: String, dump_plaintext: bool,
) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
    debug!("[mitm] WebSocket upgrade request to {}", access_label.target);
    if dump_plaintext {
        info!("[mitm plaintext websocket] upgraded streams are tunneled without body dump: {access_label}");
    }
    let client_upgrade = hyper::upgrade::on(&mut req);
    let req = map_mitm_request_body(req, access_label.clone(), dump_plaintext);
    let mut upstream_response = if let Some(forward_bypass) = forward_bypass {
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
            .await?
    } else {
        mitm_proxy_client
            .send_request_http1_only(
                req,
                &access_label,
                ipv6_first,
                |stream: HttpClientStream, access_label: AccessLabel| {
                    CounterIO::new(stream, METRICS.proxy_traffic.clone(), LabelImpl::new(access_label))
                },
            )
            .await?
    };
    if dump_plaintext {
        log_mitm_response_head(&upstream_response, &access_label);
    }

    if upstream_response.status() != http::StatusCode::SWITCHING_PROTOCOLS {
        warn!("[mitm] WebSocket upgrade failed, upstream returned: {}", upstream_response.status());
        return Ok(map_mitm_response_body(upstream_response, access_label, dump_plaintext));
    }

    let upstream_upgrade = hyper::upgrade::on(&mut upstream_response);
    spawn_websocket_tunnel(client_upgrade, upstream_upgrade, None, "mitm");
    Ok(map_mitm_response_body(upstream_response, access_label, dump_plaintext))
}

fn mod_mitm_proxy_req(req: &mut Request<Incoming>, target_authority: &str) -> io::Result<()> {
    req.headers_mut().remove(http::header::PROXY_AUTHORIZATION.to_string());
    req.headers_mut().remove("Proxy-Connection");
    if !req.headers().contains_key(HOST) {
        let host_header =
            HeaderValue::from_str(target_authority).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
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
    fn dynamic_stub_request_uri_preserves_path_and_query() -> Result<(), crate::DynError> {
        let upstream = "http://127.0.0.1:9010/stub".parse::<Uri>()?;
        let original = "/v1/profile?user=42".parse::<Uri>()?;

        let uri = dynamic_stub_request_uri(&upstream, &original)?;

        assert_eq!(uri, "http://127.0.0.1:9010/stub/v1/profile?user=42");
        Ok(())
    }

    #[test]
    fn dynamic_stub_request_uri_without_prefix_uses_original_path() -> Result<(), crate::DynError> {
        let upstream = "http://127.0.0.1:9010".parse::<Uri>()?;
        let original = "/v1/profile".parse::<Uri>()?;

        let uri = dynamic_stub_request_uri(&upstream, &original)?;

        assert_eq!(uri, "http://127.0.0.1:9010/v1/profile");
        Ok(())
    }
}
