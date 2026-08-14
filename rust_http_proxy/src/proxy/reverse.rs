use std::{
    collections::HashMap,
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::LazyLock,
};

use axum::extract::Request;
use http::{Uri, header::LOCATION};
use http_body_util::BodyExt;
use hyper::{body::Incoming, http};
use log::{info, warn};
use prom_label::LabelImpl;

use crate::{
    METRICS,
    hyper_x::CounterBody,
    ip_x::SocketAddrFormat,
    location::{Upstream, build_upstream_req, handle_websocket_upgrade_reverse, normalize302},
};

use super::{
    handler::{InterceptResultAdapter, ProxyHandler},
    http::{SchemeHostPort, build_authenticate_resp, check_static_basic_auth, is_websocket_upgrade},
    labels::{AccessLabel, ReverseProxyReqLabel},
};

static ALL_REVERSE_PROXY_REQ: LazyLock<LabelImpl<ReverseProxyReqLabel>> = LazyLock::new(|| {
    LabelImpl::new(ReverseProxyReqLabel {
        client: "all".to_string(),
        origin: "all".to_string(),
        upstream: "all".to_string(),
    })
});

#[allow(unused)]
fn reverse_proxy_label_fn(uri: &Uri) -> LabelImpl<AccessLabel> {
    LabelImpl::new(AccessLabel {
        client: "reverse_proxy".to_owned(),
        target: uri.authority().map(|a| a.to_string()).unwrap_or_default(),
        username: "reverse_proxy".to_owned(),
        relay_over_tls: None,
    })
}

impl ProxyHandler {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn handle_reverse_proxy(
        &self, req: Request<Incoming>, client_socket_addr: SocketAddr, original_scheme_host_port: &SchemeHostPort,
        location: &str, upstream: &Upstream, basic_auth: &HashMap<String, String>, basic_auth_path_prefixes: &[String],
    ) -> Result<InterceptResultAdapter, io::Error> {
        let config = &self.config;
        let res = async {
            config.allow_cidrs.check_serving_control(client_socket_addr)?;
            let mut request = req;
            let authenticated_username = match check_static_basic_auth(
                request.headers(),
                request.uri().path(),
                basic_auth,
                basic_auth_path_prefixes,
            ) {
                Ok(username) => username,
                Err(e) => {
                    warn!(
                        "reverse proxy basic auth failed from {} for {}: {}",
                        SocketAddrFormat(&client_socket_addr),
                        request.uri().path(),
                        e
                    );
                    return Ok(build_authenticate_resp(false));
                }
            };
            // 只在当前路径实际使用了入口认证时移除凭据；未受保护路径保持原有透传行为。
            if authenticated_username.is_some() {
                request.headers_mut().remove(http::header::AUTHORIZATION);
            }
            // 创建流量统计标签
            let traffic_label = AccessLabel {
                client: client_socket_addr.ip().to_canonical().to_string(),
                target: upstream.url_base.clone(),
                username: authenticated_username.unwrap_or_else(|| "reverse_proxy".to_owned()),
                relay_over_tls: None,
            };

            // 先检测是否是 WebSocket 升级请求（在 request 被消费之前）
            let is_websocket = is_websocket_upgrade(&request);

            // 记录指标
            METRICS
                .reverse_proxy_req
                .get_or_create(&LabelImpl::new(ReverseProxyReqLabel {
                    client: client_socket_addr.ip().to_canonical().to_string(),
                    origin: original_scheme_host_port.to_string() + location,
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
                let client_upgrade_fut = hyper::upgrade::on(&mut request);
                let upstream_req = build_upstream_req(location, upstream, request, original_scheme_host_port)?;
                return handle_websocket_upgrade_reverse(
                    upstream_req,
                    client_upgrade_fut,
                    traffic_label,
                    &self.reverse_proxy_client,
                )
                .await;
            }

            let upstream_req = build_upstream_req(location, upstream, request, original_scheme_host_port)?;
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
            let upstream_req_method = upstream_req.method().clone();
            let upstream_req_uri = upstream_req.uri().clone();
            let upstream_req_version = upstream_req.version();
            info!(
                "[reverse] {:^35} ==> {} {:?} {:?} <== [{}{}]",
                SocketAddrFormat(&client_socket_addr).to_string(),
                upstream_req_method,
                upstream_req_uri,
                upstream_req_version,
                original_scheme_host_port,
                location,
            );

            match self.reverse_proxy_client.request(upstream_req).await {
                Ok(mut resp) => {
                    if resp.status().is_redirection() && resp.headers().contains_key(LOCATION) {
                        normalize302(original_scheme_host_port, resp.headers_mut(), config)?;
                        //修改302的location
                    }
                    info!(
                        "[reverse response] {:^35} ==> {} {:?} {:?} <== {} [{}{}]",
                        SocketAddrFormat(&client_socket_addr).to_string(),
                        upstream_req_method,
                        upstream_req_uri,
                        upstream_req_version,
                        resp.status(),
                        original_scheme_host_port,
                        location,
                    );

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
        .await;

        match res {
            Ok(resp) => Ok(InterceptResultAdapter::Return(resp)),
            Err(e) => match e.kind() {
                ErrorKind::PermissionDenied => Ok(InterceptResultAdapter::Drop),
                _ => Err(e),
            },
        }
    }
}
