use std::{
    borrow::Cow,
    io::{self, ErrorKind},
    net::SocketAddr,
};

use axum::extract::Request;
use http_body_util::BodyExt;
use hyper::{body::Incoming, http};
use percent_encoding::percent_decode_str;
use prom_label::LabelImpl;

use crate::{METRICS, axum_handler, location::LocationAuth, static_serve};

use super::{
    handler::{InterceptResultAdapter, ProxyHandler},
    http::{LocationAccess, authorize_location},
    labels::AccessLabel,
};

impl ProxyHandler {
    pub(super) async fn handle_static_serving(
        &self, req: Request<Incoming>, client_socket_addr: SocketAddr, location: &str, static_dir: &str,
        auth: &LocationAuth,
    ) -> Result<InterceptResultAdapter, io::Error> {
        let config = &self.config;
        let res = async {
            if axum_handler::AXUM_PATHS.contains(&req.uri().path()) {
                config.allow_cidrs.check_serving_control(client_socket_addr)?;
                return static_serve::not_found().map_err(|e| io::Error::new(ErrorKind::InvalidData, e));
            }

            // 创建流量统计标签
            let raw_path = req.uri().path();
            let request_path = percent_decode_str(raw_path)
                .decode_utf8()
                .unwrap_or(Cow::from(raw_path));
            let username = match authorize_location(
                &config.allow_cidrs,
                client_socket_addr,
                req.headers(),
                request_path.as_ref(),
                auth,
                "static",
            )? {
                LocationAccess::Allowed(username) => username,
                LocationAccess::Challenge(response) => return Ok(response),
            };
            // Some(username) 表示该路径命中认证前缀且已通过认证，响应需要禁止缓存
            let auth_protected = username.is_some();
            let username = username.unwrap_or_else(|| "static_serving".to_owned());
            let traffic_label = AccessLabel::new(client_socket_addr, static_dir, username, None);

            #[allow(clippy::expect_used)]
            let path = request_path.strip_prefix(location).expect("should start with location");
            let path = "/".to_string() + path;
            let resp =
                static_serve::serve_http_request(&req, client_socket_addr, &path, static_dir, config, auth_protected)
                    .await
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;

            // 使用 CounterBody 包装响应 body 来统计响应流量
            Ok(resp.map(|body| {
                let counter_body = crate::hyper_x::CounterBody::new(
                    body,
                    METRICS.proxy_traffic.clone(),
                    LabelImpl::new(traffic_label),
                );
                counter_body.boxed()
            }))
        }
        .await;

        match res {
            Ok(resp) => {
                if resp.status() == http::StatusCode::NOT_FOUND {
                    Ok(InterceptResultAdapter::Continue(req))
                } else {
                    Ok(InterceptResultAdapter::Return(resp))
                }
            }
            Err(error) => InterceptResultAdapter::from_gate_error(error),
        }
    }
}
