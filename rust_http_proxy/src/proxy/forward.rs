use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
};

use crate::{METRICS, address::host_addr, axum_handler, config::ForwardBypassConfig, forward_proxy_client::Route};
use {io_x::CounterIO, prom_label::LabelImpl};

use axum::extract::Request;
use http::{header::HOST, header::HeaderValue};
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::{Method, Response, body::Bytes, http};
use hyper_util::rt::TokioIo;
use log::{debug, info, warn};

use super::connect::bypass_endpoint;
use super::handler::{InterceptResultAdapter, ProxyHandler};
use super::http::{
    boxed_io_body, build_authenticate_resp, first_forwarded_for, get_client_ip, invalid_connect_target,
    is_schema_secure, is_websocket_upgrade, origin_form, text_response,
};
use super::labels::AccessLabel;
use super::padding::connect_established;
use super::parent_connect::{ParentTunnelError, open_parent_tunnel};
use super::tunnel::{dial_direct_tunnel, promote_websocket_upgrade, tunnel};

impl ProxyHandler {
    fn should_mitm(&self, req: &Request<Incoming>) -> bool {
        let Some(addr) = host_addr(req.uri()) else {
            return false;
        };
        self.mitm_manager.should_mitm(&addr.host())
    }

    pub(super) async fn handle_forward_proxy(
        &self, req: Request<Incoming>, client_socket_addr: SocketAddr,
    ) -> Result<InterceptResultAdapter, io::Error> {
        let username =
            match axum_handler::check_auth(req.headers(), http::header::PROXY_AUTHORIZATION, &self.config.basic_auth) {
                Ok(username) => username.unwrap_or("unknown".to_owned()),
                Err(e) => {
                    warn!("auth check from {} error: {}", { client_socket_addr }, e);
                    return if self.config.never_ask_for_auth {
                        Err(io::Error::new(ErrorKind::PermissionDenied, "wrong basic auth, closing socket..."))
                    } else {
                        Ok(InterceptResultAdapter::Return(build_authenticate_resp(true)))
                    };
                }
            };
        self.record_forward_request(&req, client_socket_addr, &username);

        let response = if req.method() == Method::CONNECT {
            if self.should_mitm(&req) {
                self.mitm_proxy(req, client_socket_addr, username)
            } else if let Some(bypass) = self.config.forward_bypass.as_ref() {
                self.tunnel_proxy_bypass(req, client_socket_addr, username, bypass)
                    .await
            } else {
                self.tunnel_proxy(req, client_socket_addr, username)
            }
        } else {
            self.simple_proxy(req, client_socket_addr, username).await
        };
        response.map(InterceptResultAdapter::Return)
    }

    fn record_forward_request(&self, req: &Request<Incoming>, client_socket_addr: SocketAddr, username: &str) {
        if let Some(addr) = host_addr(req.uri()) {
            let url = if req.method() == Method::CONNECT {
                format!("https://{}/", req.uri())
            } else {
                req.uri().to_string()
            };
            self.mitm_manager.record_proxy_request(
                get_client_ip(req, client_socket_addr),
                req.method().to_string(),
                url,
                addr.host(),
            );
        }
        info!(
            "{:>29} {:<5} {:^8} {:^7} {:?} {:?} {} {}",
            "https://ip.im/".to_owned() + &client_socket_addr.ip().to_canonical().to_string(),
            client_socket_addr.port(),
            username,
            req.method().as_str(),
            req.uri(),
            req.version(),
            first_forwarded_for(req.headers())
                .map(|first_ip| format!("X-Forwarded-For: https://ip.im/{first_ip}"))
                .unwrap_or_default(),
            match &self.config.forward_bypass {
                Some(bypass) => format!("bypass: {bypass}"),
                None => "".to_owned(),
            }
        );
    }

    /// 处理 WebSocket 升级请求（正向代理场景）
    async fn handle_websocket_upgrade_forward(
        &self, mut req: Request<Incoming>, traffic_label: AccessLabel, ipv6_first: Option<bool>,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        debug!("[forward] WebSocket upgrade request to {}", traffic_label.target);

        // 在消费 request 之前先获取客户端的 upgrade future
        let client_upgrade = hyper::upgrade::on(&mut req);

        let mut upstream_response = self
            .forward_proxy_client
            .send_upgrade_request(req, &traffic_label, Route::Direct { ipv6_first })
            .await?;

        if !promote_websocket_upgrade(&mut upstream_response, client_upgrade, None, "forward") {
            warn!("[forward] WebSocket upgrade failed, upstream returned: {}", upstream_response.status());
            return Err(io::Error::other(format!("WebSocket upgrade failed: {}", upstream_response.status())));
        }

        info!("[forward] WebSocket upgrade successful, status: {}", upstream_response.status());
        Ok(upstream_response.map(boxed_io_body))
    }

    /// 代理普通请求
    /// HTTP/1.1 GET/POST/PUT/DELETE/HEAD
    /// 配置了 forward_bypass 时请求保持 absolute-form，直接发给父代理。
    async fn simple_proxy(
        &self, mut req: Request<Incoming>, client_socket_addr: SocketAddr, username: String,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        // 先检测是否是 WebSocket 升级请求（在 request 被消费之前）
        let is_websocket = is_websocket_upgrade(&req);
        let bypass = self.config.forward_bypass.as_ref();
        let (access_label, ipv6_first) = match bypass {
            Some(bypass) => {
                prepare_bypass_http_req(&mut req, bypass)?;
                let label =
                    AccessLabel::new(client_socket_addr, bypass_endpoint(bypass), username, Some(bypass.is_https));
                (label, bypass.ipv6_first)
            }
            None => {
                let addr = host_addr(req.uri()).ok_or_else(|| {
                    io::Error::new(ErrorKind::InvalidData, format!("URI missing host: {}", req.uri()))
                })?;
                mod_http1_proxy_req(&mut req)?;
                (AccessLabel::new(client_socket_addr, addr.to_string(), username, None), self.config.ipv6_first)
            }
        };

        if is_websocket {
            info!(
                "[{}] WebSocket upgrade request: {:^35} ==> {} {:?}",
                if bypass.is_some() { "forward_bypass" } else { "forward" },
                client_socket_addr.to_string(),
                req.method(),
                req.uri(),
            );
            return self
                .handle_websocket_upgrade_forward(req, access_label, ipv6_first)
                .await;
        }

        if bypass.is_some() {
            warn!("bypass {:?} {} {}", req.version(), req.method(), req.uri());
        }
        let result = self
            .forward_proxy_client
            .send_request(req, &access_label, Route::Direct { ipv6_first })
            .await;
        if let (Some(_), Err(e)) = (bypass, &result) {
            warn!("[forward_bypass simple_proxy error] [{}]: [{}] {} ", access_label, e.kind(), e);
        }
        result.map(|resp| resp.map(boxed_io_body))
    }

    async fn tunnel_proxy_bypass(
        &self, req: Request<Incoming>, client_socket_addr: SocketAddr, username: String,
        forward_bypass_config: &ForwardBypassConfig,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        let Some(addr) = host_addr(req.uri()) else {
            return Ok(invalid_connect_target(req.uri()));
        };
        let access_label = AccessLabel::new(
            client_socket_addr,
            bypass_endpoint(forward_bypass_config),
            username,
            Some(forward_bypass_config.is_https),
        );
        let access_tag = access_label.to_string();
        let client_ip = get_client_ip(&req, client_socket_addr);
        // 握手字节也计入流量，所以在写 CONNECT 之前包 CounterIO。
        let counted = |stream| CounterIO::new(stream, METRICS.proxy_traffic.clone(), LabelImpl::new(access_label));
        let dst_stream =
            match open_parent_tunnel(forward_bypass_config, &addr.to_string(), &client_ip, true, counted).await {
                Ok(stream) => stream,
                Err(ParentTunnelError::Dial(e)) => {
                    warn!("[forward_bypass tunnel establish error] [{}]: [{}] {} ", access_tag, e.kind(), e);
                    return Ok(text_response(http::StatusCode::BAD_GATEWAY, "Failed to connect to bypass server"));
                }
                Err(ParentTunnelError::Tls(e)) if e.kind() == ErrorKind::InvalidInput => return Err(e),
                Err(ParentTunnelError::Tls(_)) => {
                    return Ok(text_response(
                        http::StatusCode::BAD_GATEWAY,
                        "Failed to establish TLS connection to bypass server",
                    ));
                }
                Err(ParentTunnelError::Handshake(e)) => {
                    warn!("[forward_bypass unexpected response] [{}]: {}", access_tag, e);
                    return Err(e);
                }
            };

        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(src_upgraded) => {
                    if let Err(e) = tunnel(TokioIo::new(src_upgraded), dst_stream).await {
                        warn!("[forward_bypass tunnel io error] [{}]: [{}] {} ", access_tag, e.kind(), e);
                    }
                }
                Err(e) => warn!("[forward_bypass upgrade error] [{}]: {}", access_tag, e),
            }
        });
        Ok(connect_established())
    }

    /// 代理CONNECT请求
    /// HTTP/1.1 CONNECT
    fn tunnel_proxy(
        &self, req: Request<Incoming>, client_socket_addr: SocketAddr, username: String,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        // Received an HTTP request like:
        // ```
        // CONNECT www.domain.com:443 HTTP/1.1
        // Host: www.domain.com:443
        // Proxy-Connection: Keep-Alive
        // ```
        //
        // When HTTP method is CONNECT we should return an empty body
        // then we can eventually upgrade the connection and talk a new protocol.
        //
        // Note: only after client received an empty body with STATUS_OK can the
        // connection be upgraded, so we can't return a response inside
        // `on_upgrade` future.
        let Some(addr) = host_addr(req.uri()) else {
            return Ok(invalid_connect_target(req.uri()));
        };
        let ipv6_first = self.config.ipv6_first;
        tokio::task::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(src_upgraded) => {
                    let access_label = AccessLabel::new(client_socket_addr, addr.to_string(), username, None);
                    let access_tag = access_label.to_string();
                    // if the DST server did not respond the FIN(shutdown) from the SRC client, then you will see a pair of FIN-WAIT-2 and CLOSE_WAIT in the proxy server
                    // which two socketAddrs are in the true path.
                    // use this command to check:
                    // netstat -ntp|grep -E "CLOSE_WAIT|FIN_WAIT"|sort
                    // The DST server should answer for this problem, becasue it ignores the FIN
                    // Dont worry, after the FIN_WAIT_2 timeout, the CLOSE_WAIT connection will close.
                    match dial_direct_tunnel("tunnel", access_label, client_socket_addr, ipv6_first).await {
                        Ok(dst_stream) => {
                            if let Err(e) = tunnel(TokioIo::new(src_upgraded), dst_stream).await {
                                warn!("[tunnel io error] [{}]: [{}] {} ", access_tag, e.kind(), e);
                            }
                        }
                        Err(e) => warn!("[tunnel establish error] [{}]: [{}] {} ", access_tag, e.kind(), e),
                    }
                }
                Err(e) => warn!("upgrade error: {e}"),
            }
        });
        Ok(connect_established())
    }
}

/// 交给父代理的普通请求：换上父代理凭据，Host 改为父代理地址。
fn prepare_bypass_http_req<B>(req: &mut Request<B>, bypass: &ForwardBypassConfig) -> io::Result<()> {
    if let Some(credentials) = bypass.proxy_authorization() {
        let value = HeaderValue::from_str(&credentials).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        if req
            .headers_mut()
            .insert(http::header::PROXY_AUTHORIZATION, value)
            .is_some()
        {
            info!("replace client Proxy-Authorization header with forward bypass credentials");
        }
    }
    let host_header =
        HeaderValue::from_str(&bypass_endpoint(bypass)).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    let origin = req.headers_mut().insert(HOST, host_header.clone());
    if Some(&host_header) != origin.as_ref() {
        info!("change host header: {origin:?} -> {host_header:?}");
    }
    Ok(())
}

fn mod_http1_proxy_req<B>(req: &mut Request<B>) -> io::Result<()> {
    // 删除代理特有的请求头
    req.headers_mut().remove(http::header::PROXY_AUTHORIZATION.to_string());
    req.headers_mut().remove("Proxy-Connection");
    // set host header
    let uri = req.uri().clone();
    let hostname = uri
        .host()
        .ok_or(io::Error::new(ErrorKind::InvalidData, "host is absent in HTTP/1.1"))?;
    let host_header = if let Some(port) = match (uri.port().map(|p| p.as_u16()), is_schema_secure(&uri)) {
        (Some(443), true) => None,
        (Some(80), false) => None,
        _ => uri.port(),
    } {
        let s = format!("{hostname}:{port}");
        HeaderValue::from_str(&s)
    } else {
        HeaderValue::from_str(hostname)
    }
    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    let origin = req.headers_mut().insert(HOST, host_header.clone());
    if Some(host_header.clone()) != origin {
        info!("change host header: {origin:?} -> {host_header:?}");
    }
    // change absoulte uri to relative uri
    origin_form(req.uri_mut());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewritten(uri: &str) -> Result<Request<()>, crate::DynError> {
        let mut req = Request::builder()
            .uri(uri)
            .header(http::header::PROXY_AUTHORIZATION, "Basic abc")
            .header("Proxy-Connection", "keep-alive")
            .header(HOST, "client-supplied.invalid")
            .body(())?;
        mod_http1_proxy_req(&mut req)?;
        Ok(req)
    }

    #[test]
    fn http1_proxy_request_derives_host_and_omits_default_port() -> Result<(), crate::DynError> {
        for (uri, host, path) in [
            ("http://example.com/a?b", "example.com", "/a?b"),
            ("http://example.com:80/a", "example.com", "/a"),
            ("http://example.com:8080/a", "example.com:8080", "/a"),
            ("https://example.com:443/", "example.com", "/"),
            ("https://example.com:80/", "example.com:80", "/"),
            ("ws://example.com:80/ws", "example.com", "/ws"),
            ("wss://example.com:443/ws", "example.com", "/ws"),
            ("http://[::1]:8080/a", "[::1]:8080", "/a"),
        ] {
            let req = rewritten(uri)?;
            assert_eq!(req.headers().get(HOST).and_then(|v| v.to_str().ok()), Some(host), "uri {uri}");
            assert_eq!(req.uri().to_string(), path, "uri {uri}");
        }
        Ok(())
    }

    #[test]
    fn http1_proxy_request_strips_proxy_headers() -> Result<(), crate::DynError> {
        let req = rewritten("http://example.com/")?;
        assert!(!req.headers().contains_key(http::header::PROXY_AUTHORIZATION));
        assert!(!req.headers().contains_key("proxy-connection"));
        Ok(())
    }
}
