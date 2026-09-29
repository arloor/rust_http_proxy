use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
};

use crate::{METRICS, address::host_addr, axum_handler, config::ForwardBypassConfig};
use {io_x::CounterIO, prom_label::LabelImpl};

use axum::extract::Request;
use http::{header::HOST, header::HeaderValue};
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::{Method, Response, body::Bytes, http};
use hyper_util::rt::TokioIo;
use log::{debug, info, warn};

use super::connect::{HttpClientStream, bypass_endpoint, into_bypass_stream};
use super::handler::{InterceptResultAdapter, ProxyHandler};
use super::http::{
    boxed_io_body, build_authenticate_resp, empty_body, full_body, get_client_ip, is_schema_secure,
    is_websocket_upgrade, origin_form,
};
use super::labels::AccessLabel;
use super::padding::append_random_padding_headers;
use super::parent_connect::{ParentConnect, complete_parent_connect};
use super::tunnel::{dial_timed_tunnel, log_tunnel_path, promote_websocket_upgrade, tunnel};

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
        let config_basic_auth = &self.config.basic_auth;
        let never_ask_for_auth = self.config.never_ask_for_auth;

        match axum_handler::check_auth(req.headers(), http::header::PROXY_AUTHORIZATION, config_basic_auth) {
            Ok(username_option) => {
                let username = username_option.unwrap_or("unknown".to_owned());
                if let Some(addr) = host_addr(req.uri()) {
                    let method = req.method().to_string();
                    let url = if req.method() == Method::CONNECT {
                        format!("https://{}/", req.uri())
                    } else {
                        req.uri().to_string()
                    };
                    self.mitm_manager.record_proxy_request(
                        get_client_ip(&req, client_socket_addr),
                        method,
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
                    req.headers()
                        .get("X-Forwarded-For")
                        .map(|v| {
                            // 取 X-Forwarded-For 中以逗号分隔的第一个 IP，并去除空白
                            let first_ip = v
                                .to_str()
                                .unwrap_or("invalid utf8")
                                .split(',')
                                .next()
                                .unwrap_or("invalid utf8")
                                .trim();
                            format!("X-Forwarded-For: https://ip.im/{}", first_ip)
                        })
                        .unwrap_or_default(),
                    match &self.config.forward_bypass {
                        Some(bypass) => {
                            format!("bypass: {}", bypass)
                        }
                        None => "".to_owned(),
                    }
                );

                match *req.method() {
                    Method::CONNECT => {
                        if self.should_mitm(&req) {
                            self.mitm_proxy(req, client_socket_addr, username)
                                .map(InterceptResultAdapter::Return)
                        } else {
                            match self.config.forward_bypass.as_ref() {
                                Some(forward_bypass_config) => {
                                    let result = self
                                        .tunnel_proxy_bypass(req, client_socket_addr, username, forward_bypass_config)
                                        .await;
                                    result.map(InterceptResultAdapter::Return)
                                }
                                None => self
                                    .tunnel_proxy(req, client_socket_addr, username)
                                    .map(InterceptResultAdapter::Return),
                            }
                        }
                    }
                    _ => match self.config.forward_bypass.as_ref() {
                        Some(forward_bypass_config) => {
                            let result = self
                                .simple_proxy_bypass(req, client_socket_addr, username, forward_bypass_config)
                                .await;
                            result.map(InterceptResultAdapter::Return)
                        }
                        None => self
                            .simple_proxy(req, client_socket_addr, username)
                            .await
                            .map(InterceptResultAdapter::Return),
                    },
                }
            }
            Err(e) => {
                warn!("auth check from {} error: {}", { client_socket_addr }, e);
                if never_ask_for_auth {
                    Err(io::Error::new(ErrorKind::PermissionDenied, "wrong basic auth, closing socket..."))
                } else {
                    Ok(InterceptResultAdapter::Return(build_authenticate_resp(true)))
                }
            }
        }
    }

    /// 处理 WebSocket 升级请求（正向代理场景）
    pub(super) async fn handle_websocket_upgrade_forward(
        &self, mut req: Request<Incoming>, traffic_label: AccessLabel,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        debug!("[forward] WebSocket upgrade request to {}", traffic_label.target);

        // 在消费 request 之前先获取客户端的 upgrade future
        let client_upgrade = hyper::upgrade::on(&mut req);

        // 使用 send_request_no_cache 发送请求
        let mut upstream_response = self
            .forward_proxy_client
            .send_request_http1_only(
                req,
                &traffic_label,
                self.config.ipv6_first,
                |stream: HttpClientStream, access_label: AccessLabel| {
                    CounterIO::new(stream, METRICS.proxy_traffic.clone(), LabelImpl::new(access_label))
                },
            )
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
    pub(super) async fn simple_proxy(
        &self, mut req: Request<Incoming>, client_socket_addr: SocketAddr, username: String,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        let addr = host_addr(req.uri())
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, format!("URI missing host: {}", req.uri())))?;
        let access_label = AccessLabel {
            client: client_socket_addr.ip().to_canonical().to_string(),
            target: addr.to_string(),
            username,
            relay_over_tls: None,
        };

        // 先检测是否是 WebSocket 升级请求（在 request 被消费之前）
        let is_websocket = is_websocket_upgrade(&req);

        mod_http1_proxy_req(&mut req)?;
        if is_websocket {
            info!(
                "[forward] WebSocket upgrade request: {:^35} ==> {} {:?}",
                client_socket_addr.to_string(),
                req.method(),
                req.uri(),
            );

            return self.handle_websocket_upgrade_forward(req, access_label).await;
        }

        match self
            .forward_proxy_client
            .send_request(
                req,
                &access_label,
                self.config.ipv6_first,
                |stream: HttpClientStream, access_label: AccessLabel| {
                    CounterIO::new(stream, METRICS.proxy_traffic.clone(), LabelImpl::new(access_label))
                },
            )
            .await
        {
            Ok(resp) => Ok(resp.map(boxed_io_body)),
            Err(e) => Err(e),
        }
    }

    pub(super) async fn simple_proxy_bypass(
        &self, mut req: Request<Incoming>, client_socket_addr: SocketAddr, username: String,
        forward_bypass_config: &ForwardBypassConfig,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        let host = format!("{}:{}", forward_bypass_config.host, forward_bypass_config.port);
        let access_label = AccessLabel {
            client: client_socket_addr.ip().to_canonical().to_string(),
            target: host.clone(),
            username,
            relay_over_tls: Some(forward_bypass_config.is_https),
        };

        // 先检测是否是 WebSocket 升级请求（在 request 被消费之前）
        let is_websocket = is_websocket_upgrade(&req);

        // 如果配置了 username 和 password，添加 Proxy-Authorization 头
        if let (Some(username), Some(password)) = (&forward_bypass_config.username, &forward_bypass_config.password) {
            let credentials = format!("{}:{}", username, password);
            let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, credentials.as_bytes());
            if let Some(original) = req.headers_mut().insert(
                http::header::PROXY_AUTHORIZATION,
                HeaderValue::from_str(format!("Basic {}", encoded).as_str())
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?,
            ) {
                info!("change Proxy-Authorization header: {original:?} -> \"Basic {}\"", encoded);
            };
        }
        // 替换host头
        let host_header = HeaderValue::from_str(&host).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        let origin = req.headers_mut().insert(HOST, host_header.clone());
        if Some(host_header.clone()) != origin {
            info!("change host header: {origin:?} -> {host_header:?}");
        }

        if is_websocket {
            info!(
                "[forward_bypass] WebSocket upgrade request: {:^35} ==> {} {:?}",
                client_socket_addr.to_string(),
                req.method(),
                req.uri(),
            );

            return self.handle_websocket_upgrade_forward(req, access_label).await;
        }

        warn!("bypass {:?} {} {}", req.version(), req.method(), req.uri());

        match self
            .forward_proxy_client
            .send_request(
                req,
                &access_label,
                forward_bypass_config.ipv6_first,
                |stream: HttpClientStream, access_label: AccessLabel| {
                    CounterIO::new(stream, METRICS.proxy_traffic.clone(), LabelImpl::new(access_label))
                },
            )
            .await
        {
            Ok(resp) => Ok(resp.map(boxed_io_body)),
            Err(e) => {
                warn!("[forward_bypass simple_proxy error] [{}]: [{}] {} ", access_label, e.kind(), e);
                Err(e)
            }
        }
    }

    pub(super) async fn tunnel_proxy_bypass(
        &self, req: Request<Incoming>, client_socket_addr: SocketAddr, username: String,
        forward_bypass_config: &ForwardBypassConfig,
    ) -> Result<Response<BoxBody<Bytes, io::Error>>, io::Error> {
        let proxy_traffic = METRICS.proxy_traffic.clone();

        match host_addr(req.uri()) {
            None => {
                warn!("CONNECT host is not socket addr: {:?}", req.uri());
                let mut resp = Response::new(full_body("CONNECT must be to a socket address"));
                *resp.status_mut() = http::StatusCode::BAD_REQUEST;
                Ok(resp)
            }
            Some(addr) => {
                let bypass_host = bypass_endpoint(forward_bypass_config);
                let access_label = AccessLabel {
                    client: client_socket_addr.ip().to_canonical().to_string(),
                    target: bypass_host.clone(),
                    username,
                    relay_over_tls: Some(forward_bypass_config.is_https),
                };

                let tcp_stream = match dial_timed_tunnel(&bypass_host, forward_bypass_config.ipv6_first).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        warn!("[forward_bypass tunnel establish error] [{}]: [{}] {} ", access_label, e.kind(), e);
                        let mut resp = Response::new(full_body("Failed to connect to bypass server"));
                        *resp.status_mut() = http::StatusCode::BAD_GATEWAY;
                        return Ok(resp);
                    }
                };
                log_tunnel_path("forward_bypass tunnel", &access_label, client_socket_addr, tcp_stream.peer_addr());
                let access_tag = access_label.to_string();

                let stream = match into_bypass_stream(forward_bypass_config, tcp_stream).await {
                    Ok(stream) => stream,
                    Err(error) if error.kind() == ErrorKind::InvalidInput => return Err(error),
                    Err(_) => {
                        let mut resp = Response::new(full_body("Failed to establish TLS connection to bypass server"));
                        *resp.status_mut() = http::StatusCode::BAD_GATEWAY;
                        return Ok(resp);
                    }
                };

                // 握手字节也计入流量，所以先包 CounterIO 再写 CONNECT。
                let counted = CounterIO::new(stream, proxy_traffic.clone(), LabelImpl::new(access_label.clone()));
                let client_ip = get_client_ip(&req, client_socket_addr);
                let target = addr.to_string();
                let dst_stream = match complete_parent_connect(
                    counted,
                    ParentConnect {
                        target: &target,
                        client_ip: &client_ip,
                        username: forward_bypass_config.username.as_deref(),
                        password: forward_bypass_config.password.as_deref(),
                    },
                )
                .await
                {
                    Ok(stream) => stream,
                    Err(error) => {
                        warn!("[forward_bypass unexpected response] [{}]: {}", access_tag, error);
                        return Err(error);
                    }
                };

                tokio::task::spawn(async move {
                    let src_upgraded = match hyper::upgrade::on(req).await {
                        Ok(src_upgraded) => src_upgraded,
                        Err(e) => {
                            warn!("[forward_bypass upgrade error] [{}]: {}", access_tag, e);
                            return Err(io::Error::other(e));
                        }
                    };

                    if let Err(e) = tunnel(TokioIo::new(src_upgraded), dst_stream).await {
                        warn!("[forward_bypass tunnel io error] [{}]: [{}] {} ", access_tag, e.kind(), e);
                    };
                    Ok(())
                });
                let mut response = Response::new(empty_body());
                append_random_padding_headers(response.headers_mut());
                Ok(response)
            }
        }
    }

    /// 代理CONNECT请求
    /// HTTP/1.1 CONNECT
    pub(super) fn tunnel_proxy(
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
        if let Some(addr) = host_addr(req.uri()) {
            let proxy_traffic = METRICS.proxy_traffic.clone();
            let ipv6_first = self.config.ipv6_first;
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(src_upgraded) => {
                        let access_label = AccessLabel {
                            client: client_socket_addr.ip().to_canonical().to_string(),
                            target: addr.clone().to_string(),
                            username,
                            relay_over_tls: None,
                        };
                        // if the DST server did not respond the FIN(shutdown) from the SRC client, then you will see a pair of FIN-WAIT-2 and CLOSE_WAIT in the proxy server
                        // which two socketAddrs are in the true path.
                        // use this command to check:
                        // netstat -ntp|grep -E "CLOSE_WAIT|FIN_WAIT"|sort
                        // The DST server should answer for this problem, becasue it ignores the FIN
                        // Dont worry, after the FIN_WAIT_2 timeout, the CLOSE_WAIT connection will close.
                        match dial_timed_tunnel(&addr.to_string(), ipv6_first).await {
                            Ok(target_stream) => {
                                log_tunnel_path("tunnel", &access_label, client_socket_addr, target_stream.peer_addr());
                                let access_tag = access_label.to_string();
                                let dst_stream =
                                    CounterIO::new(target_stream, proxy_traffic, LabelImpl::new(access_label));
                                if let Err(e) = tunnel(TokioIo::new(src_upgraded), dst_stream).await {
                                    warn!("[tunnel io error] [{}]: [{}] {} ", access_tag, e.kind(), e);
                                };
                            }
                            Err(e) => {
                                warn!("[tunnel establish error] [{}]: [{}] {} ", access_label, e.kind(), e)
                            }
                        }
                    }
                    Err(e) => warn!("upgrade error: {e}"),
                }
            });
            let mut response = Response::new(empty_body());
            // 针对connect请求增加随机padding，防止每次建连时tcp数据长度特征过于敏感。
            append_random_padding_headers(response.headers_mut());
            Ok(response)
        } else {
            warn!("CONNECT host is not socket addr: {:?}", req.uri());
            let mut resp = Response::new(full_body("CONNECT must be to a socket address"));
            *resp.status_mut() = http::StatusCode::BAD_REQUEST;

            Ok(resp)
        }
    }
}

fn mod_http1_proxy_req(req: &mut Request<Incoming>) -> io::Result<()> {
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
    origin_form(req.uri_mut())?;
    Ok(())
}
