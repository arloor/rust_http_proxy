//! HTTP Client
#![allow(clippy::type_complexity)]
use std::{
    collections::VecDeque,
    error::Error,
    fmt::Debug,
    io::{self, ErrorKind},
    sync::Arc,
    time::{Duration, Instant},
};

use base64::Engine as _;
use http::{
    HeaderMap, HeaderValue, Uri, Version, header,
    header::{CONNECTION, HOST, TE, TRANSFER_ENCODING, UPGRADE},
};
use hyper::{
    Request, Response,
    body::{self, Body},
    client::conn::{http1, http2},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use io_x::{CounterIO, TimeoutIO};
use log::{debug, error, info, trace, warn};
use lru_time_cache::LruCache;
use prom_label::LabelImpl;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
use tokio::sync::Mutex;
use tokio_rustls::rustls::pki_types;

use crate::{
    config::ForwardBypassConfig,
    proxy::{
        AccessLabel, EitherTlsStream, HttpClientStream, build_tls_connector, build_tls_connector_with_http_alpn,
        build_tls_connector_with_http1_alpn,
    },
};

pub const CONN_EXPIRE_TIMEOUT: Duration = Duration::from_secs(60);
/// 清理任务的执行间隔
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

pub struct ForwardProxyClient<B> {
    cache_conn: Arc<Mutex<LruCache<AccessLabel, VecDeque<(HttpConnection<B>, Instant)>>>>,
}

impl<B> Clone for ForwardProxyClient<B> {
    fn clone(&self) -> Self {
        Self {
            cache_conn: self.cache_conn.clone(),
        }
    }
}

impl<B> ForwardProxyClient<B>
where
    B: Body + Send + Unpin + Debug + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn ::std::error::Error + Send + Sync>>,
{
    /// Create a new HttpClient
    pub fn new() -> ForwardProxyClient<B> {
        let cache_conn = Arc::new(Mutex::new(LruCache::with_expiry_duration(CONN_EXPIRE_TIMEOUT)));

        // 启动后台清理任务
        Self::spawn_cleanup_task(cache_conn.clone());

        ForwardProxyClient { cache_conn }
    }

    /// 启动定时清理过期连接的后台任务
    fn spawn_cleanup_task(cache_conn: Arc<Mutex<LruCache<AccessLabel, VecDeque<(HttpConnection<B>, Instant)>>>>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            loop {
                interval.tick().await;
                Self::cleanup_expired_connections(&cache_conn).await;
            }
        });
    }

    /// 清理过期和已关闭的连接
    async fn cleanup_expired_connections(
        cache_conn: &Mutex<LruCache<AccessLabel, VecDeque<(HttpConnection<B>, Instant)>>>,
    ) {
        let mut cache = cache_conn.lock().await;
        let now = Instant::now();
        let mut total_removed = 0usize;
        let mut empty_keys = Vec::new();

        // 收集所有的 key
        let keys: Vec<AccessLabel> = cache.iter().map(|(k, _)| k.clone()).collect();

        for key in keys {
            if let Some(queue) = cache.get_mut(&key) {
                let before_len = queue.len();
                // 保留未过期且未关闭的连接
                queue.retain(|(conn, inst)| {
                    let expired = now.duration_since(*inst) >= CONN_EXPIRE_TIMEOUT;
                    let closed = conn.is_closed();
                    !expired && !closed
                });
                let removed = before_len - queue.len();
                total_removed += removed;

                if queue.is_empty() {
                    empty_keys.push(key);
                }
            }
        }

        // 移除空的条目
        for key in empty_keys {
            cache.remove(&key);
        }

        let elapsed = now.elapsed();
        debug!("Connection cleanup completed: removed {} connections in {:?}", total_removed, elapsed);
    }

    /// Make HTTP requests
    #[inline]
    pub async fn send_request(
        &self, req: Request<B>, access_label: &AccessLabel, ipv6_first: Option<bool>,
        stream_map_func: impl FnOnce(HttpClientStream, AccessLabel) -> CounterIO<HttpClientStream, LabelImpl<AccessLabel>>,
    ) -> Result<Response<body::Incoming>, std::io::Error> {
        // 1. Check if there is an available client
        if let Some(c) = self.get_cached_connection(access_label).await {
            debug!("HTTP client for host: {} taken from cache", access_label);
            match self.send_request_conn(access_label, c, req).await {
                Ok(o) => return Ok(o),
                Err(err) => return Err(io::Error::new(io::ErrorKind::InvalidData, err)),
            }
        }

        // 2. If no. Make a new connection
        let c = match HttpConnection::connect(access_label, ipv6_first, stream_map_func).await {
            Ok(c) => c,
            Err(err) => {
                error!("failed to connect to host: {}, error: {}", access_label.target, err);
                return Err(io::Error::new(io::ErrorKind::InvalidData, err));
            }
        };

        self.send_request_conn(access_label, c, req)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    pub async fn send_request_http1_only(
        &self, req: Request<B>, access_label: &AccessLabel, ipv6_first: Option<bool>,
        stream_map_func: impl FnOnce(HttpClientStream, AccessLabel) -> CounterIO<HttpClientStream, LabelImpl<AccessLabel>>,
    ) -> Result<Response<body::Incoming>, std::io::Error> {
        let mut c = match HttpConnection::connect_http1_only(access_label, ipv6_first, stream_map_func).await {
            Ok(c) => c,
            Err(err) => {
                error!("failed to connect to host with HTTP/1.1 only: {}, error: {}", access_label.target, err);
                return Err(io::Error::new(io::ErrorKind::InvalidData, err));
            }
        };

        trace!("HTTP/1.1-only making request to host: {access_label}, request: {req:?}");
        c.send_request(req, access_label)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    pub async fn send_request_via_forward_bypass(
        &self, req: Request<B>, access_label: &AccessLabel, forward_bypass_config: &ForwardBypassConfig,
        client_ip: &str,
        stream_map_func: impl FnOnce(HttpClientStream, AccessLabel) -> CounterIO<HttpClientStream, LabelImpl<AccessLabel>>,
    ) -> Result<Response<body::Incoming>, std::io::Error> {
        if let Some(c) = self.get_cached_connection(access_label).await {
            debug!("HTTP client via forward bypass for host: {} taken from cache", access_label);
            match self.send_request_conn(access_label, c, req).await {
                Ok(o) => return Ok(o),
                Err(err) => return Err(io::Error::new(io::ErrorKind::InvalidData, err)),
            }
        }

        let c = match HttpConnection::connect_via_forward_bypass(
            access_label,
            forward_bypass_config,
            client_ip,
            stream_map_func,
        )
        .await
        {
            Ok(c) => c,
            Err(err) => {
                error!(
                    "failed to connect to host: {} via forward bypass {}, error: {}",
                    access_label.target, forward_bypass_config, err
                );
                return Err(io::Error::new(io::ErrorKind::InvalidData, err));
            }
        };

        self.send_request_conn(access_label, c, req)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    pub async fn send_request_via_forward_bypass_http1_only(
        &self, req: Request<B>, access_label: &AccessLabel, forward_bypass_config: &ForwardBypassConfig,
        client_ip: &str,
        stream_map_func: impl FnOnce(HttpClientStream, AccessLabel) -> CounterIO<HttpClientStream, LabelImpl<AccessLabel>>,
    ) -> Result<Response<body::Incoming>, std::io::Error> {
        let mut c = match HttpConnection::connect_via_forward_bypass_http1_only(
            access_label,
            forward_bypass_config,
            client_ip,
            stream_map_func,
        )
        .await
        {
            Ok(c) => c,
            Err(err) => {
                error!(
                    "failed to connect to host with HTTP/1.1 only: {} via forward bypass {}, error: {}",
                    access_label.target, forward_bypass_config, err
                );
                return Err(io::Error::new(io::ErrorKind::InvalidData, err));
            }
        };

        trace!("HTTP/1.1-only making request via forward bypass to host: {access_label}, request: {req:?}");
        c.send_request(req, access_label)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    async fn get_cached_connection(&self, access_label: &AccessLabel) -> Option<HttpConnection<B>> {
        if let Some(q) = self.cache_conn.lock().await.get_mut(access_label) {
            debug!("HTTP client for host: {} found in cache, len: {}", access_label, q.len());
            while let Some((c, inst)) = q.pop_front() {
                let now = Instant::now();
                if now - inst >= CONN_EXPIRE_TIMEOUT {
                    debug!("HTTP connection for host: {access_label} expired",);
                    continue;
                }
                if c.is_closed() {
                    // true at once after connection.await return
                    debug!("HTTP connection for host: {access_label} is closed",);
                    continue;
                }
                if !c.is_ready() {
                    debug!("HTTP connection for host: {access_label} is not ready",);
                    continue;
                }
                return Some(c);
            }
        } else {
            debug!("HTTP client for host: {access_label} not found in cache");
        }
        None
    }

    pub(crate) async fn send_request_conn(
        &self, access_label: &AccessLabel, mut c: HttpConnection<B>, req: Request<B>,
    ) -> hyper::Result<Response<body::Incoming>> {
        trace!("HTTP making request to host: {access_label}, request: {req:?}");
        let url = req.uri().clone();

        if let Some(cacheable_conn) = c.clone_for_multiplexed_cache() {
            debug!("HTTP/2 connection for host: {access_label} {url} remains cached for multiplexing");
            self.cache_conn
                .lock()
                .await
                .entry(access_label.clone())
                .or_insert_with(VecDeque::new)
                .push_back((cacheable_conn, Instant::now()));
        }

        let response = c.send_request(req, access_label).await?;
        trace!("HTTP received response from host: {access_label}, response: {response:?}");

        if c.is_multiplexed() {
            return Ok(response);
        }

        // Check keep-alive
        if check_keep_alive(response.version(), response.headers(), false) {
            trace!("HTTP connection keep-alive for host: {access_label}, response: {response:?}");
            let cache_conn = self.cache_conn.clone();
            let access_label = access_label.clone();
            tokio::spawn(async move {
                match c.ready().await {
                    Ok(_) => {
                        debug!("HTTP connection for host: {access_label} {url} is ready and will be cached");
                        cache_conn
                            .lock()
                            .await
                            .entry(access_label)
                            .or_insert_with(VecDeque::new)
                            .push_back((c, Instant::now()));
                    }
                    Err(e) => {
                        debug!("HTTP connection for host: {access_label} {url} failed to become ready: {}", e);
                    }
                };
            });
        }

        Ok(response)
    }
}

pub fn check_keep_alive(version: Version, headers: &HeaderMap<HeaderValue>, check_proxy: bool) -> bool {
    // HTTP/1.1, HTTP/2, HTTP/3 keeps alive by default
    let mut conn_keep_alive = !matches!(version, Version::HTTP_09 | Version::HTTP_10);

    if check_proxy {
        // Modern browsers will send Proxy-Connection instead of Connection
        // for HTTP/1.0 proxies which blindly forward Connection to remote
        //
        // https://tools.ietf.org/html/rfc7230#appendix-A.1.2
        if let Some(b) = get_keep_alive_val(headers.get_all("Proxy-Connection")) {
            conn_keep_alive = b
        }
    }

    // Connection will replace Proxy-Connection
    //
    // But why client sent both Connection and Proxy-Connection? That's not standard!
    if let Some(b) = get_keep_alive_val(headers.get_all("Connection")) {
        conn_keep_alive = b
    }

    conn_keep_alive
}

fn get_keep_alive_val(values: header::GetAll<HeaderValue>) -> Option<bool> {
    let mut conn_keep_alive = None;
    for value in values {
        if let Ok(value) = value.to_str() {
            if value.eq_ignore_ascii_case("close") {
                conn_keep_alive = Some(false);
            } else {
                for part in value.split(',') {
                    let part = part.trim();
                    if part.eq_ignore_ascii_case("keep-alive") {
                        conn_keep_alive = Some(true);
                        break;
                    }
                }
            }
        }
    }
    conn_keep_alive
}

#[allow(dead_code)]
pub(crate) enum HttpConnection<B> {
    Http1(http1::SendRequest<B>),
    Http2(http2::SendRequest<B>),
}

impl<B> HttpConnection<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn ::std::error::Error + Send + Sync>>,
{
    pub(crate) async fn connect(
        access_label: &AccessLabel, ipv6_first: Option<bool>,
        stream_map_func: impl FnOnce(HttpClientStream, AccessLabel) -> CounterIO<HttpClientStream, LabelImpl<AccessLabel>>,
    ) -> io::Result<HttpConnection<B>> {
        Self::connect_with_http2_preference(access_label, ipv6_first, true, stream_map_func).await
    }

    pub(crate) async fn connect_http1_only(
        access_label: &AccessLabel, ipv6_first: Option<bool>,
        stream_map_func: impl FnOnce(HttpClientStream, AccessLabel) -> CounterIO<HttpClientStream, LabelImpl<AccessLabel>>,
    ) -> io::Result<HttpConnection<B>> {
        Self::connect_with_http2_preference(access_label, ipv6_first, false, stream_map_func).await
    }

    async fn connect_with_http2_preference(
        access_label: &AccessLabel, ipv6_first: Option<bool>, allow_http2: bool,
        stream_map_func: impl FnOnce(HttpClientStream, AccessLabel) -> CounterIO<HttpClientStream, LabelImpl<AccessLabel>>,
    ) -> io::Result<HttpConnection<B>> {
        let stream = crate::proxy::connect_with_preference(&access_label.target, ipv6_first).await?;
        let (stream, use_http2) = if let Some(true) = access_label.relay_over_tls {
            // 建立 TLS 连接
            let connector = if allow_http2 {
                build_tls_connector_with_http_alpn()
            } else {
                build_tls_connector_with_http1_alpn()
            };

            let host = &access_label
                .target
                .split(':')
                .next()
                .ok_or(io::Error::other("invalid host"))?;
            let server_name = pki_types::ServerName::try_from(*host)
                .map_err(|e| io::Error::new(ErrorKind::InvalidInput, format!("Invalid DNS name: {}", e)))?
                .to_owned();

            match connector.connect(server_name, stream).await {
                Ok(tls_stream) => {
                    let use_http2 = allow_http2 && tls_stream.get_ref().1.alpn_protocol() == Some(b"h2");
                    (EitherTlsStream::Tls { stream: tls_stream }, use_http2)
                }
                Err(e) => {
                    warn!("[forward_bypass TLS handshake error] [{}]: {}", access_label, e);
                    return Err(e);
                }
            }
        } else {
            // 使用普通 TCP 连接
            (EitherTlsStream::Tcp { stream }, false)
        };

        let stream = stream_map_func(HttpClientStream::Direct { stream }, access_label.clone());

        HttpConnection::connect_http(access_label, stream, use_http2).await
    }

    pub(crate) async fn connect_via_forward_bypass(
        access_label: &AccessLabel, forward_bypass_config: &ForwardBypassConfig, client_ip: &str,
        stream_map_func: impl FnOnce(HttpClientStream, AccessLabel) -> CounterIO<HttpClientStream, LabelImpl<AccessLabel>>,
    ) -> io::Result<HttpConnection<B>> {
        Self::connect_via_forward_bypass_with_http2_preference(
            access_label,
            forward_bypass_config,
            client_ip,
            true,
            stream_map_func,
        )
        .await
    }

    pub(crate) async fn connect_via_forward_bypass_http1_only(
        access_label: &AccessLabel, forward_bypass_config: &ForwardBypassConfig, client_ip: &str,
        stream_map_func: impl FnOnce(HttpClientStream, AccessLabel) -> CounterIO<HttpClientStream, LabelImpl<AccessLabel>>,
    ) -> io::Result<HttpConnection<B>> {
        Self::connect_via_forward_bypass_with_http2_preference(
            access_label,
            forward_bypass_config,
            client_ip,
            false,
            stream_map_func,
        )
        .await
    }

    async fn connect_via_forward_bypass_with_http2_preference(
        access_label: &AccessLabel, forward_bypass_config: &ForwardBypassConfig, client_ip: &str, allow_http2: bool,
        stream_map_func: impl FnOnce(HttpClientStream, AccessLabel) -> CounterIO<HttpClientStream, LabelImpl<AccessLabel>>,
    ) -> io::Result<HttpConnection<B>> {
        let bypass_host = format!("{}:{}", forward_bypass_config.host, forward_bypass_config.port);
        let tcp_stream = crate::proxy::connect_with_preference(&bypass_host, forward_bypass_config.ipv6_first).await?;
        let mut parent_stream = if forward_bypass_config.is_https {
            let connector = build_tls_connector();
            let server_name = pki_types::ServerName::try_from(forward_bypass_config.host.as_str())
                .map_err(|e| io::Error::new(ErrorKind::InvalidInput, format!("Invalid DNS name: {}", e)))?
                .to_owned();
            match connector.connect(server_name, tcp_stream).await {
                Ok(tls_stream) => EitherTlsStream::Tls { stream: tls_stream },
                Err(e) => {
                    warn!("[forward_bypass TLS handshake error] [{}]: {}", bypass_host, e);
                    return Err(e);
                }
            }
        } else {
            EitherTlsStream::Tcp { stream: tcp_stream }
        };

        let mut connect_request = format!(
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\nX-Forwarded-For: {}\r\n",
            access_label.target, access_label.target, client_ip
        );
        if let (Some(username), Some(password)) = (&forward_bypass_config.username, &forward_bypass_config.password) {
            let credentials = format!("{username}:{password}");
            let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
            connect_request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
        }
        connect_request.push_str("\r\n");

        parent_stream.write_all(connect_request.as_bytes()).await?;
        let mut reader = tokio::io::BufReader::new(parent_stream);
        let mut response_line = String::new();
        reader.read_line(&mut response_line).await?;
        let status_code = response_line.split_whitespace().nth(1).unwrap_or("");
        if status_code != "200" {
            return Err(io::Error::other(format!(
                "unexpected response from forward bypass: {}",
                response_line.trim_end()
            )));
        }
        loop {
            let mut header_line = String::new();
            reader.read_line(&mut header_line).await?;
            if header_line == "\r\n" || header_line == "\n" {
                break;
            }
        }
        let parent_stream = reader.into_inner();

        let (stream, use_http2) = if let Some(true) = access_label.relay_over_tls {
            let connector = if allow_http2 {
                build_tls_connector_with_http_alpn()
            } else {
                build_tls_connector_with_http1_alpn()
            };
            let host = access_label
                .target
                .split(':')
                .next()
                .ok_or(io::Error::other("invalid host"))?;
            let server_name = pki_types::ServerName::try_from(host)
                .map_err(|e| io::Error::new(ErrorKind::InvalidInput, format!("Invalid DNS name: {}", e)))?
                .to_owned();
            let stream = connector.connect(server_name, parent_stream).await?;
            let use_http2 = allow_http2 && stream.get_ref().1.alpn_protocol() == Some(b"h2");
            (HttpClientStream::TlsOverProxy { stream }, use_http2)
        } else {
            (HttpClientStream::Direct { stream: parent_stream }, false)
        };

        let stream = stream_map_func(stream, access_label.clone());
        HttpConnection::connect_http(access_label, stream, use_http2).await
    }

    async fn connect_http(
        access_label: &AccessLabel, stream: CounterIO<HttpClientStream, LabelImpl<AccessLabel>>, use_http2: bool,
    ) -> io::Result<HttpConnection<B>> {
        if use_http2 {
            debug!("HTTP/2 selected by ALPN for host: {access_label}");
            Self::connect_http2(access_label, stream).await
        } else {
            Self::connect_http_http1(access_label, stream).await
        }
    }

    async fn connect_http_http1(
        access_label: &AccessLabel, stream: CounterIO<HttpClientStream, LabelImpl<AccessLabel>>,
    ) -> io::Result<HttpConnection<B>> {
        let stream = TimeoutIO::new(stream, crate::IDLE_TIMEOUT);

        // HTTP/1.x
        let (send_request, connection) = match http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(Box::pin(TokioIo::new(stream)))
            .await
        {
            Ok(s) => s,
            Err(err) => return Err(io::Error::other(err)),
        };

        let access_label = access_label.clone();
        tokio::spawn(async move {
            if let Err(err) = connection.with_upgrades().await {
                handle_http_connection_error("HTTP/1.1", err, access_label);
            }
        });
        Ok(HttpConnection::Http1(send_request))
    }

    async fn connect_http2(
        access_label: &AccessLabel, stream: CounterIO<HttpClientStream, LabelImpl<AccessLabel>>,
    ) -> io::Result<HttpConnection<B>> {
        let stream = TimeoutIO::new(stream, crate::IDLE_TIMEOUT);

        let (send_request, connection) = match http2::Builder::new(TokioExecutor::new())
            .handshake(Box::pin(TokioIo::new(stream)))
            .await
        {
            Ok(s) => s,
            Err(err) => return Err(io::Error::other(err)),
        };

        let access_label = access_label.clone();
        tokio::spawn(async move {
            if let Err(err) = connection.await {
                handle_http_connection_error("HTTP/2", err, access_label);
            }
        });
        Ok(HttpConnection::Http2(send_request))
    }

    #[inline]
    pub async fn send_request(
        &mut self, mut req: Request<B>, access_label: &AccessLabel,
    ) -> hyper::Result<Response<body::Incoming>> {
        match self {
            HttpConnection::Http1(r) => {
                *req.version_mut() = Version::HTTP_11;
                prepare_http1_request_for_connection_target(&mut req, access_label);
                sanitize_http1_request_headers(req.headers_mut());
                r.send_request(req).await
            }
            HttpConnection::Http2(r) => {
                *req.version_mut() = Version::HTTP_2;
                ensure_http2_uri(&mut req, access_label);
                sanitize_http2_request_headers(req.headers_mut());
                r.send_request(req).await
            }
        }
    }

    pub fn is_closed(&self) -> bool {
        match self {
            HttpConnection::Http1(r) => r.is_closed(),
            HttpConnection::Http2(r) => r.is_closed(),
        }
    }

    pub fn is_ready(&self) -> bool {
        match self {
            HttpConnection::Http1(r) => r.is_ready(),
            HttpConnection::Http2(r) => r.is_ready(),
        }
    }

    pub async fn ready(&mut self) -> Result<(), hyper::Error> {
        match self {
            HttpConnection::Http1(r) => r.ready().await,
            HttpConnection::Http2(r) => r.ready().await,
        }
    }

    fn is_multiplexed(&self) -> bool {
        matches!(self, HttpConnection::Http2(_))
    }

    fn clone_for_multiplexed_cache(&self) -> Option<Self> {
        match self {
            HttpConnection::Http1(_) => None,
            HttpConnection::Http2(r) => Some(HttpConnection::Http2(r.clone())),
        }
    }
}

fn ensure_http2_uri<B>(req: &mut Request<B>, access_label: &AccessLabel) {
    if req.uri().scheme().is_some() && req.uri().authority().is_some() {
        return;
    }

    let path = req.uri().path_and_query().map(|path| path.as_str()).unwrap_or("/");
    if let Ok(uri) = format!("https://{}{path}", access_label.target).parse() {
        *req.uri_mut() = uri;
    }
}

fn prepare_http1_request_for_connection_target<B>(req: &mut Request<B>, access_label: &AccessLabel) {
    if !req.headers().contains_key(HOST) {
        let host = req
            .uri()
            .authority()
            .map(|authority| authority.as_str())
            .unwrap_or(&access_label.target);
        if let Ok(host) = HeaderValue::from_str(host) {
            req.headers_mut().insert(HOST, host);
        }
    }

    // Direct origin connections must use origin-form ("/path?query"), while
    // parent forward proxies must receive absolute-form ("http://host/path").
    if uri_targets_current_connection(req.uri(), access_label) {
        let path = req.uri().path_and_query().cloned();
        *req.uri_mut() = path
            .and_then(|path| {
                let mut parts = http::uri::Parts::default();
                parts.path_and_query = Some(path);
                Uri::from_parts(parts).ok()
            })
            .unwrap_or_else(|| Uri::from_static("/"));
    }
}

fn uri_targets_current_connection(uri: &Uri, access_label: &AccessLabel) -> bool {
    uri.authority()
        .map(|authority| authority.as_str().eq_ignore_ascii_case(&access_label.target))
        .unwrap_or_default()
}

fn sanitize_http2_request_headers(headers: &mut HeaderMap) {
    let connection_header_values = headers
        .get_all(CONNECTION)
        .iter()
        .flat_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();

    headers.remove(CONNECTION);
    for header_name in connection_header_values {
        headers.remove(header_name);
    }

    headers.remove("keep-alive");
    headers.remove("proxy-connection");
    headers.remove(TRANSFER_ENCODING);
    headers.remove(UPGRADE);

    let keep_te = headers
        .get(TE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("trailers"));
    if !keep_te {
        headers.remove(TE);
    }
}

fn sanitize_http1_request_headers(headers: &mut HeaderMap) {
    let remove_te = headers
        .get(TE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("trailers"));
    if remove_te {
        headers.remove(TE);
    }

    headers.remove("http2-settings");
}

fn handle_http_connection_error(protocol: &str, err: hyper::Error, access_label: AccessLabel) {
    if let Some(io_err) = err.source().and_then(|s| s.downcast_ref::<io::Error>()) {
        if io_err.kind() == ErrorKind::TimedOut {
            // 由于超时导致的连接关闭（TimeoutIO）
            info!("[legacy proxy {protocol} connection io closed]: [{}] {} to {}", io_err.kind(), io_err, access_label);
        } else {
            warn!("[legacy proxy {protocol} io error]: [{}] {} to {}", io_err.kind(), io_err, access_label);
        }
    } else if let Some(source) = err.source() {
        warn!("[legacy proxy {protocol} io error]: [{source}] to {access_label}");
    } else {
        warn!("[legacy proxy {protocol} io error] [{err}] to {access_label}");
    }
}
