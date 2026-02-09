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

use http::{HeaderMap, HeaderValue, Version, header};
use hyper::{
    Request, Response,
    body::{self, Body},
    client::conn::http1::{self},
};
use hyper_util::rt::TokioIo;
use io_x::{CounterIO, TimeoutIO};
use log::{debug, error, info, trace, warn};
use lru_time_cache::LruCache;
use prom_label::LabelImpl;
use tokio::sync::Mutex;
use tokio_rustls::rustls::pki_types;

use crate::proxy::{AccessLabel, EitherTlsStream, build_tls_connector};

pub const CONN_EXPIRE_TIMEOUT: Duration = Duration::from_secs(60);
/// 清理任务的执行间隔
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

pub struct ForwardProxyClient<B> {
    cache_conn: Arc<Mutex<LruCache<AccessLabel, VecDeque<(HttpConnection<B>, Instant)>>>>,
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
        stream_map_func: impl FnOnce(EitherTlsStream, AccessLabel) -> CounterIO<EitherTlsStream, LabelImpl<AccessLabel>>,
    ) -> Result<Response<body::Incoming>, std::io::Error> {
        // 1. Check if there is an available client
        if let Some(c) = self.get_cached_connection(access_label).await {
            debug!("HTTP client for host: {} taken from cache", &access_label);
            match self.send_request_conn(access_label, c, req).await {
                Ok(o) => return Ok(o),
                Err(err) => return Err(io::Error::new(io::ErrorKind::InvalidData, err)),
            }
        }

        // 2. If no. Make a new connection
        let c = match HttpConnection::connect(access_label, ipv6_first, stream_map_func).await {
            Ok(c) => c,
            Err(err) => {
                error!("failed to connect to host: {}, error: {}", &access_label.target, err);
                return Err(io::Error::new(io::ErrorKind::InvalidData, err));
            }
        };

        self.send_request_conn(access_label, c, req)
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
        let response = c.send_request(req).await?;
        trace!("HTTP received response from host: {access_label}, response: {response:?}");

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
}

impl<B> HttpConnection<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn ::std::error::Error + Send + Sync>>,
{
    pub(crate) async fn connect(
        access_label: &AccessLabel, ipv6_first: Option<bool>,
        stream_map_func: impl FnOnce(EitherTlsStream, AccessLabel) -> CounterIO<EitherTlsStream, LabelImpl<AccessLabel>>,
    ) -> io::Result<HttpConnection<B>> {
        let stream = crate::proxy::connect_with_preference(&access_label.target, ipv6_first).await?;
        let stream = if let Some(true) = access_label.relay_over_tls {
            // 建立 TLS 连接
            let connector = build_tls_connector();

            let host = &access_label
                .target
                .split(':')
                .next()
                .ok_or(io::Error::other("invalid host"))?;
            let server_name = pki_types::ServerName::try_from(*host)
                .map_err(|e| io::Error::new(ErrorKind::InvalidInput, format!("Invalid DNS name: {}", e)))?
                .to_owned();

            match connector.connect(server_name, stream).await {
                Ok(tls_stream) => EitherTlsStream::Tls { stream: tls_stream },
                Err(e) => {
                    warn!("[forward_bypass TLS handshake error] [{}]: {}", access_label, e);
                    return Err(e);
                }
            }
        } else {
            // 使用普通 TCP 连接
            EitherTlsStream::Tcp { stream }
        };

        let stream: CounterIO<EitherTlsStream, LabelImpl<AccessLabel>> = stream_map_func(stream, access_label.clone());

        HttpConnection::connect_http_http1(access_label, stream).await
    }

    async fn connect_http_http1(
        access_label: &AccessLabel, stream: CounterIO<EitherTlsStream, LabelImpl<AccessLabel>>,
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
                handle_http1_connection_error(err, access_label);
            }
        });
        Ok(HttpConnection::Http1(send_request))
    }

    #[inline]
    pub async fn send_request(&mut self, req: Request<B>) -> hyper::Result<Response<body::Incoming>> {
        match self {
            HttpConnection::Http1(r) => r.send_request(req).await,
        }
    }

    pub fn is_closed(&self) -> bool {
        match self {
            HttpConnection::Http1(r) => r.is_closed(),
        }
    }

    pub fn is_ready(&self) -> bool {
        match self {
            HttpConnection::Http1(r) => r.is_ready(),
        }
    }

    pub async fn ready(&mut self) -> Result<(), hyper::Error> {
        match self {
            HttpConnection::Http1(r) => r.ready().await,
        }
    }
}

fn handle_http1_connection_error(err: hyper::Error, access_label: AccessLabel) {
    if let Some(io_err) = err.source().and_then(|s| s.downcast_ref::<io::Error>()) {
        if io_err.kind() == ErrorKind::TimedOut {
            // 由于超时导致的连接关闭（TimeoutIO）
            info!("[legacy proxy connection io closed]: [{}] {} to {}", io_err.kind(), io_err, access_label);
        } else {
            warn!("[legacy proxy io error]: [{}] {} to {}", io_err.kind(), io_err, access_label);
        }
    } else if let Some(source) = err.source() {
        warn!("[legacy proxy io error]: [{source}] to {access_label}");
    } else {
        warn!("[legacy proxy io error] [{err}] to {access_label}");
    }
}
