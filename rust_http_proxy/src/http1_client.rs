//! HTTP Client

use std::{
    collections::VecDeque,
    error::Error,
    fmt::Debug,
    io::{self, ErrorKind},
    sync::Arc,
    time::{Duration, Instant},
};

use http::{header, HeaderMap, HeaderValue, Version};
use hyper::{
    body::{self, Body},
    client::conn::http1,
    http::uri::Scheme,
    Request, Response,
};
use hyper_util::rt::TokioIo;
use io_x::{CounterIO, TimeoutIO};
use log::{debug, error, info, trace, warn};
use lru_time_cache::LruCache;
use prom_label::LabelImpl;
use tokio::{net::TcpStream, sync::Mutex};

use crate::proxy::AccessLabel;

const CONNECTION_EXPIRE_DURATION: Duration = Duration::from_secs(if !cfg!(debug_assertions) { 30 } else { 10 });

/// HTTPClient, supporting HTTP/1.1 and H2, HTTPS.
pub struct HttpClient<B> {
    #[allow(clippy::type_complexity)]
    cache_conn: Arc<Mutex<LruCache<AccessLabel, VecDeque<(HttpConnection<B>, Instant)>>>>,
}

impl<B> HttpClient<B>
where
    B: Body + Send + Unpin + Debug + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn ::std::error::Error + Send + Sync>>,
{
    /// Create a new HttpClient
    pub fn new() -> HttpClient<B> {
        HttpClient {
            cache_conn: Arc::new(Mutex::new(LruCache::with_expiry_duration(CONNECTION_EXPIRE_DURATION))),
        }
    }

    /// Make HTTP requests
    #[inline]
    pub async fn send_request(
        &self, req: Request<B>, access_label: &AccessLabel,
        stream_map_func: impl FnOnce(TcpStream, AccessLabel) -> CounterIO<TcpStream, LabelImpl<AccessLabel>>,
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
        let scheme = match req.uri().scheme() {
            Some(s) => s,
            None => &Scheme::HTTP,
        };

        let c = match HttpConnection::connect(scheme, access_label, stream_map_func).await {
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
                if now - inst >= CONNECTION_EXPIRE_DURATION {
                    debug!("HTTP connection for host: {} expired", access_label,);
                    continue;
                }
                if c.is_closed() {
                    // true at once after connection.await return
                    debug!("HTTP connection for host: {} is closed", access_label,);
                    continue;
                }
                return Some(c);
            }
        } else {
            debug!("HTTP client for host: {} not found in cache", access_label);
        }
        None
    }

    async fn send_request_conn(
        &self, access_label: &AccessLabel, mut c: HttpConnection<B>, req: Request<B>,
    ) -> hyper::Result<Response<body::Incoming>> {
        trace!("HTTP making request to host: {}, request: {:?}", access_label, req);
        let response = c.send_request(req).await?;
        trace!("HTTP received response from host: {}, response: {:?}", access_label, response);

        // Check keep-alive
        if check_keep_alive(response.version(), response.headers(), false) {
            trace!("HTTP connection keep-alive for host: {}, response: {:?}", access_label, response);
            self.cache_conn
                .lock()
                .await
                .entry(access_label.clone())
                .or_insert_with(VecDeque::new)
                .push_back((c, Instant::now()));
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
enum HttpConnection<B> {
    Http1(http1::SendRequest<B>),
}

impl<B> HttpConnection<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn ::std::error::Error + Send + Sync>>,
{
    async fn connect(
        scheme: &Scheme, access_label: &AccessLabel,
        stream_map_func: impl FnOnce(TcpStream, AccessLabel) -> CounterIO<TcpStream, LabelImpl<AccessLabel>>,
    ) -> io::Result<HttpConnection<B>> {
        if *scheme != Scheme::HTTP && *scheme != Scheme::HTTPS {
            return Err(io::Error::new(ErrorKind::InvalidInput, "invalid scheme"));
        }

        let stream = TcpStream::connect(&access_label.target).await?;
        let stream: CounterIO<TcpStream, LabelImpl<AccessLabel>> = stream_map_func(stream, access_label.clone());

        HttpConnection::connect_http_http1(scheme, access_label, stream).await
    }

    async fn connect_http_http1(
        scheme: &Scheme, access_label: &AccessLabel, stream: CounterIO<TcpStream, LabelImpl<AccessLabel>>,
    ) -> io::Result<HttpConnection<B>> {
        trace!("HTTP making new HTTP/1.1 connection to host: {}, scheme: {}", access_label, scheme);
        let stream = TimeoutIO::new(stream, CONNECTION_EXPIRE_DURATION);

        // HTTP/1.x
        let (send_request, connection) = match http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(Box::pin(TokioIo::new(stream)))
            .await
        {
            Ok(s) => s,
            Err(err) => return Err(io::Error::new(ErrorKind::Other, err)),
        };

        let access_label = access_label.clone();
        tokio::spawn(async move {
            if let Err(err) = connection.await {
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
}

fn handle_http1_connection_error(err: hyper::Error, access_label: AccessLabel) {
    if let Some(source) = err.source() {
        if let Some(io_err) = source.downcast_ref::<io::Error>() {
            if io_err.kind() == ErrorKind::TimedOut {
                // 由于超时导致的连接关闭（TimeoutIO）
                info!("[legacy proxy connection io closed]: [{}] {} to {}", io_err.kind(), io_err, access_label);
            } else {
                warn!("[legacy proxy io error]: [{}] {} to {}", io_err.kind(), io_err, access_label);
            }
        } else {
            warn!("[legacy proxy io error]: [{}] to {}", source, access_label);
        }
    } else {
        warn!("[legacy proxy io error] [{}] to {}", err, access_label);
    }
}
