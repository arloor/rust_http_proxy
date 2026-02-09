//! HTTP Client
#![allow(clippy::type_complexity)]
use std::{
    collections::{HashMap, HashSet, VecDeque},
    error::Error,
    fmt::{Debug, Display, Formatter},
    io::{self, ErrorKind},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use futures_util::{
    FutureExt,
    future::{self, Either},
};
use http::{HeaderMap, HeaderValue, Uri, Version, header};
use hyper::{
    Request, Response,
    body::{self, Body},
    client::conn::{
        TrySendError as ConnTrySendError,
        http1::{self},
        http2,
    },
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use io_x::{CounterIO, TimeoutIO};
use log::{debug, error, info, trace, warn};
use prom_label::LabelImpl;
use tokio::sync::{Mutex, oneshot};
use tokio_rustls::rustls::pki_types;

use crate::proxy::{AccessLabel, EitherTlsStream, build_tls_connector};

pub const CONN_EXPIRE_TIMEOUT: Duration = Duration::from_secs(60);
/// Cleanup task interval.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_MAX_IDLE_PER_HOST: usize = usize::MAX;

enum Reservation<T> {
    Shared(T, T),
    Unique(T),
}

struct IdleEntry<B> {
    conn: HttpConnection<B>,
    idle_at: Instant,
}

struct PoolInner<B> {
    idle: HashMap<AccessLabel, Vec<IdleEntry<B>>>,
    waiters: HashMap<AccessLabel, VecDeque<oneshot::Sender<HttpConnection<B>>>>,
    connecting_h2: HashSet<AccessLabel>,
    max_idle_per_host: usize,
}

impl<B> PoolInner<B> {
    fn new(max_idle_per_host: usize) -> Self {
        Self {
            idle: HashMap::new(),
            waiters: HashMap::new(),
            connecting_h2: HashSet::new(),
            max_idle_per_host,
        }
    }
}

impl<B> PoolInner<B>
where
    B: Body + Send + Unpin + Debug + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn ::std::error::Error + Send + Sync>>,
{
    fn put(&mut self, access_label: AccessLabel, conn: HttpConnection<B>) {
        if conn.can_share() && self.idle.get(&access_label).is_some_and(|idle| !idle.is_empty()) {
            trace!("put; existing idle HTTP/2 connection for {access_label}");
            return;
        }

        let mut conn = Some(conn);
        let mut remove_waiters = false;

        if let Some(waiters) = self.waiters.get_mut(&access_label) {
            while let Some(waiter) = waiters.pop_front() {
                if waiter.is_closed() {
                    continue;
                }

                #[allow(clippy::expect_used)]
                let current = conn.take().expect("connection should exist");
                match current.reserve() {
                    Reservation::Unique(unique) => match waiter.send(unique) {
                        Ok(()) => {
                            conn = None;
                            break;
                        }
                        Err(returned) => {
                            conn = Some(returned);
                        }
                    },
                    Reservation::Shared(to_keep, to_send) => {
                        conn = Some(to_keep);
                        if waiter.send(to_send).is_ok() {
                            continue;
                        }
                    }
                }
            }
            remove_waiters = waiters.is_empty();
        }

        if remove_waiters {
            self.waiters.remove(&access_label);
        }

        if let Some(conn) = conn {
            let idle_list = self.idle.entry(access_label.clone()).or_default();
            if idle_list.len() >= self.max_idle_per_host {
                trace!("max idle per host reached for {access_label}, dropping connection");
                return;
            }
            idle_list.push(IdleEntry {
                conn,
                idle_at: Instant::now(),
            });
        }
    }

    fn take_idle(&mut self, access_label: &AccessLabel) -> Option<HttpConnection<B>> {
        let now = Instant::now();
        let mut should_remove_entry = false;
        let mut selected = None;

        if let Some(idle_list) = self.idle.get_mut(access_label) {
            while let Some(entry) = idle_list.pop() {
                let expired = now.saturating_duration_since(entry.idle_at) >= CONN_EXPIRE_TIMEOUT;
                if expired {
                    trace!("removing expired connection for {access_label}");
                    continue;
                }
                if !entry.conn.is_open() {
                    trace!("removing closed connection for {access_label}");
                    continue;
                }

                selected = Some(match entry.conn.reserve() {
                    Reservation::Unique(unique) => unique,
                    Reservation::Shared(to_reinsert, to_checkout) => {
                        idle_list.push(IdleEntry {
                            conn: to_reinsert,
                            idle_at: now,
                        });
                        to_checkout
                    }
                });
                break;
            }

            should_remove_entry = idle_list.is_empty();
        }

        if should_remove_entry {
            self.idle.remove(access_label);
        }

        selected
    }

    fn clear_expired(&mut self) -> usize {
        let now = Instant::now();
        let mut removed = 0usize;

        self.idle.retain(|access_label, idle_list| {
            let before = idle_list.len();
            idle_list.retain(|entry| {
                let expired = now.saturating_duration_since(entry.idle_at) >= CONN_EXPIRE_TIMEOUT;
                let open = entry.conn.is_open();
                !expired && open
            });
            removed += before.saturating_sub(idle_list.len());
            if idle_list.is_empty() {
                trace!("all idle connections removed for {access_label}");
            }
            !idle_list.is_empty()
        });

        removed
    }

    fn clean_waiters(&mut self) {
        self.waiters.retain(|_, waiters| {
            waiters.retain(|waiter| !waiter.is_closed());
            !waiters.is_empty()
        });
    }
}

pub struct ForwardProxyClient<B> {
    pool: Arc<Mutex<PoolInner<B>>>,
}

impl<B> Clone for ForwardProxyClient<B> {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
        }
    }
}

impl<B> ForwardProxyClient<B>
where
    B: Body + Send + Unpin + Debug + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn ::std::error::Error + Send + Sync>>,
{
    /// Create a new ForwardProxyClient.
    pub fn new() -> ForwardProxyClient<B> {
        let pool = Arc::new(Mutex::new(PoolInner::new(DEFAULT_MAX_IDLE_PER_HOST)));

        Self::spawn_cleanup_task(pool.clone());

        ForwardProxyClient { pool }
    }

    fn spawn_cleanup_task(pool: Arc<Mutex<PoolInner<B>>>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            loop {
                interval.tick().await;
                Self::cleanup_expired_connections(&pool).await;
            }
        });
    }

    async fn cleanup_expired_connections(pool: &Mutex<PoolInner<B>>) {
        let mut inner = pool.lock().await;
        let removed = inner.clear_expired();
        inner.clean_waiters();
        debug!("Connection cleanup completed: removed {removed} connections");
    }

    /// Make HTTP requests
    #[inline]
    pub async fn send_request<F>(
        &self, req: Request<B>, access_label: &AccessLabel, ipv6_first: Option<bool>, stream_map_func: F,
    ) -> Result<Response<body::Incoming>, io::Error>
    where
        F: Fn(EitherTlsStream, AccessLabel) -> CounterIO<EitherTlsStream, LabelImpl<AccessLabel>>
            + Send
            + Sync
            + Clone
            + 'static,
    {
        let uri = req.uri().clone();
        let req_version = req.version();
        let force_http1 = is_upgrade_request(&req);
        let mut req = req;

        loop {
            let mut pooled = self
                .connection_for(access_label.clone(), ipv6_first, req_version, force_http1, stream_map_func.clone())
                .await?;

            let url = req.uri().clone();
            trace!("HTTP making request to host: {access_label}, request: {req:?}");

            match pooled.conn.try_send_request(req).await {
                Ok(response) => {
                    trace!("HTTP received response from host: {access_label}, response: {response:?}");
                    self.recycle_after_response(access_label.clone(), pooled.conn, &response, url);
                    return Ok(response);
                }
                Err(mut err) => {
                    let req_back = err.take_message();
                    let send_err = err.into_error();

                    if let Some(mut retry_req) = req_back {
                        if pooled.is_reused {
                            trace!("unstarted request canceled, trying again for host: {access_label}");
                            *retry_req.uri_mut() = uri.clone();
                            req = retry_req;
                            continue;
                        }
                    }

                    return Err(io::Error::new(ErrorKind::InvalidData, send_err));
                }
            }
        }
    }

    fn recycle_after_response(
        &self, access_label: AccessLabel, mut conn: HttpConnection<B>, response: &Response<body::Incoming>, url: Uri,
    ) {
        if conn.is_http2() {
            return;
        }

        if !check_keep_alive(response.version(), response.headers(), false) {
            return;
        }

        let this = self.clone();
        tokio::spawn(async move {
            match conn.ready().await {
                Ok(_) => {
                    debug!("HTTP connection for host: {access_label} {url} is ready and will be cached");
                    this.insert_connection(access_label, conn).await;
                }
                Err(err) => {
                    debug!("HTTP connection for host: {access_label} {url} failed to become ready: {err}");
                }
            }
        });
    }

    async fn connection_for<F>(
        &self, access_label: AccessLabel, ipv6_first: Option<bool>, req_version: Version, force_http1: bool,
        stream_map_func: F,
    ) -> Result<PooledConnection<B>, io::Error>
    where
        F: Fn(EitherTlsStream, AccessLabel) -> CounterIO<EitherTlsStream, LabelImpl<AccessLabel>>
            + Send
            + Sync
            + Clone
            + 'static,
    {
        loop {
            match self
                .one_connection_for(access_label.clone(), ipv6_first, req_version, force_http1, stream_map_func.clone())
                .await
            {
                Ok(pooled) => return Ok(pooled),
                Err(AcquireError::CheckoutCanceled) | Err(AcquireError::ConnectCanceled) => {
                    trace!("connection acquire canceled for host: {access_label}, retrying");
                    continue;
                }
                Err(AcquireError::Io(err)) => return Err(err),
            }
        }
    }

    async fn one_connection_for<F>(
        &self, access_label: AccessLabel, ipv6_first: Option<bool>, req_version: Version, force_http1: bool,
        stream_map_func: F,
    ) -> Result<PooledConnection<B>, AcquireError>
    where
        F: Fn(EitherTlsStream, AccessLabel) -> CounterIO<EitherTlsStream, LabelImpl<AccessLabel>>
            + Send
            + Sync
            + Clone
            + 'static,
    {
        if let Some(conn) = self.try_take_idle_connection(&access_label).await {
            return Ok(PooledConnection { conn, is_reused: true });
        }

        let checkout_client = self.clone();
        let checkout_key = access_label.clone();
        let checkout = async move { checkout_client.checkout_connection(checkout_key).await }.boxed();

        let started = Arc::new(AtomicBool::new(false));
        let started_for_connect = started.clone();
        let connect_client = self.clone();
        let connect_key = access_label.clone();
        let connect = async move {
            started_for_connect.store(true, Ordering::Relaxed);
            connect_client
                .connect_to(connect_key, ipv6_first, req_version, force_http1, stream_map_func)
                .await
        }
        .boxed();

        match future::select(checkout, connect).await {
            Either::Left((Ok(checked_out), connecting)) => {
                if started.load(Ordering::Relaxed) {
                    self.spawn_background_connect(access_label, connecting);
                }
                Ok(checked_out)
            }
            Either::Right((Ok(connected), _checkout)) => Ok(connected),
            Either::Left((Err(err), connecting)) => {
                if err.is_canceled() {
                    connecting.await
                } else {
                    Err(AcquireError::CheckoutCanceled)
                }
            }
            Either::Right((Err(err), checkout)) => {
                if err.is_canceled() {
                    match checkout.await {
                        Ok(checked_out) => Ok(checked_out),
                        Err(checkout_err) => {
                            if checkout_err.is_canceled() {
                                Err(AcquireError::CheckoutCanceled)
                            } else {
                                Err(AcquireError::Io(io::Error::other(checkout_err.to_string())))
                            }
                        }
                    }
                } else {
                    Err(err)
                }
            }
        }
    }

    fn spawn_background_connect(
        &self, access_label: AccessLabel,
        connecting: futures_util::future::BoxFuture<'static, Result<PooledConnection<B>, AcquireError>>,
    ) {
        let this = self.clone();
        tokio::spawn(async move {
            match connecting.await {
                Ok(mut pooled) => {
                    if let Err(err) = pooled.conn.ready().await {
                        trace!("background connection for {access_label} is not ready: {err}");
                        return;
                    }
                    this.insert_connection(access_label, pooled.conn).await;
                }
                Err(AcquireError::Io(err)) => {
                    trace!("background connect error: {err}");
                }
                Err(_) => {}
            }
        });
    }

    async fn checkout_connection(&self, access_label: AccessLabel) -> Result<PooledConnection<B>, CheckoutError> {
        if let Some(conn) = self.try_take_idle_connection(&access_label).await {
            return Ok(PooledConnection { conn, is_reused: true });
        }

        let rx = {
            let mut inner = self.pool.lock().await;
            if let Some(conn) = inner.take_idle(&access_label) {
                return Ok(PooledConnection { conn, is_reused: true });
            }
            let (tx, rx) = oneshot::channel();
            inner.waiters.entry(access_label).or_default().push_back(tx);
            rx
        };

        match rx.await {
            Ok(conn) => {
                if conn.is_open() {
                    Ok(PooledConnection { conn, is_reused: true })
                } else {
                    Err(CheckoutError::CheckedOutClosedValue)
                }
            }
            Err(_) => Err(CheckoutError::CheckoutNoLongerWanted),
        }
    }

    async fn connect_to<F>(
        &self, access_label: AccessLabel, ipv6_first: Option<bool>, req_version: Version, force_http1: bool,
        stream_map_func: F,
    ) -> Result<PooledConnection<B>, AcquireError>
    where
        F: Fn(EitherTlsStream, AccessLabel) -> CounterIO<EitherTlsStream, LabelImpl<AccessLabel>>
            + Send
            + Sync
            + Clone
            + 'static,
    {
        let lock_h2_connecting = req_version == Version::HTTP_2 && !force_http1;

        if lock_h2_connecting {
            let mut inner = self.pool.lock().await;
            if !inner.connecting_h2.insert(access_label.clone()) {
                return Err(AcquireError::ConnectCanceled);
            }
        }

        let connected =
            HttpConnection::connect(&access_label, ipv6_first, req_version, force_http1, stream_map_func).await;

        if lock_h2_connecting {
            let mut inner = self.pool.lock().await;
            inner.connecting_h2.remove(&access_label);
            if connected.is_err() {
                // Wake all in-flight checkouts to retry like hyper-util legacy pool does.
                inner.waiters.remove(&access_label);
            }
        }

        let connected = connected.map_err(|err| {
            error!("failed to connect to host: {}, error: {}", access_label.target, err);
            AcquireError::Io(io::Error::new(ErrorKind::InvalidData, err))
        })?;

        self.build_pooled_connection(access_label, connected).await
    }

    async fn build_pooled_connection(
        &self, access_label: AccessLabel, connected: HttpConnection<B>,
    ) -> Result<PooledConnection<B>, AcquireError> {
        match connected.reserve() {
            Reservation::Unique(unique) => Ok(PooledConnection {
                conn: unique,
                is_reused: false,
            }),
            Reservation::Shared(to_insert, to_return) => {
                self.insert_connection(access_label, to_insert).await;
                Ok(PooledConnection {
                    conn: to_return,
                    is_reused: false,
                })
            }
        }
    }

    async fn try_take_idle_connection(&self, access_label: &AccessLabel) -> Option<HttpConnection<B>> {
        let mut inner = self.pool.lock().await;
        inner.take_idle(access_label)
    }

    async fn insert_connection(&self, access_label: AccessLabel, conn: HttpConnection<B>) {
        let mut inner = self.pool.lock().await;
        inner.put(access_label, conn);
    }
}

pub fn check_keep_alive(version: Version, headers: &HeaderMap<HeaderValue>, check_proxy: bool) -> bool {
    // HTTP/1.1, HTTP/2, HTTP/3 keeps alive by default.
    let mut conn_keep_alive = !matches!(version, Version::HTTP_09 | Version::HTTP_10);

    if check_proxy {
        // Modern browsers will send Proxy-Connection instead of Connection
        // for HTTP/1.0 proxies which blindly forward Connection to remote.
        if let Some(b) = get_keep_alive_val(headers.get_all("Proxy-Connection")) {
            conn_keep_alive = b;
        }
    }

    // Connection will replace Proxy-Connection.
    if let Some(b) = get_keep_alive_val(headers.get_all("Connection")) {
        conn_keep_alive = b;
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
    pub(crate) async fn connect<F>(
        access_label: &AccessLabel, ipv6_first: Option<bool>, req_version: Version, force_http1: bool,
        stream_map_func: F,
    ) -> io::Result<HttpConnection<B>>
    where
        F: Fn(EitherTlsStream, AccessLabel) -> CounterIO<EitherTlsStream, LabelImpl<AccessLabel>> + Send + Sync,
    {
        let stream = crate::proxy::connect_with_preference(&access_label.target, ipv6_first).await?;
        let stream = if let Some(true) = access_label.relay_over_tls {
            let connector = build_tls_connector();

            let host = &access_label
                .target
                .split(':')
                .next()
                .ok_or(io::Error::other("invalid host"))?;
            let server_name = pki_types::ServerName::try_from(*host)
                .map_err(|e| io::Error::new(ErrorKind::InvalidInput, format!("Invalid DNS name: {e}")))?
                .to_owned();

            match connector.connect(server_name, stream).await {
                Ok(tls_stream) => EitherTlsStream::Tls { stream: tls_stream },
                Err(e) => {
                    warn!("[forward_bypass TLS handshake error] [{}]: {}", access_label, e);
                    return Err(e);
                }
            }
        } else {
            EitherTlsStream::Tcp { stream }
        };

        let negotiated_h2 = match &stream {
            EitherTlsStream::Tcp { .. } => false,
            EitherTlsStream::Tls { stream } => stream.get_ref().1.alpn_protocol().is_some_and(|alpn| alpn == b"h2"),
        };

        let stream: CounterIO<EitherTlsStream, LabelImpl<AccessLabel>> = stream_map_func(stream, access_label.clone());

        let use_h2 = !force_http1 && (req_version == Version::HTTP_2 || negotiated_h2);
        if use_h2 {
            Self::connect_http2(access_label, stream).await
        } else {
            Self::connect_http1(access_label, stream).await
        }
    }

    async fn connect_http1(
        access_label: &AccessLabel, stream: CounterIO<EitherTlsStream, LabelImpl<AccessLabel>>,
    ) -> io::Result<HttpConnection<B>> {
        let stream = TimeoutIO::new(stream, crate::IDLE_TIMEOUT);
        let (send_request, connection) = http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(Box::pin(TokioIo::new(stream)))
            .await
            .map_err(io::Error::other)?;

        let access_label = access_label.clone();
        tokio::spawn(async move {
            if let Err(err) = connection.with_upgrades().await {
                handle_http1_connection_error(err, access_label);
            }
        });
        Ok(HttpConnection::Http1(send_request))
    }

    async fn connect_http2(
        access_label: &AccessLabel, stream: CounterIO<EitherTlsStream, LabelImpl<AccessLabel>>,
    ) -> io::Result<HttpConnection<B>> {
        let stream = TimeoutIO::new(stream, crate::IDLE_TIMEOUT);
        let (mut send_request, connection) = http2::Builder::new(TokioExecutor::new())
            .handshake(Box::pin(TokioIo::new(stream)))
            .await
            .map_err(io::Error::other)?;

        let access_label = access_label.clone();
        tokio::spawn(async move {
            if let Err(err) = connection.await {
                handle_http2_connection_error(err, access_label);
            }
        });

        send_request.ready().await.map_err(io::Error::other)?;
        Ok(HttpConnection::Http2(send_request))
    }

    #[inline]
    pub async fn try_send_request(
        &mut self, req: Request<B>,
    ) -> Result<Response<body::Incoming>, ConnTrySendError<Request<B>>> {
        match self {
            HttpConnection::Http1(r) => r.try_send_request(req).await,
            HttpConnection::Http2(r) => r.try_send_request(req).await,
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

    pub fn is_open(&self) -> bool {
        !self.is_closed() && self.is_ready()
    }

    pub fn is_http2(&self) -> bool {
        matches!(self, HttpConnection::Http2(_))
    }

    pub fn can_share(&self) -> bool {
        self.is_http2()
    }

    fn reserve(self) -> Reservation<Self> {
        match self {
            HttpConnection::Http1(tx) => Reservation::Unique(HttpConnection::Http1(tx)),
            HttpConnection::Http2(tx) => {
                let to_checkout = HttpConnection::Http2(tx.clone());
                let to_reinsert = HttpConnection::Http2(tx);
                Reservation::Shared(to_reinsert, to_checkout)
            }
        }
    }

    pub async fn ready(&mut self) -> Result<(), hyper::Error> {
        match self {
            HttpConnection::Http1(r) => r.ready().await,
            HttpConnection::Http2(r) => r.ready().await,
        }
    }
}

struct PooledConnection<B> {
    conn: HttpConnection<B>,
    is_reused: bool,
}

#[derive(Debug)]
enum CheckoutError {
    CheckoutNoLongerWanted,
    CheckedOutClosedValue,
}

impl CheckoutError {
    fn is_canceled(&self) -> bool {
        true
    }
}

impl Display for CheckoutError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckoutError::CheckoutNoLongerWanted => f.write_str("request was canceled"),
            CheckoutError::CheckedOutClosedValue => f.write_str("checked out connection was closed"),
        }
    }
}

#[derive(Debug)]
enum AcquireError {
    CheckoutCanceled,
    ConnectCanceled,
    Io(io::Error),
}

impl AcquireError {
    fn is_canceled(&self) -> bool {
        matches!(self, AcquireError::CheckoutCanceled | AcquireError::ConnectCanceled)
    }
}

fn is_upgrade_request<B>(req: &Request<B>) -> bool {
    req.headers().contains_key(http::header::UPGRADE)
}

fn handle_http1_connection_error(err: hyper::Error, access_label: AccessLabel) {
    if let Some(io_err) = err.source().and_then(|s| s.downcast_ref::<io::Error>()) {
        if io_err.kind() == ErrorKind::TimedOut {
            // Closed by TimeoutIO.
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

fn handle_http2_connection_error(err: hyper::Error, access_label: AccessLabel) {
    if let Some(io_err) = err.source().and_then(|s| s.downcast_ref::<io::Error>()) {
        if io_err.kind() == ErrorKind::TimedOut {
            info!("[legacy proxy h2 io closed]: [{}] {} to {}", io_err.kind(), io_err, access_label);
        } else {
            warn!("[legacy proxy h2 io error]: [{}] {} to {}", io_err.kind(), io_err, access_label);
        }
    } else if let Some(source) = err.source() {
        warn!("[legacy proxy h2 io error]: [{source}] to {access_label}");
    } else {
        warn!("[legacy proxy h2 io error] [{err}] to {access_label}");
    }
}
