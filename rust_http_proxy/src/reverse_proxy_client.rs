use std::{
    collections::VecDeque,
    fmt::Debug,
    io,
    sync::Arc,
    time::{Duration, Instant},
};

use http_body::Body;
use hyper::{Request, Response, body};
use log::{debug, trace};
use lru_time_cache::LruCache;
use tokio::sync::Mutex;

use crate::{
    forward_proxy_client::{
        CONN_EXPIRE_TIMEOUT, DirectConnectionKey, DirectProtocol, DirectSendError, HttpConnection, check_keep_alive,
    },
    proxy::AccessLabel,
};

const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const MAX_POOL_KEYS: usize = 1024;
const MAX_IDLE_HTTP1_PER_KEY: usize = 5;
const MAX_IDLE_HTTP2_PER_KEY: usize = 1;
type ConnectionQueue<B> = VecDeque<(HttpConnection<B>, Instant)>;
type ConnectionCache<B> = Arc<Mutex<LruCache<DirectConnectionKey, ConnectionQueue<B>>>>;

pub(crate) struct ReverseProxyClient<B> {
    cache: ConnectionCache<B>,
}

impl<B> Clone for ReverseProxyClient<B> {
    fn clone(&self) -> Self {
        Self {
            cache: self.cache.clone(),
        }
    }
}

impl<B> ReverseProxyClient<B>
where
    B: Body + Send + Unpin + Debug + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    pub(crate) fn new() -> Self {
        let cache =
            Arc::new(Mutex::new(LruCache::with_expiry_duration_and_capacity(CONN_EXPIRE_TIMEOUT, MAX_POOL_KEYS)));
        Self::spawn_cleanup_task(cache.clone());
        Self { cache }
    }

    fn spawn_cleanup_task(cache: ConnectionCache<B>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            loop {
                interval.tick().await;
                let mut cache = cache.lock().await;
                let now = Instant::now();
                let keys = cache.iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
                for key in keys {
                    if let Some(queue) = cache.get_mut(&key) {
                        queue.retain(|(connection, created_at)| {
                            now.duration_since(*created_at) < CONN_EXPIRE_TIMEOUT && !connection.is_closed()
                        });
                    }
                    if cache.get(&key).is_some_and(VecDeque::is_empty) {
                        cache.remove(&key);
                    }
                }
            }
        });
    }

    pub(crate) async fn send_request(
        &self, req: Request<B>, connection_key: &DirectConnectionKey, access_label: &AccessLabel,
        ipv6_first: Option<bool>,
    ) -> io::Result<Response<body::Incoming>> {
        if let Some(connection) = self.take_cached_connection(connection_key).await {
            return match self
                .try_send_on_connection(req, connection_key, access_label, connection)
                .await
            {
                Ok(response) => Ok(response),
                Err(mut error) => match error.take_request() {
                    Some(req) => {
                        debug!("retrying request after a reused reverse proxy connection closed before sending");
                        let connection = HttpConnection::connect_direct(
                            connection_key,
                            access_label,
                            ipv6_first,
                            Some(crate::IDLE_TIMEOUT),
                        )
                        .await?;
                        self.try_send_on_connection(req, connection_key, access_label, connection)
                            .await
                            .map_err(DirectSendError::into_io_error)
                    }
                    None => Err(error.into_io_error()),
                },
            };
        }

        let connection =
            HttpConnection::connect_direct(connection_key, access_label, ipv6_first, Some(crate::IDLE_TIMEOUT)).await?;
        self.try_send_on_connection(req, connection_key, access_label, connection)
            .await
            .map_err(DirectSendError::into_io_error)
    }

    pub(crate) async fn send_request_uncached(
        &self, req: Request<B>, connection_key: &DirectConnectionKey, access_label: &AccessLabel,
        ipv6_first: Option<bool>,
    ) -> io::Result<Response<body::Incoming>> {
        // Upgrade tunnels have their own lifetime and must not inherit the
        // ordinary HTTP connection idle timeout.
        let mut connection = HttpConnection::connect_direct(connection_key, access_label, ipv6_first, None).await?;
        connection.send_direct_request(req, connection_key).await
    }

    async fn take_cached_connection(&self, connection_key: &DirectConnectionKey) -> Option<HttpConnection<B>> {
        let mut cache = self.cache.lock().await;
        let queue = cache.get_mut(connection_key)?;
        while let Some((connection, created_at)) = queue.pop_front() {
            if created_at.elapsed() < CONN_EXPIRE_TIMEOUT && !connection.is_closed() && connection.is_ready() {
                return Some(connection);
            }
        }
        None
    }

    async fn try_send_on_connection(
        &self, req: Request<B>, connection_key: &DirectConnectionKey, access_label: &AccessLabel,
        mut connection: HttpConnection<B>,
    ) -> Result<Response<body::Incoming>, DirectSendError<B>> {
        let uri = req.uri().clone();
        trace!("reverse proxy request to {access_label}: {uri}");

        if let Some(cacheable) = connection.clone_for_multiplexed_cache() {
            let mut cache = self.cache.lock().await;
            Self::insert_cached_connection(&mut cache, connection_key.clone(), cacheable);
        }

        let response = connection.try_send_direct_request(req, connection_key).await?;
        if connection.is_multiplexed() {
            return Ok(response);
        }

        if check_keep_alive(response.version(), response.headers(), false) {
            let cache = self.cache.clone();
            let connection_key = connection_key.clone();
            tokio::spawn(async move {
                if connection.ready().await.is_ok() {
                    let mut cache = cache.lock().await;
                    Self::insert_cached_connection(&mut cache, connection_key, connection);
                } else {
                    debug!("reverse proxy HTTP/1.1 connection was not reusable");
                }
            });
        }
        Ok(response)
    }

    fn insert_cached_connection(
        cache: &mut LruCache<DirectConnectionKey, ConnectionQueue<B>>, connection_key: DirectConnectionKey,
        connection: HttpConnection<B>,
    ) {
        let max_idle = match connection_key.protocol {
            DirectProtocol::Http1 => MAX_IDLE_HTTP1_PER_KEY,
            DirectProtocol::Http2 => MAX_IDLE_HTTP2_PER_KEY,
        };
        let queue = cache.entry(connection_key).or_insert_with(VecDeque::new);
        while queue.len() >= max_idle {
            queue.pop_front();
        }
        queue.push_back((connection, Instant::now()));
    }
}
