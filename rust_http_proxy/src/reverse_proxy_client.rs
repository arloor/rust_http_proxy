use std::{fmt::Debug, io};

use http_body::Body;
use hyper::{Request, Response, body};
use log::{debug, trace};

use crate::{
    connection_pool::{IdlePool, MAX_IDLE_HTTP1_PER_KEY, MAX_IDLE_HTTP2_PER_KEY},
    forward_proxy_client::{DirectConnectionKey, DirectProtocol, DirectSendError, HttpConnection, check_keep_alive},
    proxy::AccessLabel,
};

pub(crate) struct ReverseProxyClient<B> {
    pool: IdlePool<DirectConnectionKey, HttpConnection<B>>,
}

impl<B> Clone for ReverseProxyClient<B> {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
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
        Self { pool: IdlePool::new() }
    }

    pub(crate) async fn send_request(
        &self, req: Request<B>, connection_key: &DirectConnectionKey, access_label: &AccessLabel,
        ipv6_first: Option<bool>,
    ) -> io::Result<Response<body::Incoming>> {
        if let Some(connection) = self.pool.take(connection_key).await {
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

    async fn try_send_on_connection(
        &self, req: Request<B>, connection_key: &DirectConnectionKey, access_label: &AccessLabel,
        mut connection: HttpConnection<B>,
    ) -> Result<Response<body::Incoming>, DirectSendError<B>> {
        let uri = req.uri().clone();
        trace!("reverse proxy request to {access_label}: {uri}");

        if let Some(cacheable) = connection.clone_for_multiplexed_cache() {
            self.cache_connection(connection_key.clone(), cacheable).await;
        }

        let response = connection.try_send_direct_request(req, connection_key).await?;
        if connection.is_multiplexed() {
            return Ok(response);
        }

        if check_keep_alive(response.version(), response.headers(), false) {
            let client = self.clone();
            let connection_key = connection_key.clone();
            tokio::spawn(async move {
                if connection.ready().await.is_ok() {
                    client.cache_connection(connection_key, connection).await;
                } else {
                    debug!("reverse proxy HTTP/1.1 connection was not reusable");
                }
            });
        }
        Ok(response)
    }

    async fn cache_connection(&self, connection_key: DirectConnectionKey, connection: HttpConnection<B>) {
        let max_idle = match connection_key.protocol {
            DirectProtocol::Http1 => MAX_IDLE_HTTP1_PER_KEY,
            DirectProtocol::Http2 => MAX_IDLE_HTTP2_PER_KEY,
        };
        self.pool.insert_oldest(connection_key, connection, max_idle).await;
    }
}
