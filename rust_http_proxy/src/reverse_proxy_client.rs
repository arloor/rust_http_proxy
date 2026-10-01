use std::{fmt::Debug, io};

use http_body::Body;
use hyper::{Request, Response, body};
use log::{debug, trace};

use crate::{
    connection_pool::IdlePool,
    forward_proxy_client::{DirectConnectionKey, DirectSendError, HttpConnection},
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
        let req = match self.pool.take(connection_key).await {
            Some(connection) => {
                match self
                    .try_send_on_connection(req, connection_key, access_label, connection)
                    .await
                {
                    Ok(response) => return Ok(response),
                    Err(mut error) => match error.take_request() {
                        Some(req) => {
                            debug!("retrying request after a reused reverse proxy connection closed before sending");
                            req
                        }
                        None => return Err(error.into_io_error()),
                    },
                }
            }
            None => req,
        };

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
        trace!("reverse proxy request to {access_label}: {}", req.uri());
        self.pool.share_if_multiplexed(connection_key, &connection).await;
        let response = connection.try_send_direct_request(req, connection_key).await?;
        self.pool
            .recycle_after_response(connection_key.clone(), connection, &response);
        Ok(response)
    }
}
