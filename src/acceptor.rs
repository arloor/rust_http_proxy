// https://github.com/rustls/hyper-rustls/blob/286e1fa57ff5cac99994fab355f91c3454d6d83d/src/acceptor.rs
use core::task::{Context, Poll};
use std::future::Future;
use std::io;
use std::io::{Error};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use futures_util::ready;
use hyper::server::{
    accept::Accept,
    conn::{AddrIncoming, AddrStream},
};
use log::{info, warn};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::tls_helper::tls_config;


enum State {
    Handshaking(tokio_rustls::Accept<AddrStream>),
    Streaming(tokio_rustls::server::TlsStream<AddrStream>),
}

// tokio_rustls::server::TlsStream doesn't expose constructor methods,
// so we have to TlsAcceptor::accept and handshake to have access to it
// TlsStream implements AsyncRead/AsyncWrite by handshaking with tokio_rustls::Accept first
pub struct TlsStream {
    state: State,
}

impl TlsStream {
    fn new(stream: AddrStream, config: Arc<ServerConfig>) -> TlsStream {
        let accept = tokio_rustls::TlsAcceptor::from(config).accept(stream);
        TlsStream {
            state: State::Handshaking(accept),
        }
    }
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        match &self.state {
            State::Handshaking(accept) => {
                match accept.get_ref() {
                    Some(addr_stream) => Some(addr_stream.remote_addr()),
                    None => None
                }
            }
            State::Streaming(tls_stream) => Some(tls_stream.get_ref().0.remote_addr()),
        }
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let pin = self.get_mut();
        match pin.state {
            State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    let result = Pin::new(&mut stream).poll_read(cx, buf);
                    pin.state = State::Streaming(stream);
                    result
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            State::Streaming(ref mut stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let pin = self.get_mut();
        match pin.state {
            State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    let result = Pin::new(&mut stream).poll_write(cx, buf);
                    pin.state = State::Streaming(stream);
                    result
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            State::Streaming(ref mut stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// A TLS acceptor that can be used with hyper servers.
pub struct TlsAcceptor {
    key: String,
    cert: String,
    config: Arc<ServerConfig>,
    incoming: AddrIncoming,
    last_refresh_time: SystemTime,
}

/// An Acceptor for the `https` scheme.
impl TlsAcceptor {
    /// Provides a builder for a `TlsAcceptor`.
    /// Creates a new `TlsAcceptor` from a `ServerConfig` and an `AddrIncoming`.


    pub fn new(key: String, cert: String, incoming: AddrIncoming) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
        let config = tls_config(&key, &cert)?;
        let acceptor = TlsAcceptor { key, cert, config, incoming, last_refresh_time: SystemTime::now() };
        return Ok(acceptor);
    }

    fn refresh_if_need(&mut self) {
        let now = SystemTime::now();
        if now.duration_since(self.last_refresh_time).unwrap_or(Duration::from_secs(0)) > Duration::from_secs(REFRESH_TIME) {
            self.last_refresh_time = now;
            match tls_config(&self.key, &self.cert) {
                Ok(config) => {
                    info!("success refresh certs!");
                    self.config = config
                }
                Err(e) => {
                    warn!("error refresh certs, {:?}",e);
                }
            }
        }
    }
}

// 每两小时更新证书
const REFRESH_TIME: u64 = 2 * 60 * 60;

impl Accept for TlsAcceptor {
    type Conn = TlsStream;
    type Error = Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let pin = self.get_mut();
        pin.refresh_if_need();
        match ready!(Pin::new(&mut pin.incoming).poll_accept(cx)) {
            Some(Ok(sock)) => Poll::Ready(Some(Ok(TlsStream::new(sock, pin.config.clone())))),
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}