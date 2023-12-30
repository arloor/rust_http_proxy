use std::{pin::Pin, task::Context, task::Poll};

use pin_project_lite::pin_project;
use prometheus_client::metrics::{counter::Counter, family::Family};

use crate::proxy::AccessLabel;

pin_project! {
    /// enhance inner tcp stream with prometheus counter
    #[derive(Debug)]
    pub struct TcpStreamWrapper<T> {
        #[pin]
        inner: T,
        proxy_traffic: Family<AccessLabel, Counter, fn() -> Counter>,
        access_label: AccessLabel,
    }
}

impl<T> TcpStreamWrapper<T> {
    pub fn new(
        inner: T,
        proxy_traffic: Family<AccessLabel, Counter, fn() -> Counter>,
        access_label: AccessLabel,
    ) -> Self {
        Self {
            inner,
            proxy_traffic,
            access_label: access_label.clone(),
        }
    }
}

impl<T> tokio::io::AsyncRead for TcpStreamWrapper<T>
where
    T: tokio::io::AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let pro = self.project();
        let proxy_traffic =pro.proxy_traffic;
        let access_label = pro.access_label;
        match pro.inner.poll_read(cx, buf) {
            Poll::Ready(Ok(_)) => {
                proxy_traffic
                    .get_or_create(access_label)
                    .inc_by(buf.filled().len() as u64);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<T> tokio::io::AsyncWrite for TcpStreamWrapper<T>
where
    T: tokio::io::AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let pro = self.project();
        let proxy_traffic =pro.proxy_traffic;
        let access_label = pro.access_label;
        match pro.inner.poll_write(cx, buf) {
            Poll::Ready(result) => {
                if let Ok(size) = result {
                    proxy_traffic
                        .get_or_create(access_label)
                        .inc_by(size as u64);
                }
                Poll::Ready(result)
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.project().inner.poll_write_vectored(cx, bufs)
    }
}
