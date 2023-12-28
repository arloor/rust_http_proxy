use std::{pin::Pin, task::Context, task::Poll};

use pin_project_lite::pin_project;
use prometheus_client::metrics::{counter::Counter, family::Family};

use crate::proxy::AccessLabel;

pin_project! {
    /// A wrapping implementing hyper IO traits for a type that
    /// implements Tokio's IO traits.
    #[derive(Debug)]
    pub struct TcpStreamWrapper<T> {
        #[pin]
        pub(crate) inner: T,
        pub(crate) proxy_traffic: Family<AccessLabel, Counter, fn() -> Counter>,
        pub(crate) access_label: AccessLabel,
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
        let proxy_traffic = self.proxy_traffic.clone();
        let access_label = self.access_label.clone();
        match self.project().inner.poll_read(cx, buf) {
            Poll::Ready(Ok(_)) => {
                proxy_traffic
                    .get_or_create(&access_label)
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
        let proxy_traffic = self.proxy_traffic.clone();
        let access_label = self.access_label.clone();
        match self.project().inner.poll_write(cx, buf) {
            Poll::Ready(result) =>{
                if let Ok(size) = result {
                    proxy_traffic
                        .get_or_create(&access_label)
                        .inc_by(size as u64);
                }
                Poll::Ready(result)
            },
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
