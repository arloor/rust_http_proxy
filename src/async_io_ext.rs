use core::hash::Hash;
use std::{fmt::Debug, pin::Pin, task::Context, task::Poll};

use pin_project_lite::pin_project;
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family},
};
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;

pin_project! {
    /// enhance inner tcp stream with prometheus counter
    #[derive(Debug)]
    pub struct AsyncIOExt<T,R>
    where
    T: AsyncWrite,
    T: AsyncRead,
    R: Clone,
    R: Debug,
    R: Hash,
    R: PartialEq,
    R: Eq ,
    R: EncodeLabelSet,
    R:'static,
    {
        #[pin]
        inner: T,
        traffic_counter: Family<R, Counter, fn() -> Counter>,
        label: R,
    }
}

impl<T, R> AsyncIOExt<T, R>
where
    T: AsyncWrite + AsyncRead,
    R: Clone + Debug + Hash + PartialEq + Eq + EncodeLabelSet + 'static,
{
    pub fn new(inner: T, traffic_counter: Family<R, Counter, fn() -> Counter>, label: R) -> Self {
        Self {
            inner,
            traffic_counter,
            label,
        }
    }
}

impl<T, R> AsyncRead for AsyncIOExt<T, R>
where
    T: AsyncWrite + AsyncRead,
    R: Clone + Debug + Hash + PartialEq + Eq + EncodeLabelSet + 'static,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let pro = self.project();
        let traffic_counter = pro.traffic_counter;
        let label = pro.label;
        match pro.inner.poll_read(cx, buf) {
            Poll::Ready(Ok(_)) => {
                traffic_counter
                    .get_or_create(label)
                    .inc_by(buf.filled().len() as u64);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<T, R> AsyncWrite for AsyncIOExt<T, R>
where
    T: AsyncWrite + AsyncRead,
    R: Clone + Debug + Hash + PartialEq + Eq + EncodeLabelSet + 'static,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let pro = self.project();
        let traffic_counter = pro.traffic_counter;
        let label = pro.label;
        match pro.inner.poll_write(cx, buf) {
            Poll::Ready(result) => {
                if let Ok(size) = result {
                    traffic_counter.get_or_create(label).inc_by(size as u64);
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
