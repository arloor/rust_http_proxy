use std::io;
use std::time::Duration;
use std::{fmt::Debug, pin::Pin, task::Context, task::Poll};

use futures_util::Future;
use pin_project_lite::pin_project;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::time::{sleep, Instant, Sleep};

pin_project! {
    /// enhance inner tcp stream with prometheus counter
    #[derive(Debug)]
    pub struct TimeoutIO<T>
    where
    T: AsyncWrite,
    T: AsyncRead,
    {
        #[pin]
        inner: T,
        timeout:Duration,
        #[pin]
        idle_future:Sleep
    }
}

impl<T> TimeoutIO<T>
where
    T: AsyncWrite + AsyncRead,
{
    pub fn new(inner: T, timeout:Duration) -> Self {
        Self {
            inner,
            timeout,
            idle_future: sleep(timeout),
        }
    }
}

impl<T> AsyncRead for TimeoutIO<T>
where
    T: AsyncWrite + AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let pro = self.project();
        let mut idle_feature = pro.idle_future;
        let timeout: &mut Duration = pro.timeout;
        let read_poll = pro.inner.poll_read(cx, buf);
        if read_poll.is_ready(){
            // 读到内容或者读到EOF等等,重置计时
            idle_feature.as_mut().reset(Instant::now() + *timeout);
        }else if idle_feature.poll(cx).is_ready(){ 
            // 没有读到内容，且已经timeout，则返回错误
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::TimedOut)));
        }
        read_poll
    }
}

impl<T> AsyncWrite for TimeoutIO<T>
where
    T: AsyncWrite + AsyncRead,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let pro = self.project();
        pro.inner.poll_write(cx, buf)
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
        let pro = self.project();
        pro.inner.poll_write_vectored(cx, bufs)
    }
}
