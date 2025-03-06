use std::{fmt::Debug, pin::Pin, task::Context, task::Poll};

use pin_project_lite::pin_project;
use prometheus_client::metrics::{counter::Counter, family::Family};
use std::io;
use std::time::Duration;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;

use futures_util::Future;
use tokio::time::{sleep, Instant, Sleep};

use prom_label::Label;

pin_project! {
    /// enhance inner tcp stream with prometheus counter
    #[derive(Debug)]
    pub struct CounterIO<T,R>
    where
    T: AsyncWrite,
    T: AsyncRead,
    R: Label
    {
        #[pin]
        inner: T,
        traffic_counter: Family<R, Counter>,
        label: R,
    }
}

impl<T, R> CounterIO<T, R>
where
    T: AsyncWrite + AsyncRead,
    R: Label,
{
    pub fn new(inner: T, traffic_counter: Family<R, Counter>, label: R) -> Self {
        Self {
            inner,
            traffic_counter,
            label,
        }
    }
}

impl<T, R> AsyncRead for CounterIO<T, R>
where
    T: AsyncWrite + AsyncRead,
    R: Label,
{
    fn poll_read(
        self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let pro = self.project();
        let traffic_counter = pro.traffic_counter;
        let label = pro.label;
        match pro.inner.poll_read(cx, buf) {
            Poll::Ready(Ok(_)) => {
                traffic_counter.get_or_create(label).inc_by(buf.filled().len() as u64);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<T, R> AsyncWrite for CounterIO<T, R>
where
    T: AsyncWrite + AsyncRead,
    R: Label,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
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

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        let pro = self.project();
        let count = bufs.iter().map(|buf| buf.len()).sum::<usize>() as u64;
        pro.traffic_counter.get_or_create(pro.label).inc_by(count);
        pro.inner.poll_write_vectored(cx, bufs)
    }
}

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
    pub fn new(inner: T, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            idle_future: sleep(timeout),
        }
    }
    /// set timeout
    pub fn _set_timeout_pinned(mut self: Pin<&mut Self>, timeout: Duration) {
        *self.as_mut().project().timeout = timeout;
        self.project().idle_future.as_mut().reset(Instant::now() + timeout);
    }
}

impl<T> AsyncRead for TimeoutIO<T>
where
    T: AsyncWrite + AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let pro = self.project();
        let idle_feature = pro.idle_future;
        let timeout: &mut Duration = pro.timeout;
        let read_poll = pro.inner.poll_read(cx, buf);
        if read_poll.is_ready() {
            // 读到内容或者读到EOF等等,重置计时
            idle_feature.reset(Instant::now() + *timeout);
        } else if idle_feature.poll(cx).is_ready() {
            // 没有读到内容，且已经timeout，则返回错误
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, format!("read idle for {:?}", timeout))));
        }
        read_poll
    }
}

impl<T> AsyncWrite for TimeoutIO<T>
where
    T: AsyncWrite + AsyncRead,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
        let pro = self.project();
        let idle_feature = pro.idle_future;
        let timeout: &mut Duration = pro.timeout;
        let write_poll = pro.inner.poll_write(cx, buf);
        if write_poll.is_ready() {
            idle_feature.reset(Instant::now() + *timeout);
        } else if idle_feature.poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, format!("write idle for {:?}", timeout))));
        }
        write_poll
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let pro = self.project();
        let idle_feature = pro.idle_future;
        let timeout: &mut Duration = pro.timeout;
        let write_poll = pro.inner.poll_flush(cx);
        if write_poll.is_ready() {
            idle_feature.reset(Instant::now() + *timeout);
        } else if idle_feature.poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, format!("write idle for {:?}", timeout))));
        }
        write_poll
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let pro = self.project();
        let idle_feature = pro.idle_future;
        let timeout: &mut Duration = pro.timeout;
        let write_poll = pro.inner.poll_shutdown(cx);
        if write_poll.is_ready() {
            idle_feature.reset(Instant::now() + *timeout);
        } else if idle_feature.poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, format!("write idle for {:?}", timeout))));
        }
        write_poll
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        let pro = self.project();
        let idle_feature = pro.idle_future;
        let timeout: &mut Duration = pro.timeout;
        let write_poll = pro.inner.poll_write_vectored(cx, bufs);
        if write_poll.is_ready() {
            idle_feature.reset(Instant::now() + *timeout);
        } else if idle_feature.poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, format!("write idle for {:?}", timeout))));
        }
        write_poll
    }
}
