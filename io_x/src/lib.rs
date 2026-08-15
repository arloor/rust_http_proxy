use std::{fmt::Debug, pin::Pin, task::Context, task::Poll};

use pin_project_lite::pin_project;
use prometheus_client::metrics::{counter::Counter, family::Family};
use std::io;
use std::time::Duration;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;

use futures_util::Future;
use tokio::time::{Instant, Sleep, sleep};

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
        timeout:Option<Duration>,
        #[pin]
        idle_future:Sleep
    }
}

impl<T> TimeoutIO<T>
where
    T: AsyncWrite + AsyncRead,
{
    pub fn new(inner: T, timeout: Duration) -> Self {
        Self::new_optional(inner, Some(timeout))
    }

    pub fn new_optional(inner: T, timeout: Option<Duration>) -> Self {
        Self {
            inner,
            timeout,
            idle_future: sleep(timeout.unwrap_or(Duration::ZERO)),
        }
    }
    /// set timeout
    pub fn _set_timeout_pinned(mut self: Pin<&mut Self>, timeout: Duration) {
        *self.as_mut().project().timeout = Some(timeout);
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
        let timeout: &mut Option<Duration> = pro.timeout;
        let read_poll = pro.inner.poll_read(cx, buf);
        if let Some(timeout) = *timeout {
            if read_poll.is_ready() {
                // 读到内容或者读到EOF等等,重置计时
                idle_feature.reset(Instant::now() + timeout);
            } else if idle_feature.poll(cx).is_ready() {
                // 没有读到内容，且已经timeout，则返回错误
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, format!("read idle for {timeout:?}"))));
            }
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
        let timeout: &mut Option<Duration> = pro.timeout;
        let write_poll = pro.inner.poll_write(cx, buf);
        if let Some(timeout) = *timeout {
            if write_poll.is_ready() {
                idle_feature.reset(Instant::now() + timeout);
            } else if idle_feature.poll(cx).is_ready() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("write idle for {timeout:?}"),
                )));
            }
        }
        write_poll
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let pro = self.project();
        let idle_feature = pro.idle_future;
        let timeout: &mut Option<Duration> = pro.timeout;
        let write_poll = pro.inner.poll_flush(cx);
        if let Some(timeout) = *timeout {
            if write_poll.is_ready() {
                idle_feature.reset(Instant::now() + timeout);
            } else if idle_feature.poll(cx).is_ready() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("write idle for {timeout:?}"),
                )));
            }
        }
        write_poll
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let pro = self.project();
        let idle_feature = pro.idle_future;
        let timeout: &mut Option<Duration> = pro.timeout;
        let write_poll = pro.inner.poll_shutdown(cx);
        if let Some(timeout) = *timeout {
            if write_poll.is_ready() {
                idle_feature.reset(Instant::now() + timeout);
            } else if idle_feature.poll(cx).is_ready() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("write idle for {timeout:?}"),
                )));
            }
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
        let timeout: &mut Option<Duration> = pro.timeout;
        let write_poll = pro.inner.poll_write_vectored(cx, bufs);
        if let Some(timeout) = *timeout {
            if write_poll.is_ready() {
                idle_feature.reset(Instant::now() + timeout);
            } else if idle_feature.poll(cx).is_ready() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("write idle for {timeout:?}"),
                )));
            }
        }
        write_poll
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[tokio::test]
    async fn optional_timeout_can_be_disabled_for_upgraded_tunnels() -> io::Result<()> {
        let (client, mut server) = tokio::io::duplex(16);
        let mut client = Box::pin(TimeoutIO::new_optional(client, None));
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            server.write_all(b"ok").await
        });

        let mut bytes = [0; 2];
        tokio::time::timeout(Duration::from_secs(1), client.as_mut().read_exact(&mut bytes))
            .await
            .map_err(io::Error::other)??;
        writer.await.map_err(io::Error::other)??;
        assert_eq!(&bytes, b"ok");
        Ok(())
    }
}
