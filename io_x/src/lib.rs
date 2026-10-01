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
        let filled_before = buf.filled().len();
        let poll = pro.inner.poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = poll {
            let read = buf.filled().len().saturating_sub(filled_before);
            pro.traffic_counter.get_or_create(pro.label).inc_by(read as u64);
        }
        poll
    }
}

impl<T, R> AsyncWrite for CounterIO<T, R>
where
    T: AsyncWrite + AsyncRead,
    R: Label,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, std::io::Error>> {
        let pro = self.project();
        let poll = pro.inner.poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = poll {
            pro.traffic_counter.get_or_create(pro.label).inc_by(written as u64);
        }
        poll
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
        let poll = pro.inner.poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(written)) = poll {
            pro.traffic_counter.get_or_create(pro.label).inc_by(written as u64);
        }
        poll
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
    use prom_label::LabelImpl;
    use prometheus_client::encoding::EncodeLabelSet;
    use std::future::poll_fn;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, ReadBuf};

    #[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
    struct TestLabel {
        name: String,
    }

    fn counter_family() -> (Family<LabelImpl<TestLabel>, Counter>, LabelImpl<TestLabel>) {
        (
            Family::default(),
            LabelImpl::new(TestLabel {
                name: "test".to_owned(),
            }),
        )
    }

    /// 每次最多接受 `max` 字节；`pending` 时不接受任何写入。
    struct PartialWriter {
        max: usize,
        pending: bool,
        written: Vec<u8>,
    }

    impl AsyncRead for PartialWriter {
        fn poll_read(
            self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for PartialWriter {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.pending {
                return Poll::Pending;
            }
            let n = buf.len().min(this.max);
            this.written.extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>, _cx: &mut Context<'_>, bufs: &[std::io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            if this.pending {
                return Poll::Pending;
            }
            let mut n = 0;
            for buf in bufs {
                let take = buf.len().min(this.max - n);
                this.written.extend_from_slice(&buf[..take]);
                n += take;
                if n == this.max {
                    break;
                }
            }
            Poll::Ready(Ok(n))
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn read_counts_only_bytes_filled_by_this_call() -> io::Result<()> {
        let (client, mut server) = tokio::io::duplex(64);
        server.write_all(b"abc").await?;
        let (family, label) = counter_family();
        let mut io = Box::pin(CounterIO::new(client, family.clone(), label.clone()));

        let mut storage = [0u8; 32];
        let mut buf = ReadBuf::new(&mut storage);
        // tokio::io::copy 在写端阻塞时会带着已缓存的数据继续读，ReadBuf 不一定从空开始。
        buf.put_slice(b"already-buffered");
        poll_fn(|cx| io.as_mut().poll_read(cx, &mut buf)).await?;

        assert_eq!(buf.filled(), b"already-bufferedabc");
        assert_eq!(family.get_or_create(&label).get(), 3);
        Ok(())
    }

    #[tokio::test]
    async fn vectored_write_counts_only_accepted_bytes() -> io::Result<()> {
        let (family, label) = counter_family();
        let writer = PartialWriter {
            max: 4,
            pending: false,
            written: Vec::new(),
        };
        let mut io = Box::pin(CounterIO::new(writer, family.clone(), label.clone()));
        let bufs = [std::io::IoSlice::new(b"hello"), std::io::IoSlice::new(b"world")];

        let written = poll_fn(|cx| io.as_mut().poll_write_vectored(cx, &bufs)).await?;

        assert_eq!(written, 4);
        assert_eq!(family.get_or_create(&label).get(), 4);
        Ok(())
    }

    #[test]
    fn pending_vectored_write_is_not_counted() {
        let (family, label) = counter_family();
        let writer = PartialWriter {
            max: 4,
            pending: true,
            written: Vec::new(),
        };
        let mut io = Box::pin(CounterIO::new(writer, family.clone(), label.clone()));
        let bufs = [std::io::IoSlice::new(b"hello")];
        let waker = futures_util::task::noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(io.as_mut().poll_write_vectored(&mut cx, &bufs).is_pending());
        assert_eq!(family.get_or_create(&label).get(), 0);
    }

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
