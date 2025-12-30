use std::{
    pin::Pin,
    task::Poll,
};

use http_body::Body as HttpBodyTrait;
use hyper::body::Bytes;
use prometheus_client::metrics::{counter::Counter, family::Family};

// CounterBody: 为 HTTP body stream 添加流量统计功能
pin_project_lite::pin_project! {
    /// 包装 HTTP body 并统计传输的字节数
    pub struct CounterBody<B, R>
    where
        R: prom_label::Label,
    {
        #[pin]
        inner: B,
        traffic_counter: Family<R, Counter>,
        label: R,
    }
}

impl<B, R> CounterBody<B, R>
where
    R: prom_label::Label,
{
    pub fn new(inner: B, traffic_counter: Family<R, Counter>, label: R) -> Self {
        Self {
            inner,
            traffic_counter,
            label,
        }
    }
}

impl<B, R> HttpBodyTrait for CounterBody<B, R>
where
    B: HttpBodyTrait<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    R: prom_label::Label + Clone,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>, cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.project();

        match this.inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // 如果是数据帧，统计字节数
                if let Some(data) = frame.data_ref() {
                    let bytes = data.len() as u64;
                    this.traffic_counter.get_or_create(this.label).inc_by(bytes);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

// CounterHyperIO: 为 hyper 的 IO 类型添加流量统计功能
pin_project_lite::pin_project! {
    /// enhance inner hyper IO with prometheus counter
    pub struct CounterHyperIO<T, R> {
        #[pin]
        inner: T,
        traffic_counter: Family<R, Counter>,
        label: R,
    }
}

impl<T, R> CounterHyperIO<T, R> {
    pub fn new(inner: T, traffic_counter: Family<R, Counter>, label: R) -> Self {
        Self {
            inner,
            traffic_counter,
            label,
        }
    }
}

impl<T, R> hyper::rt::Read for CounterHyperIO<T, R>
where
    T: hyper::rt::Read,
    R: prom_label::Label,
{
    fn poll_read(
        self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let this = self.project();

        // 注意：由于 hyper::rt::ReadBufCursor 的 API 设计，
        // 我们无法在不修改 trait 的情况下准确统计读取的字节数。
        // 这里只转发调用，主要统计将在 Write 端进行。
        // 如果需要准确统计双向流量，可能需要在更高层进行包装。

        this.inner.poll_read(cx, buf)
    }
}

impl<T, R> hyper::rt::Write for CounterHyperIO<T, R>
where
    T: hyper::rt::Write,
    R: prom_label::Label,
{
    fn poll_write(
        self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.project();
        match this.inner.poll_write(cx, buf) {
            Poll::Ready(result) => {
                if let Ok(size) = result {
                    this.traffic_counter.get_or_create(this.label).inc_by(size as u64);
                }
                Poll::Ready(result)
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.project();
        match this.inner.poll_write_vectored(cx, bufs) {
            Poll::Ready(result) => {
                if let Ok(size) = result {
                    this.traffic_counter.get_or_create(this.label).inc_by(size as u64);
                }
                Poll::Ready(result)
            }
            other => other,
        }
    }
}

// 实现 Connection trait，使 CounterHyperIO 可以用于 hyper client
impl<T, R> hyper_util::client::legacy::connect::Connection for CounterHyperIO<T, R>
where
    T: hyper_util::client::legacy::connect::Connection,
    R: prom_label::Label,
{
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        self.inner.connected()
    }
}
