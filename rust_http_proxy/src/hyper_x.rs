use std::{pin::Pin, task::Poll};

use http::Uri;
use http_body::Body as HttpBodyTrait;
use hyper::body::Bytes;
use prometheus_client::metrics::{counter::Counter, family::Family};
use tower::Service;

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

// CounterConnector: 装饰器，用于包装 Connector 并添加流量统计
#[derive(Clone)]
pub struct CounterConnector<C, R, F>
where
    R: prom_label::Label,
    F: Fn(&Uri) -> R,
{
    inner: C,
    traffic_counter: Family<R, Counter>,
    label_fn: F,
}

impl<C, R, F> CounterConnector<C, R, F>
where
    R: prom_label::Label,
    F: Fn(&Uri) -> R,
{
    pub fn new(inner: C, traffic_counter: Family<R, Counter>, label_fn: F) -> Self {
        Self {
            inner,
            traffic_counter,
            label_fn,
        }
    }
}

impl<C, R, F> Service<Uri> for CounterConnector<C, R, F>
where
    C: Service<Uri>,
    C::Response: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
    C::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    C::Future: Send + 'static,
    R: prom_label::Label + Clone + Send + Sync + 'static,
    F: Fn(&Uri) -> R + Clone + Send + 'static,
{
    type Response = CounterHyperIO<C::Response, R>;
    type Error = C::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let fut = self.inner.call(uri.clone());
        let traffic_counter = self.traffic_counter.clone();
        let label = (self.label_fn)(&uri);

        Box::pin(async move {
            let io = fut.await?;
            Ok(CounterHyperIO::new(io, traffic_counter, label))
        })
    }
}

#[cfg(test)]
mod test {
    use prometheus_client::encoding::EncodeLabelSet;

    use super::*;

    #[test]
    fn test_counter_hyper_io_creation() {
        use hyper_util::rt::TokioIo;
        use prometheus_client::metrics::{counter::Counter, family::Family};
        use tokio::net::TcpStream;

        // 创建一个简单的 label
        #[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
        struct TestLabel {
            name: String,
        }
        impl prom_label::Label for TestLabel {}

        let traffic_counter: Family<TestLabel, Counter> = Family::default();
        let label = TestLabel {
            name: "test".to_string(),
        };

        // 注意：我们不能直接创建 TcpStream 用于测试，
        // 但可以验证类型系统是正确的
        // 这里只是一个编译时检查
        let _check_types = |stream: TokioIo<TcpStream>| {
            let _counter_io = CounterHyperIO::new(stream, traffic_counter.clone(), label.clone());
        };
    }

    #[test]
    fn test_aa() {
        let host = "www.arloor.com";
        assert_eq!(host.split(':').next().unwrap_or("").to_string(), host);
    }
}
