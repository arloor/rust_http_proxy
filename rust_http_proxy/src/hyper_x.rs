use std::{pin::Pin, task::Poll};

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
