use std::io::{self, ErrorKind, Write as _};
use std::sync::Arc;

use axum::extract::Request;
use http::header::{CONTENT_ENCODING, CONTENT_TYPE};
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::Response;
use hyper::body::{Bytes, Incoming};

use crate::mitm_manager::{BodyDirection, MitmManager};

pub(super) fn map_mitm_request_body(
    request: Request<Incoming>, manager: Arc<MitmManager>, record_id: Option<String>,
) -> Request<BoxBody<Bytes, io::Error>> {
    let mode = body_capture_mode(request.headers());
    request.map(|body| {
        let body = body
            .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))
            .boxed();
        match record_id {
            Some(id) => MitmCaptureBody::new(body, manager, id, BodyDirection::Request, mode).boxed(),
            None => body,
        }
    })
}

pub(super) async fn capture_and_drain_mitm_request_body(
    body: &mut Incoming, headers: &http::HeaderMap, manager: Arc<MitmManager>, record_id: Option<String>,
) -> io::Result<()> {
    let Some(id) = record_id else {
        while let Some(frame) = body.frame().await {
            frame.map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
        }
        return Ok(());
    };
    let mut captured = 0usize;
    let mut total = 0usize;
    let mut truncated = false;
    let mut mode = body_capture_mode(headers);
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
        if let Some(data) = frame.data_ref() {
            match &mut mode {
                CaptureMode::Plaintext => capture_bytes(
                    &manager,
                    &id,
                    BodyDirection::Request,
                    data,
                    &mut captured,
                    &mut total,
                    &mut truncated,
                ),
                CaptureMode::Decoded(decoder) => match decoder.decode_chunk(data) {
                    Ok(decoded) => capture_bytes(
                        &manager,
                        &id,
                        BodyDirection::Request,
                        &decoded,
                        &mut captured,
                        &mut total,
                        &mut truncated,
                    ),
                    Err(error) => mode = CaptureMode::Skip(format!("content decode failed: {error}")),
                },
                CaptureMode::Skip(_) => {}
            }
        }
    }
    let note = match &mut mode {
        CaptureMode::Decoded(decoder) => match decoder.finish() {
            Ok(decoded) => {
                capture_bytes(
                    &manager,
                    &id,
                    BodyDirection::Request,
                    &decoded,
                    &mut captured,
                    &mut total,
                    &mut truncated,
                );
                truncated.then(|| "body truncated at configured limit".to_owned())
            }
            Err(error) => Some(format!("content decode finish failed: {error}")),
        },
        CaptureMode::Skip(reason) => Some(reason.clone()),
        CaptureMode::Plaintext => truncated.then(|| "body truncated at configured limit".to_owned()),
    };
    manager.finish_body(&id, BodyDirection::Request, note);
    Ok(())
}

pub(super) fn map_mitm_response_body(
    response: Response<Incoming>, manager: Arc<MitmManager>, record_id: Option<String>,
) -> Response<BoxBody<Bytes, io::Error>> {
    let mode = body_capture_mode(response.headers());
    response.map(|body| {
        let body = body
            .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))
            .boxed();
        match record_id {
            Some(id) => MitmCaptureBody::new(body, manager, id, BodyDirection::Response, mode).boxed(),
            None => body,
        }
    })
}

pub(super) fn map_boxed_mitm_response_body(
    response: Response<BoxBody<Bytes, io::Error>>, manager: Arc<MitmManager>, record_id: Option<String>,
) -> Response<BoxBody<Bytes, io::Error>> {
    let mode = body_capture_mode(response.headers());
    response.map(|body| match record_id {
        Some(id) => MitmCaptureBody::new(body, manager, id, BodyDirection::Response, mode).boxed(),
        None => body,
    })
}

enum CaptureMode {
    Plaintext,
    Decoded(DecoderPipeline),
    Skip(String),
}

fn body_capture_mode(headers: &http::HeaderMap) -> CaptureMode {
    let content_encoding = non_identity_content_encodings(headers);
    let encoding_mode = if content_encoding.is_empty() {
        CaptureMode::Plaintext
    } else {
        match DecoderPipeline::new(&content_encoding) {
            Ok(decoder) => CaptureMode::Decoded(decoder),
            Err(reason) => return CaptureMode::Skip(reason),
        }
    };

    let Some(content_type) = headers.get(CONTENT_TYPE) else {
        return encoding_mode;
    };
    let Ok(content_type) = content_type.to_str() else {
        return encoding_mode;
    };
    let media_type = content_type
        .split_once(';')
        .map_or(content_type, |(media_type, _)| media_type)
        .trim()
        .to_ascii_lowercase();
    if is_human_readable_media_type(&media_type) {
        encoding_mode
    } else {
        CaptureMode::Skip(format!("non-text content-type: {media_type}"))
    }
}

fn non_identity_content_encodings(headers: &http::HeaderMap) -> Vec<String> {
    headers
        .get_all(CONTENT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|encoding| !encoding.is_empty() && !encoding.eq_ignore_ascii_case("identity"))
                .map(str::to_owned)
        })
        .collect()
}

fn is_human_readable_media_type(media_type: &str) -> bool {
    media_type.starts_with("text/")
        || matches!(
            media_type,
            "application/ecmascript"
                | "application/graphql"
                | "application/javascript"
                | "application/json"
                | "application/x-javascript"
                | "application/x-www-form-urlencoded"
                | "application/xhtml+xml"
                | "application/xml"
                | "image/svg+xml"
        )
        || media_type.ends_with("+json")
        || media_type.ends_with("+xml")
}

struct DecoderPipeline {
    stages: Vec<DecoderStage>,
}

impl DecoderPipeline {
    fn new(content_encodings: &[String]) -> Result<Self, String> {
        let stages = content_encodings
            .iter()
            .rev()
            .map(|encoding| DecoderStage::new(encoding))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { stages })
    }

    fn decode_chunk(&mut self, compressed: &[u8]) -> io::Result<Bytes> {
        let mut output = compressed.to_vec();
        for stage in &mut self.stages {
            output = stage.decode_chunk(&output)?;
        }
        Ok(Bytes::from(output))
    }

    fn finish(&mut self) -> io::Result<Bytes> {
        let mut decoded = Vec::new();
        for index in 0..self.stages.len() {
            let (finished, remaining) = self.stages.split_at_mut(index + 1);
            let mut output = finished[index].finish()?;
            for stage in remaining {
                output = stage.decode_chunk(&output)?;
            }
            decoded.extend_from_slice(&output);
        }
        Ok(Bytes::from(decoded))
    }
}

enum DecoderStage {
    Gzip(flate2::write::GzDecoder<Vec<u8>>),
    Deflate(flate2::write::ZlibDecoder<Vec<u8>>),
    Brotli(Box<brotli::DecompressorWriter<Vec<u8>>>),
    Zstd(zstd::stream::write::Decoder<'static, Vec<u8>>),
}

impl DecoderStage {
    fn new(encoding: &str) -> Result<Self, String> {
        match encoding.to_ascii_lowercase().as_str() {
            "gzip" | "x-gzip" => Ok(Self::Gzip(flate2::write::GzDecoder::new(Vec::new()))),
            "deflate" => Ok(Self::Deflate(flate2::write::ZlibDecoder::new(Vec::new()))),
            "br" => Ok(Self::Brotli(Box::new(brotli::DecompressorWriter::new(Vec::new(), 4096)))),
            "zstd" => zstd::stream::write::Decoder::new(Vec::new())
                .map(Self::Zstd)
                .map_err(|error| format!("failed to initialize zstd decoder: {error}")),
            _ => Err(format!("unsupported content-encoding: {encoding}")),
        }
    }

    fn decode_chunk(&mut self, compressed: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::Gzip(decoder) => {
                decoder.write_all(compressed)?;
                Ok(std::mem::take(decoder.get_mut()))
            }
            Self::Deflate(decoder) => {
                decoder.write_all(compressed)?;
                Ok(std::mem::take(decoder.get_mut()))
            }
            Self::Brotli(decoder) => {
                decoder.write_all(compressed)?;
                Ok(std::mem::take(decoder.get_mut()))
            }
            Self::Zstd(decoder) => {
                decoder.write_all(compressed)?;
                Ok(std::mem::take(decoder.get_mut()))
            }
        }
    }

    fn finish(&mut self) -> io::Result<Vec<u8>> {
        match self {
            Self::Gzip(decoder) => {
                decoder.try_finish()?;
                Ok(std::mem::take(decoder.get_mut()))
            }
            Self::Deflate(decoder) => {
                decoder.try_finish()?;
                Ok(std::mem::take(decoder.get_mut()))
            }
            Self::Brotli(decoder) => {
                decoder.close()?;
                Ok(std::mem::take(decoder.get_mut()))
            }
            Self::Zstd(decoder) => {
                decoder.flush()?;
                Ok(std::mem::take(decoder.get_mut()))
            }
        }
    }
}

pin_project_lite::pin_project! {
    struct MitmCaptureBody {
        #[pin]
        inner: BoxBody<Bytes, io::Error>,
        manager: Arc<MitmManager>,
        record_id: String,
        direction: BodyDirection,
        mode: CaptureMode,
        captured_bytes: usize,
        total_bytes: usize,
        truncated: bool,
        stopped: bool,
        completed: bool,
    }

    // 客户端提前断开或连接被回收时，body 不会 poll 到结束，直接 Drop。
    // 在此收尾，避免记录永远停留在 capturing 状态。
    impl PinnedDrop for MitmCaptureBody {
        fn drop(this: Pin<&mut Self>) {
            let this = this.project();
            if *this.completed {
                return;
            }
            *this.completed = true;
            if !*this.stopped {
                this.manager.finish_body(
                    this.record_id,
                    *this.direction,
                    Some("connection closed before body stream ended".to_owned()),
                );
            }
            if matches!(*this.direction, BodyDirection::Response) {
                this.manager.finish_record(this.record_id, "interrupted");
            }
        }
    }
}

impl MitmCaptureBody {
    fn new(
        inner: BoxBody<Bytes, io::Error>, manager: Arc<MitmManager>, record_id: String, direction: BodyDirection,
        mode: CaptureMode,
    ) -> Self {
        Self {
            inner,
            manager,
            record_id,
            direction,
            mode,
            captured_bytes: 0,
            total_bytes: 0,
            truncated: false,
            stopped: false,
            completed: false,
        }
    }
}

impl http_body::Body for MitmCaptureBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>, context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        match this.inner.as_mut().poll_frame(context) {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                if !this.manager.capture_enabled() {
                    if !*this.stopped {
                        *this.stopped = true;
                        this.manager.finish_body(
                            this.record_id,
                            *this.direction,
                            Some("capture stopped by runtime setting".to_owned()),
                        );
                    }
                } else if let Some(data) = frame.data_ref() {
                    match this.mode {
                        CaptureMode::Plaintext => capture_bytes(
                            this.manager,
                            this.record_id,
                            *this.direction,
                            data,
                            this.captured_bytes,
                            this.total_bytes,
                            this.truncated,
                        ),
                        CaptureMode::Decoded(decoder) => match decoder.decode_chunk(data) {
                            Ok(decoded) => capture_bytes(
                                this.manager,
                                this.record_id,
                                *this.direction,
                                &decoded,
                                this.captured_bytes,
                                this.total_bytes,
                                this.truncated,
                            ),
                            Err(error) => {
                                *this.mode = CaptureMode::Skip(format!("content decode failed: {error}"));
                            }
                        },
                        CaptureMode::Skip(_) => {}
                    }
                }
                if this.inner.is_end_stream() {
                    finish_capture(
                        this.manager,
                        this.record_id,
                        *this.direction,
                        this.mode,
                        this.captured_bytes,
                        this.total_bytes,
                        this.truncated,
                        this.stopped,
                        this.completed,
                    );
                }
                std::task::Poll::Ready(Some(Ok(frame)))
            }
            std::task::Poll::Ready(Some(Err(error))) => {
                this.manager.record_error(this.record_id, error.to_string());
                std::task::Poll::Ready(Some(Err(error)))
            }
            std::task::Poll::Ready(None) => {
                finish_capture(
                    this.manager,
                    this.record_id,
                    *this.direction,
                    this.mode,
                    this.captured_bytes,
                    this.total_bytes,
                    this.truncated,
                    this.stopped,
                    this.completed,
                );
                std::task::Poll::Ready(None)
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.completed
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

#[allow(clippy::too_many_arguments)]
fn finish_capture(
    manager: &MitmManager, record_id: &str, direction: BodyDirection, mode: &mut CaptureMode,
    captured_bytes: &mut usize, total_bytes: &mut usize, truncated: &mut bool, stopped: &mut bool,
    completed: &mut bool,
) {
    if *completed {
        return;
    }
    *completed = true;
    let mut note = None;
    if !*stopped {
        match mode {
            CaptureMode::Decoded(decoder) => match decoder.finish() {
                Ok(decoded) => {
                    capture_bytes(manager, record_id, direction, &decoded, captured_bytes, total_bytes, truncated)
                }
                Err(error) => note = Some(format!("content decode finish failed: {error}")),
            },
            CaptureMode::Skip(reason) => note = Some(reason.clone()),
            CaptureMode::Plaintext => {}
        }
        if *truncated {
            note = Some("body truncated at configured limit".to_owned());
        }
        manager.finish_body(record_id, direction, note);
    }
    if matches!(direction, BodyDirection::Response) {
        manager.finish_record(record_id, "complete");
    }
}

fn capture_bytes(
    manager: &MitmManager, record_id: &str, direction: BodyDirection, data: &[u8], captured: &mut usize,
    total: &mut usize, truncated: &mut bool,
) {
    *total = total.saturating_add(data.len());
    let limit = manager.body_limit_bytes();
    let remaining = limit.saturating_sub(*captured);
    let captured_now = remaining.min(data.len());
    if captured_now > 0 {
        *captured += captured_now;
        *truncated |= captured_now < data.len();
        manager.body_chunk(record_id, direction, &data[..captured_now], *total, *truncated);
    } else if !data.is_empty() {
        *truncated = true;
        manager.body_chunk(record_id, direction, &[], *total, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::{GzEncoder, ZlibEncoder};
    use http::{HeaderMap, HeaderValue};
    use std::io::{Cursor, Write};

    const PLAINTEXT: &[u8] = br#"{"message":"compressed MITM plaintext","ok":true}"#;

    // 客户端提前断开导致 body 未读完就被 Drop 时，记录应收尾为 interrupted 而不是永远 capturing
    #[tokio::test]
    async fn dropped_body_marks_record_interrupted() -> Result<(), crate::DynError> {
        let path = std::env::temp_dir().join(format!(
            "rust_http_proxy_mitm_capture_drop_{}_{:x}.sqlite3",
            std::process::id(),
            rand::random::<u64>()
        ));
        let manager = crate::mitm_manager::MitmManager::open(
            path.clone(),
            true,
            &["example.com".to_owned()],
            true,
            10_000,
            65_536,
        )?;
        let request_headers = HeaderMap::new();
        let id = manager
            .begin_record(crate::mitm_manager::RecordMetadata {
                client_ip: "127.0.0.1".to_owned(),
                proxy_username: "tester".to_owned(),
                authority: "example.com:443".to_owned(),
                host: "example.com".to_owned(),
                path: "/".to_owned(),
                query: None,
                method: "GET".to_owned(),
                request_version: http::Version::HTTP_2,
                request_headers: &request_headers,
            })
            .ok_or("capture unexpectedly disabled")?;
        let body = http_body_util::Full::new(Bytes::from_static(b"never polled"))
            .map_err(|never: std::convert::Infallible| match never {})
            .boxed();
        let wrapped =
            MitmCaptureBody::new(body, manager.clone(), id.clone(), BodyDirection::Response, CaptureMode::Plaintext);
        drop(wrapped);
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        let detail = manager.get_record(id).await?.ok_or("record not found")?;
        assert_eq!(detail.summary.capture_state, "interrupted");
        drop(manager);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    // HTTP/1.1 下游写满 Content-Length 后可能不再 poll body：消费完最后一帧时 is_end_stream
    // 已经完成收尾，随后即使直接 Drop 也必须保持 complete，不能误标为 interrupted
    #[tokio::test]
    async fn content_length_fulfilled_body_stays_complete_after_drop() -> Result<(), crate::DynError> {
        let path = std::env::temp_dir().join(format!(
            "rust_http_proxy_mitm_capture_exact_len_{}_{:x}.sqlite3",
            std::process::id(),
            rand::random::<u64>()
        ));
        let manager = crate::mitm_manager::MitmManager::open(
            path.clone(),
            true,
            &["example.com".to_owned()],
            true,
            10_000,
            65_536,
        )?;
        let request_headers = HeaderMap::new();
        let id = manager
            .begin_record(crate::mitm_manager::RecordMetadata {
                client_ip: "127.0.0.1".to_owned(),
                proxy_username: "tester".to_owned(),
                authority: "example.com:443".to_owned(),
                host: "example.com".to_owned(),
                path: "/".to_owned(),
                query: None,
                method: "GET".to_owned(),
                request_version: http::Version::HTTP_2,
                request_headers: &request_headers,
            })
            .ok_or("capture unexpectedly disabled")?;
        let body = http_body_util::Full::new(Bytes::from_static(b"exact length"))
            .map_err(|never: std::convert::Infallible| match never {})
            .boxed();
        let mut wrapped =
            MitmCaptureBody::new(body, manager.clone(), id.clone(), BodyDirection::Response, CaptureMode::Plaintext);
        // 只 poll 一次拿到全部数据，模拟下游消费完 Content-Length 后不再 poll
        let first = wrapped.frame().await;
        assert!(matches!(first, Some(Ok(_))));
        drop(wrapped);
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        let detail = manager.get_record(id).await?.ok_or("record not found")?;
        assert_eq!(detail.summary.capture_state, "complete");
        drop(manager);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn response_mode_skips_binary() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/png"));
        assert!(matches!(body_capture_mode(&headers), CaptureMode::Skip(_)));
    }

    #[test]
    fn response_mode_accepts_supported_content_encodings() -> Result<(), crate::DynError> {
        for encoding in ["gzip", "x-gzip", "deflate", "br", "zstd"] {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            headers.insert(CONTENT_ENCODING, HeaderValue::from_str(encoding)?);
            assert!(matches!(body_capture_mode(&headers), CaptureMode::Decoded(_)));
        }
        Ok(())
    }

    #[test]
    fn decodes_gzip_deflate_brotli_and_zstd_streams() -> Result<(), crate::DynError> {
        assert_decodes(&["gzip"], gzip(PLAINTEXT)?)?;
        assert_decodes(&["deflate"], deflate(PLAINTEXT)?)?;
        assert_decodes(&["br"], brotli(PLAINTEXT)?)?;
        assert_decodes(&["zstd"], zstd::stream::encode_all(Cursor::new(PLAINTEXT), 3)?)?;
        Ok(())
    }

    #[test]
    fn decodes_multiple_content_encodings_in_reverse_order() -> Result<(), crate::DynError> {
        let gzip_then_brotli = brotli(&gzip(PLAINTEXT)?)?;
        assert_decodes(&["gzip", "br"], gzip_then_brotli)?;
        Ok(())
    }

    #[test]
    fn unsupported_content_encoding_is_skipped() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("compress"));
        assert!(matches!(body_capture_mode(&headers), CaptureMode::Skip(_)));
    }

    fn assert_decodes(encodings: &[&str], compressed: Vec<u8>) -> io::Result<()> {
        let encodings = encodings
            .iter()
            .map(|encoding| (*encoding).to_owned())
            .collect::<Vec<_>>();
        let mut pipeline = DecoderPipeline::new(&encodings).map_err(io::Error::other)?;
        let mut decoded = Vec::new();
        for chunk in compressed.chunks(7) {
            decoded.extend_from_slice(&pipeline.decode_chunk(chunk)?);
        }
        decoded.extend_from_slice(&pipeline.finish()?);
        assert_eq!(decoded, PLAINTEXT);
        Ok(())
    }

    fn gzip(input: &[u8]) -> io::Result<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input)?;
        encoder.finish()
    }

    fn deflate(input: &[u8]) -> io::Result<Vec<u8>> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input)?;
        encoder.finish()
    }

    fn brotli(input: &[u8]) -> io::Result<Vec<u8>> {
        let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 5, 22);
        encoder.write_all(input)?;
        Ok(encoder.into_inner())
    }
}
