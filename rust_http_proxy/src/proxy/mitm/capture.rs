use std::io::{self, ErrorKind, Write as _};
use std::pin::Pin;
use std::sync::Arc;

use axum::extract::Request;
use base64::Engine as _;
use http::header::{CONTENT_ENCODING, CONTENT_TYPE};
use http_body::Body as _;
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::Response;
use hyper::body::{Bytes, Incoming};

use crate::mitm_manager::{BodyDirection, MitmManager};
use crate::proxy::empty_body;

const CONNECTION_CLOSED_BEFORE_BODY_ENDED: &str = "connection closed before body stream ended";

const CONNECTION_CLOSED_CLIENT_MAY_NOT_READ: &str =
    "connection closed before body stream ended; possibly because the client did not read the body";

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
            capture_data(
                &manager,
                &id,
                BodyDirection::Request,
                &mut mode,
                data,
                &mut captured,
                &mut total,
                &mut truncated,
            );
        }
    }
    let mut image_media_type = None;
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
        CaptureMode::Image(image) => {
            let (note, media_type) = finish_image_capture(
                &manager,
                &id,
                BodyDirection::Request,
                image,
                &mut captured,
                &mut total,
                &mut truncated,
            );
            image_media_type = media_type;
            note
        }
        CaptureMode::Skip(reason) => Some(reason.clone()),
        CaptureMode::Plaintext => truncated.then(|| "body truncated at configured limit".to_owned()),
    };
    manager.finish_body(&id, BodyDirection::Request, note, image_media_type);
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
    Image(ImageCapture),
    Skip(String),
}

// 图片 body 不按文本抓取：先按原始字节缓冲（遵守 body 上限），
// 完整收完后 base64 编码存入 body 列，media type 记入 *_body_image 列供 UI 预览。
struct ImageCapture {
    media_type: String,
    decoder: Option<DecoderPipeline>,
    buffer: Vec<u8>,
}

impl ImageCapture {
    fn decode(&mut self, data: &[u8]) -> io::Result<Bytes> {
        match &mut self.decoder {
            Some(decoder) => decoder.decode_chunk(data),
            None => Ok(Bytes::copy_from_slice(data)),
        }
    }

    fn finish(&mut self) -> io::Result<Bytes> {
        match &mut self.decoder {
            Some(decoder) => decoder.finish(),
            None => Ok(Bytes::new()),
        }
    }

    fn push(&mut self, data: &[u8], limit: usize, captured: &mut usize, total: &mut usize, truncated: &mut bool) {
        *total = total.saturating_add(data.len());
        let remaining = limit.saturating_sub(*captured);
        let take = remaining.min(data.len());
        if take > 0 {
            self.buffer.extend_from_slice(&data[..take]);
            *captured += take;
        }
        *truncated |= take < data.len();
    }
}

fn body_capture_mode(headers: &http::HeaderMap) -> CaptureMode {
    let content_encoding = non_identity_content_encodings(headers);
    let decoder = if content_encoding.is_empty() {
        None
    } else {
        match DecoderPipeline::new(&content_encoding) {
            Ok(decoder) => Some(decoder),
            Err(reason) => return CaptureMode::Skip(reason),
        }
    };

    let Some(content_type) = headers.get(CONTENT_TYPE) else {
        return decoder.map_or(CaptureMode::Plaintext, CaptureMode::Decoded);
    };
    let Ok(content_type) = content_type.to_str() else {
        return decoder.map_or(CaptureMode::Plaintext, CaptureMode::Decoded);
    };
    let media_type = content_type
        .split_once(';')
        .map_or(content_type, |(media_type, _)| media_type)
        .trim()
        .to_ascii_lowercase();
    if is_human_readable_media_type(&media_type) {
        decoder.map_or(CaptureMode::Plaintext, CaptureMode::Decoded)
    } else if is_previewable_image_media_type(&media_type) {
        CaptureMode::Image(ImageCapture {
            media_type,
            decoder,
            buffer: Vec::new(),
        })
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

fn is_previewable_image_media_type(media_type: &str) -> bool {
    // svg 是文本，走 is_human_readable_media_type 按文本抓取
    media_type.starts_with("image/") && media_type != "image/svg+xml"
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

    // 下游写完头后可能不再 poll 空 body（204/304、Content-Length: 0、H2 END_STREAM）。
    // 客户端提前断开时 body 也不会 poll 到结束。两种情况都走 Drop，必须区分：
    // 已经结束的空流记 complete。未读完的响应则后台继续从上游 drain 以便 dump body，
    // dump 成功后记 complete，并注明可能是客户端未读取 body。
    // 没有 Content-Length（chunked / HTTP2 / close-delimited）时读到流结束，body 不超限就完整落库。
    impl PinnedDrop for MitmCaptureBody {
        fn drop(this: Pin<&mut Self>) {
            let this = this.project();
            if *this.completed {
                return;
            }
            if stream_already_complete(&this.inner) {
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
                return;
            }
            if matches!(*this.direction, BodyDirection::Response)
                && !*this.stopped
                && !matches!(*this.mode, CaptureMode::Skip(_))
                && spawn_interrupted_response_drain(
                    this.inner,
                    this.manager,
                    this.record_id,
                    this.mode,
                    this.captured_bytes,
                    this.total_bytes,
                    this.truncated,
                    this.stopped,
                    this.completed,
                )
            {
                return;
            }
            *this.completed = true;
            if !*this.stopped {
                this.manager.finish_body(
                    this.record_id,
                    *this.direction,
                    Some(CONNECTION_CLOSED_BEFORE_BODY_ENDED.to_owned()),
                    None,
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
                            None,
                        );
                    }
                } else if let Some(data) = frame.data_ref() {
                    capture_data(
                        this.manager,
                        this.record_id,
                        *this.direction,
                        this.mode,
                        data,
                        this.captured_bytes,
                        this.total_bytes,
                        this.truncated,
                    );
                }
                // HTTP/1 writers can stop polling once the body's exact size hint reaches zero.
                // In that case the wrapped body may never be polled again to return `None`, and
                // some implementations do not report `is_end_stream()` until that terminal poll.
                // Finish while processing the last data frame so the record does not remain in
                // `capturing` after the complete response has already been forwarded.
                if stream_already_complete(&this.inner) {
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
        // Capture completion is bookkeeping only. The wrapped transport must
        // remain authoritative so an exact-length H2 body can still deliver
        // trailing headers after its final data frame.
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

fn stream_already_complete(inner: &BoxBody<Bytes, io::Error>) -> bool {
    inner.is_end_stream() || inner.size_hint().exact() == Some(0)
}

#[allow(clippy::too_many_arguments)]
fn capture_data(
    manager: &MitmManager, record_id: &str, direction: BodyDirection, mode: &mut CaptureMode, data: &[u8],
    captured_bytes: &mut usize, total_bytes: &mut usize, truncated: &mut bool,
) {
    match mode {
        CaptureMode::Plaintext => {
            capture_bytes(manager, record_id, direction, data, captured_bytes, total_bytes, truncated)
        }
        CaptureMode::Decoded(decoder) => match decoder.decode_chunk(data) {
            Ok(decoded) => {
                capture_bytes(manager, record_id, direction, &decoded, captured_bytes, total_bytes, truncated)
            }
            Err(error) => *mode = CaptureMode::Skip(format!("content decode failed: {error}")),
        },
        CaptureMode::Image(image) => match image.decode(data) {
            Ok(decoded) => image.push(&decoded, manager.body_limit_bytes(), captured_bytes, total_bytes, truncated),
            Err(error) => *mode = CaptureMode::Skip(format!("content decode failed: {error}")),
        },
        CaptureMode::Skip(_) => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_interrupted_response_drain(
    inner: Pin<&mut BoxBody<Bytes, io::Error>>, manager: &Arc<MitmManager>, record_id: &str, mode: &mut CaptureMode,
    captured_bytes: &mut usize, total_bytes: &mut usize, truncated: &mut bool, stopped: &mut bool,
    completed: &mut bool,
) -> bool {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return false;
    };
    *completed = true;
    let inner = std::mem::replace(Pin::get_mut(inner), empty_body());
    let manager = Arc::clone(manager);
    let record_id = record_id.to_owned();
    let mode = std::mem::replace(mode, CaptureMode::Skip(String::new()));
    let captured_bytes = *captured_bytes;
    let total_bytes = *total_bytes;
    let truncated = *truncated;
    let stopped = *stopped;
    drop(handle.spawn(drain_interrupted_response_body(
        inner,
        manager,
        record_id,
        mode,
        captured_bytes,
        total_bytes,
        truncated,
        stopped,
    )));
    true
}

#[allow(clippy::too_many_arguments)]
async fn drain_interrupted_response_body(
    mut inner: BoxBody<Bytes, io::Error>, manager: Arc<MitmManager>, record_id: String, mut mode: CaptureMode,
    mut captured_bytes: usize, mut total_bytes: usize, mut truncated: bool, mut stopped: bool,
) {
    let mut stream_error = false;
    // 未知长度只能靠流结束判断；超限后仍读完上游，避免截断解码器/连接，只是不再追加落库。
    loop {
        match inner.frame().await {
            Some(Ok(frame)) => {
                if !manager.capture_enabled() {
                    if !stopped {
                        stopped = true;
                        manager.finish_body(
                            &record_id,
                            BodyDirection::Response,
                            Some("capture stopped by runtime setting".to_owned()),
                            None,
                        );
                    }
                    break;
                }
                if let Some(data) = frame.data_ref() {
                    if truncated {
                        continue;
                    }
                    capture_data(
                        &manager,
                        &record_id,
                        BodyDirection::Response,
                        &mut mode,
                        data,
                        &mut captured_bytes,
                        &mut total_bytes,
                        &mut truncated,
                    );
                }
            }
            Some(Err(_)) => {
                stream_error = true;
                break;
            }
            None => break,
        }
    }
    finish_interrupted_response_capture(
        &manager,
        &record_id,
        &mut mode,
        &mut captured_bytes,
        &mut total_bytes,
        &mut truncated,
        stopped,
        stream_error,
    );
}

#[allow(clippy::too_many_arguments)]
fn finish_interrupted_response_capture(
    manager: &MitmManager, record_id: &str, mode: &mut CaptureMode, captured_bytes: &mut usize,
    total_bytes: &mut usize, truncated: &mut bool, stopped: bool, stream_error: bool,
) {
    if !stopped {
        let mut image_media_type = None;
        match mode {
            CaptureMode::Decoded(decoder) => {
                if let Ok(decoded) = decoder.finish() {
                    capture_bytes(
                        manager,
                        record_id,
                        BodyDirection::Response,
                        &decoded,
                        captured_bytes,
                        total_bytes,
                        truncated,
                    );
                }
            }
            CaptureMode::Image(image) => {
                let (_note, media_type) = finish_image_capture(
                    manager,
                    record_id,
                    BodyDirection::Response,
                    image,
                    captured_bytes,
                    total_bytes,
                    truncated,
                );
                image_media_type = media_type;
            }
            CaptureMode::Skip(_) | CaptureMode::Plaintext => {}
        }
        manager.finish_body(
            record_id,
            BodyDirection::Response,
            Some(CONNECTION_CLOSED_CLIENT_MAY_NOT_READ.to_owned()),
            image_media_type,
        );
    }
    manager.finish_record(
        record_id,
        if stopped || stream_error {
            "interrupted"
        } else {
            "complete"
        },
    );
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
    let mut image_media_type = None;
    if !*stopped {
        match mode {
            CaptureMode::Decoded(decoder) => match decoder.finish() {
                Ok(decoded) => {
                    capture_bytes(manager, record_id, direction, &decoded, captured_bytes, total_bytes, truncated)
                }
                Err(error) => note = Some(format!("content decode finish failed: {error}")),
            },
            CaptureMode::Image(image) => {
                let (image_note, media_type) =
                    finish_image_capture(manager, record_id, direction, image, captured_bytes, total_bytes, truncated);
                note = image_note;
                image_media_type = media_type;
            }
            CaptureMode::Skip(reason) => note = Some(reason.clone()),
            CaptureMode::Plaintext => {}
        }
        if *truncated {
            note = Some("body truncated at configured limit".to_owned());
        }
        manager.finish_body(record_id, direction, note, image_media_type);
    }
    if matches!(direction, BodyDirection::Response) {
        manager.finish_record(record_id, "complete");
    }
}

// 图片抓取收尾：截断时只记字节数不存内容；完整时 base64 落库并返回 media type
#[allow(clippy::too_many_arguments)]
fn finish_image_capture(
    manager: &MitmManager, record_id: &str, direction: BodyDirection, image: &mut ImageCapture, captured: &mut usize,
    total: &mut usize, truncated: &mut bool,
) -> (Option<String>, Option<String>) {
    let mut note = None;
    let mut usable = true;
    match image.finish() {
        Ok(decoded) => image.push(&decoded, manager.body_limit_bytes(), captured, total, truncated),
        Err(error) => {
            usable = false;
            note = Some(format!("content decode finish failed: {error}"));
        }
    }
    let mut media_type = None;
    if *truncated {
        manager.body_chunk(record_id, direction, &[], *total, true);
        note = Some("body truncated at configured limit".to_owned());
    } else if usable && !image.buffer.is_empty() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(&image.buffer);
        manager.body_chunk(record_id, direction, encoded.as_bytes(), *total, false);
        media_type = Some(image.media_type.clone());
    }
    (note, media_type)
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
    use http_body::{Frame, SizeHint};
    use std::io::{Cursor, Write};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    const PLAINTEXT: &[u8] = br#"{"message":"compressed MITM plaintext","ok":true}"#;

    // 空响应（204 / Content-Length: 0 / H2 END_STREAM）下游常常一次都不 poll，Drop 必须记 complete
    #[tokio::test]
    async fn unpolled_empty_body_marks_record_complete() -> Result<(), crate::DynError> {
        let (manager, path, id) = open_capture_record("empty")?;
        let body = http_body_util::Empty::<Bytes>::new()
            .map_err(|never: std::convert::Infallible| match never {})
            .boxed();
        let wrapped =
            MitmCaptureBody::new(body, manager.clone(), id.clone(), BodyDirection::Response, CaptureMode::Plaintext);
        drop(wrapped);
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        let detail = manager.get_record(id).await?.ok_or("record not found")?;
        assert_eq!(detail.summary.capture_state, "complete");
        assert_eq!(detail.response_body_note, None);
        drop(manager);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    // H2 204 常不带 content-length：is_end_stream 为真，但 size_hint 不是 exact(0)
    #[tokio::test]
    async fn unpolled_end_stream_without_exact_size_marks_record_complete() -> Result<(), crate::DynError> {
        let (manager, path, id) = open_capture_record("end_stream")?;
        let wrapped = MitmCaptureBody::new(
            EndedStreamWithoutSizeHint.boxed(),
            manager.clone(),
            id.clone(),
            BodyDirection::Response,
            CaptureMode::Plaintext,
        );
        drop(wrapped);
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        let detail = manager.get_record(id).await?.ok_or("record not found")?;
        assert_eq!(detail.summary.capture_state, "complete");
        drop(manager);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    // 客户端提前断开导致 body 未读完就被 Drop 时，后台继续 dump 上游 body，
    // dump 成功后记 complete，并注明可能是客户端未读取 body。
    #[tokio::test]
    async fn dropped_body_dumps_content_and_marks_complete() -> Result<(), crate::DynError> {
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
                client_port: 54321,
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
        assert_eq!(detail.summary.capture_state, "complete");
        assert_eq!(detail.response_body, "never polled");
        assert_eq!(detail.response_body_note.as_deref(), Some(CONNECTION_CLOSED_CLIENT_MAY_NOT_READ));
        drop(manager);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[tokio::test]
    async fn dropped_gzip_response_body_is_decoded_and_marked_complete() -> Result<(), crate::DynError> {
        let (manager, path, id) = open_capture_record("drop_gzip")?;
        let compressed = gzip(PLAINTEXT)?;
        let body = http_body_util::Full::new(Bytes::from(compressed))
            .map_err(|never: std::convert::Infallible| match never {})
            .boxed();
        let decoder = DecoderPipeline::new(&["gzip".to_owned()]).map_err(io::Error::other)?;
        let wrapped = MitmCaptureBody::new(
            body,
            manager.clone(),
            id.clone(),
            BodyDirection::Response,
            CaptureMode::Decoded(decoder),
        );
        drop(wrapped);
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        let detail = manager.get_record(id).await?.ok_or("record not found")?;
        assert_eq!(detail.summary.capture_state, "complete");
        assert_eq!(detail.response_body.as_bytes(), PLAINTEXT);
        assert_eq!(detail.response_body_note.as_deref(), Some(CONNECTION_CLOSED_CLIENT_MAY_NOT_READ));
        drop(manager);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[tokio::test]
    async fn dropped_after_partial_poll_dumps_remaining_response_body() -> Result<(), crate::DynError> {
        let (manager, path, id) = open_capture_record("drop_partial")?;
        let mut wrapped = MitmCaptureBody::new(
            PendingChunks::new([Bytes::from_static(b"hello "), Bytes::from_static(b"world")]).boxed(),
            manager.clone(),
            id.clone(),
            BodyDirection::Response,
            CaptureMode::Plaintext,
        );
        let first = wrapped.frame().await;
        assert!(matches!(first, Some(Ok(_))));
        drop(wrapped);
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        let detail = manager.get_record(id).await?.ok_or("record not found")?;
        assert_eq!(detail.summary.capture_state, "complete");
        assert_eq!(detail.response_body, "hello world");
        assert_eq!(detail.response_body_note.as_deref(), Some(CONNECTION_CLOSED_CLIENT_MAY_NOT_READ));
        drop(manager);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[tokio::test]
    async fn dropped_unknown_length_body_is_fully_dumped() -> Result<(), crate::DynError> {
        let (manager, path, id) = open_capture_record("drop_unknown_len")?;
        let wrapped = MitmCaptureBody::new(
            PendingChunks::new([
                Bytes::from_static(b"{\"ok\":"),
                Bytes::from_static(b"true,"),
                Bytes::from_static(b"\"n\":1}"),
            ])
            .boxed(),
            manager.clone(),
            id.clone(),
            BodyDirection::Response,
            CaptureMode::Plaintext,
        );
        drop(wrapped);
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        let detail = manager.get_record(id).await?.ok_or("record not found")?;
        assert_eq!(detail.summary.capture_state, "complete");
        assert_eq!(detail.response_body, "{\"ok\":true,\"n\":1}");
        assert!(!detail.response_body_truncated);
        assert_eq!(detail.response_body_note.as_deref(), Some(CONNECTION_CLOSED_CLIENT_MAY_NOT_READ));
        drop(manager);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    #[tokio::test]
    async fn dropped_delayed_unknown_length_body_is_fully_dumped() -> Result<(), crate::DynError> {
        let (manager, path, id) = open_capture_record("drop_unknown_delayed")?;
        let wrapped = MitmCaptureBody::new(
            DelayedUnknownLength::new([Bytes::from_static(b"chunk-a"), Bytes::from_static(b"-chunk-b")]).boxed(),
            manager.clone(),
            id.clone(),
            BodyDirection::Response,
            CaptureMode::Plaintext,
        );
        drop(wrapped);
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        let detail = manager.get_record(id).await?.ok_or("record not found")?;
        assert_eq!(detail.summary.capture_state, "complete");
        assert_eq!(detail.response_body, "chunk-a-chunk-b");
        assert_eq!(detail.response_body_note.as_deref(), Some(CONNECTION_CLOSED_CLIENT_MAY_NOT_READ));
        drop(manager);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    // HTTP/1.1 下游写满 Content-Length 后可能不再 poll body：最后一帧消费后 size_hint
    // 已精确归零，即使底层尚未报告 is_end_stream，也必须收尾为 complete 而不是 interrupted
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
                client_port: 54321,
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
        let body = LastFrameWithoutEndStream::new(Bytes::from_static(b"exact length")).boxed();
        let mut wrapped =
            MitmCaptureBody::new(body, manager.clone(), id.clone(), BodyDirection::Response, CaptureMode::Plaintext);
        // 只 poll 一次拿到全部数据，模拟下游消费完 Content-Length 后不再 poll
        let first = wrapped.frame().await;
        assert!(matches!(first, Some(Ok(_))));
        assert!(!wrapped.is_end_stream(), "capture completion must not hide possible trailers");
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
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
        assert!(matches!(body_capture_mode(&headers), CaptureMode::Skip(_)));
    }

    #[test]
    fn response_mode_buffers_images_but_not_svg() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/png"));
        assert!(matches!(body_capture_mode(&headers), CaptureMode::Image(_)));

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/svg+xml"));
        assert!(matches!(body_capture_mode(&headers), CaptureMode::Plaintext));
    }

    // 完整的图片 body 应以 base64 落库，并把 media type 写入 response_body_image 供 UI 预览
    #[tokio::test]
    async fn complete_image_body_is_stored_as_base64() -> Result<(), crate::DynError> {
        const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        let (manager, path, id) = open_capture_record("image")?;
        let body = http_body_util::Full::new(Bytes::from_static(PNG))
            .map_err(|never: std::convert::Infallible| match never {})
            .boxed();
        let mut wrapped = MitmCaptureBody::new(
            body,
            manager.clone(),
            id.clone(),
            BodyDirection::Response,
            CaptureMode::Image(ImageCapture {
                media_type: "image/png".to_owned(),
                decoder: None,
                buffer: Vec::new(),
            }),
        );
        while let Some(frame) = wrapped.frame().await {
            frame?;
        }
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        let detail = manager.get_record(id).await?.ok_or("record not found")?;
        assert_eq!(detail.summary.capture_state, "complete");
        assert_eq!(detail.response_body, base64::engine::general_purpose::STANDARD.encode(PNG));
        assert_eq!(detail.response_body_bytes, PNG.len() as i64);
        assert!(!detail.response_body_truncated);
        assert_eq!(detail.response_body_note, None);
        assert_eq!(detail.response_body_image.as_deref(), Some("image/png"));
        drop(manager);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    // 超过抓取上限的图片不完整，无法预览：只记字节数和截断标记，不落 base64
    #[tokio::test]
    async fn truncated_image_body_is_not_stored() -> Result<(), crate::DynError> {
        let (manager, path, id) = open_capture_record("image_truncated")?;
        manager
            .patch_settings(crate::mitm_manager::MitmSettingsPatch {
                capture_enabled: None,
                max_records: None,
                body_limit_bytes: Some(1024),
            })
            .await?;
        let data = vec![7u8; 2048];
        let body = http_body_util::Full::new(Bytes::from(data))
            .map_err(|never: std::convert::Infallible| match never {})
            .boxed();
        let mut wrapped = MitmCaptureBody::new(
            body,
            manager.clone(),
            id.clone(),
            BodyDirection::Response,
            CaptureMode::Image(ImageCapture {
                media_type: "image/png".to_owned(),
                decoder: None,
                buffer: Vec::new(),
            }),
        );
        while let Some(frame) = wrapped.frame().await {
            frame?;
        }
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        let detail = manager.get_record(id).await?.ok_or("record not found")?;
        assert_eq!(detail.response_body, "");
        assert_eq!(detail.response_body_bytes, 2048);
        assert!(detail.response_body_truncated);
        assert_eq!(detail.response_body_image, None);
        drop(manager);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let _ = std::fs::remove_file(path);
        Ok(())
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

    fn open_capture_record(tag: &str) -> Result<(Arc<MitmManager>, std::path::PathBuf, String), crate::DynError> {
        let path = std::env::temp_dir().join(format!(
            "rust_http_proxy_mitm_capture_{tag}_{}_{:x}.sqlite3",
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
                client_port: 54321,
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
        Ok((manager, path, id))
    }

    struct EndedStreamWithoutSizeHint;

    impl http_body::Body for EndedStreamWithoutSizeHint {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            self: Pin<&mut Self>, _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(None)
        }

        fn is_end_stream(&self) -> bool {
            true
        }

        fn size_hint(&self) -> SizeHint {
            SizeHint::default()
        }
    }

    struct LastFrameWithoutEndStream {
        data: Option<Bytes>,
    }

    impl LastFrameWithoutEndStream {
        fn new(data: Bytes) -> Self {
            Self { data: Some(data) }
        }
    }

    impl http_body::Body for LastFrameWithoutEndStream {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>, _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(self.data.take().map(|data| Ok(Frame::data(data))))
        }

        fn is_end_stream(&self) -> bool {
            false
        }

        fn size_hint(&self) -> SizeHint {
            SizeHint::with_exact(self.data.as_ref().map_or(0, |data| data.len()) as u64)
        }
    }

    struct PendingChunks {
        chunks: std::vec::IntoIter<Bytes>,
    }

    impl PendingChunks {
        fn new(chunks: impl Into<Vec<Bytes>>) -> Self {
            Self {
                chunks: chunks.into().into_iter(),
            }
        }
    }

    impl http_body::Body for PendingChunks {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>, _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(self.chunks.next().map(|data| Ok(Frame::data(data))))
        }

        fn is_end_stream(&self) -> bool {
            false
        }

        fn size_hint(&self) -> SizeHint {
            SizeHint::default()
        }
    }

    // 模拟 chunked / 无 Content-Length：帧之间先 Pending 再继续，size_hint 没有精确长度。
    struct DelayedUnknownLength {
        chunks: std::vec::IntoIter<Bytes>,
        pending: bool,
    }

    impl DelayedUnknownLength {
        fn new(chunks: impl Into<Vec<Bytes>>) -> Self {
            Self {
                chunks: chunks.into().into_iter(),
                pending: true,
            }
        }
    }

    impl http_body::Body for DelayedUnknownLength {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>, context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            if self.pending {
                self.pending = false;
                context.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.pending = true;
            Poll::Ready(self.chunks.next().map(|data| Ok(Frame::data(data))))
        }

        fn is_end_stream(&self) -> bool {
            false
        }

        fn size_hint(&self) -> SizeHint {
            SizeHint::default()
        }
    }
}
