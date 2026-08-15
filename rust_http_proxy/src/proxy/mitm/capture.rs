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
                CaptureMode::Gzip(decoder) => match decoder.decode_chunk(data) {
                    Ok(decoded) => capture_bytes(
                        &manager,
                        &id,
                        BodyDirection::Request,
                        &decoded,
                        &mut captured,
                        &mut total,
                        &mut truncated,
                    ),
                    Err(error) => mode = CaptureMode::Skip(format!("gzip decode failed: {error}")),
                },
                CaptureMode::Skip(_) => {}
            }
        }
    }
    let note = match &mut mode {
        CaptureMode::Gzip(decoder) => match decoder.finish() {
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
            Err(error) => Some(format!("gzip finish failed: {error}")),
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

#[derive(Debug)]
enum CaptureMode {
    Plaintext,
    Gzip(GzipBodyDecoder),
    Skip(String),
}

fn body_capture_mode(headers: &http::HeaderMap) -> CaptureMode {
    let content_encoding = non_identity_content_encodings(headers);
    let encoding_mode = match content_encoding.as_slice() {
        [] => CaptureMode::Plaintext,
        [encoding] if encoding.eq_ignore_ascii_case("gzip") => CaptureMode::Gzip(GzipBodyDecoder::new()),
        _ => return CaptureMode::Skip(format!("unsupported content-encoding: {}", content_encoding.join(", "))),
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

#[derive(Debug)]
struct GzipBodyDecoder {
    decoder: flate2::write::GzDecoder<Vec<u8>>,
}

impl GzipBodyDecoder {
    fn new() -> Self {
        Self {
            decoder: flate2::write::GzDecoder::new(Vec::new()),
        }
    }

    fn decode_chunk(&mut self, compressed: &[u8]) -> io::Result<Bytes> {
        self.decoder.write_all(compressed)?;
        Ok(Bytes::from(std::mem::take(self.decoder.get_mut())))
    }

    fn finish(&mut self) -> io::Result<Bytes> {
        self.decoder.try_finish()?;
        Ok(Bytes::from(std::mem::take(self.decoder.get_mut())))
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
                        CaptureMode::Gzip(decoder) => match decoder.decode_chunk(data) {
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
                                *this.mode = CaptureMode::Skip(format!("gzip decode failed: {error}"));
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
            CaptureMode::Gzip(decoder) => match decoder.finish() {
                Ok(decoded) => {
                    capture_bytes(manager, record_id, direction, &decoded, captured_bytes, total_bytes, truncated)
                }
                Err(error) => note = Some(format!("gzip finish failed: {error}")),
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
    use http::{HeaderMap, HeaderValue};

    #[test]
    fn response_mode_skips_binary() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/png"));
        assert!(matches!(body_capture_mode(&headers), CaptureMode::Skip(_)));
    }

    #[test]
    fn response_mode_decodes_gzip_text() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(matches!(body_capture_mode(&headers), CaptureMode::Gzip(_)));
    }
}
