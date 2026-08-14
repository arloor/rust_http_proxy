use std::{
    borrow::Cow,
    io::{self, ErrorKind, Write as _},
};

use axum::extract::Request;
use http::header::{CONTENT_ENCODING, CONTENT_TYPE, HOST};
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::{
    Response, Version,
    body::{Bytes, Incoming},
};
use log::{info, warn};

use crate::proxy::labels::AccessLabel;

const MITM_DUMP_BODY_LIMIT: usize = 16 * 1024;

pub(super) fn map_mitm_request_body(
    req: Request<Incoming>, access_label: AccessLabel, dump_plaintext: bool,
) -> Request<BoxBody<Bytes, io::Error>> {
    req.map(|body| {
        let body = body.map_err(|e| io::Error::new(ErrorKind::InvalidData, e));
        if dump_plaintext {
            let mut bytes_seen = 0usize;
            let mut truncated = false;
            body.map_frame(move |frame| {
                if let Some(data) = frame.data_ref() {
                    log_mitm_body_chunk(&access_label, "request", data, &mut bytes_seen, &mut truncated);
                }
                frame
            })
            .boxed()
        } else {
            body.boxed()
        }
    })
}

pub(super) async fn dump_mitm_request_body(body: &mut Incoming, access_label: &AccessLabel) -> io::Result<()> {
    let mut bytes_seen = 0usize;
    let mut truncated = false;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        if let Some(data) = frame.data_ref() {
            log_mitm_body_chunk(access_label, "request", data, &mut bytes_seen, &mut truncated);
        }
    }
    Ok(())
}

pub(super) fn map_mitm_response_body(
    resp: Response<Incoming>, access_label: AccessLabel, dump_plaintext: bool,
) -> Response<BoxBody<Bytes, io::Error>> {
    let log_mode = if dump_plaintext {
        mitm_response_body_log_mode(resp.headers())
    } else {
        MitmResponseBodyLogMode::Disabled
    };
    resp.map(|body| {
        let body = body.map_err(|e| io::Error::new(ErrorKind::InvalidData, e));
        match log_mode {
            MitmResponseBodyLogMode::Disabled => body.boxed(),
            MitmResponseBodyLogMode::Skip(reason) => {
                info!("[mitm plaintext response body] {access_label} skipped: body is not human-readable ({reason})");
                body.boxed()
            }
            MitmResponseBodyLogMode::Plaintext => {
                let mut bytes_seen = 0usize;
                let mut truncated = false;
                body.map_frame(move |frame| {
                    if let Some(data) = frame.data_ref() {
                        log_mitm_body_chunk(&access_label, "response", data, &mut bytes_seen, &mut truncated);
                    }
                    frame
                })
                .boxed()
            }
            MitmResponseBodyLogMode::Gzip => MitmGzipLogBody::new(body, access_label).boxed(),
        }
    })
}

#[derive(Debug, PartialEq, Eq)]
enum MitmResponseBodyLogMode {
    Disabled,
    Plaintext,
    Gzip,
    Skip(String),
}

fn mitm_response_body_log_mode(headers: &http::HeaderMap) -> MitmResponseBodyLogMode {
    let content_encoding = non_identity_content_encodings(headers);
    let encoding_mode = match content_encoding.as_slice() {
        [] => MitmResponseBodyLogMode::Plaintext,
        [encoding] if encoding.eq_ignore_ascii_case("gzip") => MitmResponseBodyLogMode::Gzip,
        _ => {
            return MitmResponseBodyLogMode::Skip(format!("content-encoding: {}", content_encoding.join(", ")));
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
        MitmResponseBodyLogMode::Skip(format!("content-type: {media_type}"))
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
                .filter(|encoding| !encoding.is_empty())
                .filter(|encoding| !encoding.eq_ignore_ascii_case("identity"))
                .map(str::to_owned)
        })
        .collect()
}

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
    struct MitmGzipLogBody<B> {
        #[pin]
        inner: B,
        access_label: AccessLabel,
        decoder: Option<GzipBodyDecoder>,
        compressed_bytes_seen: usize,
        decoded_bytes_seen: usize,
        truncated: bool,
        completed: bool,
    }
}

impl<B> MitmGzipLogBody<B> {
    fn new(inner: B, access_label: AccessLabel) -> Self {
        Self {
            inner,
            access_label,
            decoder: Some(GzipBodyDecoder::new()),
            compressed_bytes_seen: 0,
            decoded_bytes_seen: 0,
            truncated: false,
            completed: false,
        }
    }
}

impl<B> http_body::Body for MitmGzipLogBody<B>
where
    B: http_body::Body<Data = Bytes, Error = io::Error>,
{
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        match this.inner.as_mut().poll_frame(cx) {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    *this.compressed_bytes_seen = this.compressed_bytes_seen.saturating_add(data.len());
                    if let Some(decoder) = this.decoder.as_mut() {
                        match decoder.decode_chunk(data) {
                            Ok(decoded) => log_mitm_body_chunk(
                                this.access_label,
                                "response",
                                &decoded,
                                this.decoded_bytes_seen,
                                this.truncated,
                            ),
                            Err(error) => {
                                warn!(
                                    "[mitm plaintext response body] {} stopped gzip decoding: {error}",
                                    this.access_label
                                );
                                *this.decoder = None;
                            }
                        }
                        if *this.truncated {
                            *this.decoder = None;
                        }
                    }
                }
                std::task::Poll::Ready(Some(Ok(frame)))
            }
            std::task::Poll::Ready(None) => {
                if !*this.completed {
                    *this.completed = true;
                    if *this.compressed_bytes_seen == 0 {
                        info!(
                            "[mitm plaintext response body] {} 0 bytes (empty response; no gzip payload)",
                            this.access_label
                        );
                    } else if let Some(decoder) = this.decoder.as_mut() {
                        match decoder.finish() {
                            Ok(decoded) => {
                                log_mitm_body_chunk(
                                    this.access_label,
                                    "response",
                                    &decoded,
                                    this.decoded_bytes_seen,
                                    this.truncated,
                                );
                                if *this.decoded_bytes_seen == 0 {
                                    info!(
                                        "[mitm plaintext response body] {} 0 bytes (empty after decoding {} gzip bytes)",
                                        this.access_label, this.compressed_bytes_seen
                                    );
                                }
                            }
                            Err(error) => warn!(
                                "[mitm plaintext response body] {} failed to finish gzip decoding after {} compressed bytes: {error}",
                                this.access_label, this.compressed_bytes_seen
                            ),
                        }
                    }
                    *this.decoder = None;
                }
                std::task::Poll::Ready(None)
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.completed
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
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

pub(super) fn log_mitm_request_head(req: &Request<Incoming>, access_label: &AccessLabel) {
    info!(
        "[mitm plaintext request curl] {access_label} {}\n{}",
        http_version_label(req.version()),
        format_request_as_curl(req, access_label),
    );
}

pub(super) fn log_mitm_response_head(resp: &Response<Incoming>, access_label: &AccessLabel) {
    info!(
        "[mitm plaintext response head] {access_label}\n{:?} {}\n{}",
        resp.version(),
        resp.status(),
        format_headers(resp.headers()),
    );
}

fn format_headers(headers: &http::HeaderMap) -> String {
    let mut output = String::new();
    for (name, value) in headers {
        output.push_str(name.as_str());
        output.push_str(": ");
        output.push_str(&String::from_utf8_lossy(value.as_bytes()));
        output.push('\n');
    }
    output
}

fn format_request_as_curl<B>(req: &Request<B>, access_label: &AccessLabel) -> String {
    let url = match req.uri().scheme() {
        Some(_) => req.uri().to_string(),
        None => {
            let path = req.uri().path_and_query().map(|path| path.as_str()).unwrap_or("/");
            format!("https://{}{path}", access_label.target)
        }
    };

    let mut output = String::from("curl");
    if let Some(flag) = curl_http_version_flag(req.version()) {
        output.push(' ');
        output.push_str(flag);
    }
    output.push_str(&format!(" -X {} \\\n  {}", req.method(), shell_quote(&url)));
    for (name, value) in req.headers() {
        let header = format!("{}: {}", name.as_str(), String::from_utf8_lossy(value.as_bytes()));
        output.push_str(" \\\n  -H ");
        output.push_str(&shell_quote(&header));
    }
    output
}

pub(super) fn request_authority_for_log<'a, B>(req: &'a Request<B>, access_label: &'a AccessLabel) -> Cow<'a, str> {
    req.uri()
        .authority()
        .map(|authority| Cow::Borrowed(authority.as_str()))
        .or_else(|| {
            req.headers()
                .get(HOST)
                .and_then(|host| host.to_str().ok())
                .filter(|host| !host.is_empty())
                .map(Cow::Borrowed)
        })
        .unwrap_or_else(|| Cow::Borrowed(&access_label.target))
}

fn curl_http_version_flag(version: Version) -> Option<&'static str> {
    match version {
        Version::HTTP_10 => Some("--http1.0"),
        Version::HTTP_11 => Some("--http1.1"),
        Version::HTTP_2 => Some("--http2"),
        Version::HTTP_3 => Some("--http3"),
        _ => None,
    }
}

fn http_version_label(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/unknown",
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn log_mitm_body_chunk(
    access_label: &AccessLabel, direction: &'static str, data: &Bytes, bytes_seen: &mut usize, truncated: &mut bool,
) {
    if data.is_empty() {
        return;
    }
    if *bytes_seen >= MITM_DUMP_BODY_LIMIT {
        if !*truncated {
            info!("[mitm plaintext {direction} body] {access_label} truncated after {MITM_DUMP_BODY_LIMIT} bytes");
            *truncated = true;
        }
        *bytes_seen = (*bytes_seen).saturating_add(data.len());
        return;
    }

    let remaining = MITM_DUMP_BODY_LIMIT - *bytes_seen;
    let logged_len = remaining.min(data.len());
    let plaintext = String::from_utf8_lossy(&data[..logged_len]);
    info!("[mitm plaintext {direction} body] {access_label} {logged_len} bytes\n{plaintext}");

    *bytes_seen = (*bytes_seen).saturating_add(data.len());
    if data.len() > remaining && !*truncated {
        info!("[mitm plaintext {direction} body] {access_label} truncated after {MITM_DUMP_BODY_LIMIT} bytes");
        *truncated = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::HeaderValue;
    use http_body_util::Full;
    use hyper::Method;

    fn test_access_label() -> AccessLabel {
        AccessLabel {
            client: "127.0.0.1".to_owned(),
            target: "example.com".to_owned(),
            username: "test".to_owned(),
            relay_over_tls: Some(true),
        }
    }

    #[test]
    fn format_request_as_curl_uses_http1_version_flag() -> Result<(), http::Error> {
        let req = Request::builder()
            .version(Version::HTTP_11)
            .method(Method::GET)
            .uri("/plain?x=1")
            .header(HOST, "example.com")
            .body(())?;

        let curl = format_request_as_curl(&req, &test_access_label());

        assert!(curl.starts_with("curl --http1.1 -X GET"));
        assert!(curl.contains("'https://example.com/plain?x=1'"));
        assert!(curl.contains("-H 'host: example.com'"));
        Ok(())
    }

    #[test]
    fn format_request_as_curl_uses_http2_version_flag() -> Result<(), http::Error> {
        let req = Request::builder()
            .version(Version::HTTP_2)
            .method(Method::POST)
            .uri("https://example.com/h2")
            .body(())?;

        let curl = format_request_as_curl(&req, &test_access_label());

        assert!(curl.starts_with("curl --http2 -X POST"));
        assert!(curl.contains("'https://example.com/h2'"));
        Ok(())
    }

    #[test]
    fn http_version_label_formats_request_version_for_log_head() {
        assert_eq!(http_version_label(Version::HTTP_10), "HTTP/1.0");
        assert_eq!(http_version_label(Version::HTTP_11), "HTTP/1.1");
        assert_eq!(http_version_label(Version::HTTP_2), "HTTP/2");
    }

    #[test]
    fn request_authority_for_log_prefers_uri_authority() -> Result<(), http::Error> {
        let req = Request::builder()
            .uri("https://uri.example/path")
            .header(HOST, "host.example")
            .body(())?;

        assert_eq!(request_authority_for_log(&req, &test_access_label()), "uri.example");
        Ok(())
    }

    #[test]
    fn request_authority_for_log_uses_host_then_target() -> Result<(), http::Error> {
        let req_with_host = Request::builder().uri("/path").header(HOST, "host.example").body(())?;
        assert_eq!(request_authority_for_log(&req_with_host, &test_access_label()), "host.example",);

        let req_without_host = Request::builder().uri("/path").body(())?;
        assert_eq!(request_authority_for_log(&req_without_host, &test_access_label()), "example.com",);
        Ok(())
    }

    #[test]
    fn mitm_response_body_decodes_gzip_body() {
        let mut headers = http::HeaderMap::new();
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        assert_eq!(mitm_response_body_log_mode(&headers), MitmResponseBodyLogMode::Gzip);
    }

    #[test]
    fn mitm_response_body_skips_unsupported_encoding() {
        let mut headers = http::HeaderMap::new();
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("br"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        assert_eq!(
            mitm_response_body_log_mode(&headers),
            MitmResponseBodyLogMode::Skip("content-encoding: br".to_owned())
        );
    }

    #[test]
    fn mitm_response_body_skips_non_text_content_type() {
        let mut headers = http::HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/png"));

        assert_eq!(
            mitm_response_body_log_mode(&headers),
            MitmResponseBodyLogMode::Skip("content-type: image/png".to_owned())
        );
    }

    #[test]
    fn mitm_response_body_allows_text_content_types() {
        for content_type in [
            "text/plain; charset=utf-8",
            "application/json",
            "application/problem+json",
            "application/xml",
            "image/svg+xml",
        ] {
            let mut headers = http::HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));

            assert_eq!(mitm_response_body_log_mode(&headers), MitmResponseBodyLogMode::Plaintext);
        }
    }

    #[test]
    fn mitm_response_body_allows_missing_content_type() {
        let headers = http::HeaderMap::new();

        assert_eq!(mitm_response_body_log_mode(&headers), MitmResponseBodyLogMode::Plaintext);
    }

    #[test]
    fn gzip_body_decoder_handles_fragmented_input() -> io::Result<()> {
        let plaintext = br#"{"message":"gzip response body"}"#;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(plaintext)?;
        let compressed = encoder.finish()?;
        let mut decoder = GzipBodyDecoder::new();
        let mut decoded = Vec::new();

        for chunk in compressed.chunks(3) {
            decoded.extend_from_slice(&decoder.decode_chunk(chunk)?);
        }
        decoded.extend_from_slice(&decoder.finish()?);

        assert_eq!(decoded, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn gzip_log_body_forwards_compressed_bytes_unchanged() -> io::Result<()> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"response")?;
        let compressed = Bytes::from(encoder.finish()?);
        let body = Full::new(compressed.clone()).map_err(|never| match never {});

        let forwarded = MitmGzipLogBody::new(body, test_access_label())
            .collect()
            .await?
            .to_bytes();

        assert_eq!(forwarded, compressed);
        Ok(())
    }

    #[tokio::test]
    async fn gzip_log_body_completes_for_empty_upstream_body() -> io::Result<()> {
        let body = Full::new(Bytes::new()).map_err(|never| match never {});

        let forwarded = MitmGzipLogBody::new(body, test_access_label())
            .collect()
            .await?
            .to_bytes();

        assert!(forwarded.is_empty());
        Ok(())
    }
}
