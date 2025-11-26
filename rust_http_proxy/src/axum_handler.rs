use crate::metrics::METRICS;
use askama::Template;
use axum::extract::{ConnectInfo, MatchedPath, State};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;

use http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use log::{debug, warn};
use prometheus_client::encoding::text::encode;
use std::collections::HashMap;
use std::fmt::Display;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

#[cfg(target_os = "linux")]
use crate::linux_axum_handler;

pub(crate) struct AppState {
    pub basic_auth: HashMap<String, String>,
}

pub(crate) fn build_router(appstate: AppState) -> Router {
    // build our application with a route
    let router = Router::new()
        .route(
            "/ip",
            get(|ConnectInfo(addr): ConnectInfo<SocketAddr>| async move {
                (StatusCode::OK, addr.ip().to_canonical().to_string())
            }),
        )
        .route("/metrics", get(serve_metrics))
        .fallback(get(|| async {
            let mut header_map = HeaderMap::new();
            #[allow(clippy::expect_used)]
            header_map.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
            (
                StatusCode::NOT_FOUND,
                header_map,
                Html(
                    ErrorTemplate {
                        title: "404 Not Found".to_string(),
                        msg: "The requested URL was not found on this server.".to_string(),
                    }
                    .render()
                    .unwrap_or("Failed to render error template".to_string()),
                ),
            )
        }))
        .layer((
            TraceLayer::new_for_http() // Create our own span for the request and include the matched path. The matched
                // path is useful for figuring out which handler the request was routed to.
                .make_span_with(make_span)
                // By default `TraceLayer` will log 5xx responses but we're doing our specific
                // logging of errors so disable that
                .on_failure(()),
            CorsLayer::permissive(),
            TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(30)),
            CompressionLayer::new(),
        ));
    #[cfg(target_os = "linux")]
    let router = router
        .route("/nt", get(linux_axum_handler::count_incoming_stream))
        .route("/nt2", get(linux_axum_handler::count_outcoming_stream))
        .route("/net", get(linux_axum_handler::net_html))
        .route("/netx", get(linux_axum_handler::netx_html))
        .route("/net.json", get(linux_axum_handler::net_json));

    router.with_state(Arc::new(appstate))
}

fn make_span(req: &http::Request<axum::body::Body>) -> tracing::Span {
    let method = req.method();
    let path = req.uri().path();

    // axum automatically adds this extension.
    let matched_path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|matched_path| matched_path.as_str());

    tracing::debug_span!("recv request", %method, %path, matched_path)
}

pub(crate) const AXUM_PATHS: [&str; 6] = [
    "/ip",
    "/metrics",
    "/nt",       // netstat
    "/net",      // net html
    "/netx",     // net extended html
    "/net.json", // net json
];

pub(crate) fn check_auth(
    headers: &HeaderMap, header_name: HeaderName, basic_auth: &HashMap<String, String>,
) -> Result<Option<String>, io::Error> {
    // If no auth configuration, skip auth check
    if basic_auth.is_empty() {
        return Ok(None);
    }

    // Get Authorization header
    let auth_header = headers
        .get(header_name)
        .ok_or_else(|| {
            warn!("no Authorization header found");
            std::io::Error::new(std::io::ErrorKind::NotFound, "no Authorization header found")
        })?
        .to_str()
        .map_err(|e| {
            warn!("Failed to parse Authorization header: {e:?}");
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, e)
        })?;

    // Check if auth header matches any configured auth
    for (key, value) in basic_auth {
        if auth_header == key {
            return Ok(Some(value.clone()));
        }
    }

    Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "wrong Authorization header value"))
}

async fn serve_metrics(
    State(state): State<Arc<AppState>>, headers: HeaderMap,
) -> Result<(StatusCode, HeaderMap, String), AppProxyError> {
    let mut header_map = HeaderMap::new();
    match check_auth(&headers, http::header::AUTHORIZATION, &state.basic_auth) {
        Ok(some_user) => {
            debug!("authorized request from [{some_user:?}]");
        }
        Err(e) => {
            warn!("authorization failed: {e:?}");
            header_map
                .insert(http::header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"are you kidding me\""));
            return Ok((http::StatusCode::UNAUTHORIZED, header_map, format!("{e}")));
        }
    }

    #[cfg(all(target_os = "linux", feature = "bpf"))]
    crate::ebpf::snapshot_metrics();
    #[cfg(target_os = "linux")]
    crate::metrics::update_cgroup_metrics();
    let mut buffer = String::new();
    encode(&mut buffer, &METRICS.registry).map_err(AppProxyError::new)?;
    Ok((http::StatusCode::OK, header_map, buffer))
}

#[derive(Template)]
#[template(path = "error.html")]
#[allow(dead_code)]
struct ErrorTemplate {
    title: String,
    msg: String,
}

#[allow(dead_code)]
pub(crate) struct HtmlTemplate<T>(pub T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to render template. Error: {err}")).into_response()
            }
        }
    }
}

// Make our own error that wraps `anyhow::Error`.
#[derive(Debug)]
pub struct AppProxyError(anyhow::Error);

impl Display for AppProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

// Tell axum how to convert `AppProxyError` into a response.
impl IntoResponse for AppProxyError {
    fn into_response(self) -> Response {
        let err = self.0;
        // Because `TraceLayer` wraps each request in a span that contains the request
        // method, uri, etc we don't need to include those details here
        tracing::error!(%err, "error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html(
                ErrorTemplate {
                    title: "502 Bad Gateway".to_string(),
                    msg: format!("Internal server error: {err}"),
                }
                .render()
                .unwrap_or("Failed to render error template".to_string()),
            ),
        )
            .into_response()
    }
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to turn them into
// `Result<_, AppProxyError>`. That way you don't need to do that manually.
impl<E> From<E> for AppProxyError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

impl AppProxyError {
    #[allow(dead_code)]
    pub fn new<T: std::error::Error + Send + Sync + 'static>(err: T) -> Self {
        use anyhow::anyhow;
        Self(anyhow!(err))
    }
}
