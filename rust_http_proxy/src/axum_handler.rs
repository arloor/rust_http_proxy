use crate::metrics::METRICS;
use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::routing::get;
use axum::Router;
use axum_bootstrap::AppError;

use http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use log::{debug, warn};
use prometheus_client::encoding::text::encode;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

pub(crate) const BODY404: &str = include_str!("../html/404.html");

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
            (StatusCode::NOT_FOUND, header_map, BODY404)
        }))
        .layer((
            TraceLayer::new_for_http() // Create our own span for the request and include the matched path. The matched
                // path is useful for figuring out which handler the request was routed to.
                .make_span_with(|req: &Request| {
                    let method = req.method();
                    let path = req.uri().path();

                    // axum automatically adds this extension.
                    let matched_path = req
                        .extensions()
                        .get::<MatchedPath>()
                        .map(|matched_path| matched_path.as_str());

                    tracing::debug_span!("recv request", %method, %path, matched_path)
                })
                // By default `TraceLayer` will log 5xx responses but we're doing our specific
                // logging of errors so disable that
                .on_failure(()),
            CorsLayer::permissive(),
            TimeoutLayer::new(Duration::from_secs(30)),
            CompressionLayer::new(),
        ));
    #[cfg(target_os = "linux")]
    let router = router
        .route("/nt", get(count_stream))
        .route("/net", get(net_html))
        .route("/netx", get(netx_html))
        .route("/net.json", get(net_json));

    router.with_state(Arc::new(appstate))
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
            warn!("Failed to parse Authorization header: {:?}", e);
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
) -> Result<(StatusCode, HeaderMap, String), AppError> {
    let mut header_map = HeaderMap::new();
    match check_auth(&headers, http::header::AUTHORIZATION, &state.basic_auth) {
        Ok(some_user) => {
            debug!("authorized request from [{some_user:?}]");
        }
        Err(e) => {
            warn!("authorization failed: {:?}", e);
            header_map
                .insert(http::header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"are you kidding me\""));
            return Ok((http::StatusCode::UNAUTHORIZED, header_map, format!("{e}")));
        }
    }

    #[cfg(all(target_os = "linux", feature = "bpf"))]
    crate::ebpf::snapshot_metrics();
    let mut buffer = String::new();
    encode(&mut buffer, &METRICS.registry).map_err(AppError::new)?;
    Ok((http::StatusCode::OK, header_map, buffer))
}

#[axum_macros::debug_handler]
#[cfg(target_os = "linux")]
async fn count_stream() -> Result<(HeaderMap, String), AppError> {
    let mut headers = HeaderMap::new();
    match std::process::Command::new("sh")
                .arg("-c")
                .arg(r#"
                netstat -ntp|grep -E "ESTABLISHED|CLOSE_WAIT"|awk -F "[ :]+"  -v OFS="" '$5<10000 && $5!="22" && $7>1024 {printf("%15s   => %15s:%-5s %s\n",$6,$4,$5,$9)}'|sort|uniq -c|sort -rn
                "#)
                .output() {
            Ok(output) => {
                #[allow(clippy::expect_used)]
                headers.insert(http::header::REFRESH, HeaderValue::from_static("3")); // 设置刷新时间
                Ok((headers, String::from_utf8(output.stdout).unwrap_or("".to_string())
                + (&*String::from_utf8(output.stderr).unwrap_or("".to_string()))))
            },
            Err(e) => {
                warn!("sh -c error: {}", e);
                Err(AppError::new(e))
            },
        }
}

#[cfg(target_os = "linux")]
async fn net_html(
    State(_): State<Arc<AppState>>, axum_extra::extract::Host(host): axum_extra::extract::Host,
) -> Result<axum::response::Html<String>, AppError> {
    use crate::linux_monitor::NET_MONITOR;

    NET_MONITOR
        .net_html("/net", &host)
        .await
        .map_err(AppError::new)
        .map(axum::response::Html)
}

#[cfg(target_os = "linux")]
async fn netx_html(
    State(_): State<Arc<AppState>>, axum_extra::extract::Host(host): axum_extra::extract::Host,
) -> Result<axum::response::Html<String>, AppError> {
    use crate::linux_monitor::NET_MONITOR;
    NET_MONITOR
        .net_html("/netx", &host)
        .await
        .map_err(AppError::new)
        .map(axum::response::Html)
}

#[cfg(target_os = "linux")]
async fn net_json(State(_): State<Arc<AppState>>) -> Result<axum::Json<crate::linux_monitor::Snapshot>, AppError> {
    use crate::linux_monitor::NET_MONITOR;
    Ok(axum::Json(NET_MONITOR.net_json().await))
}
