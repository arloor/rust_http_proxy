use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use futures::stream;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};

use crate::axum_handler::{AppState, check_auth};
use crate::mitm_manager::{ManagerError, MitmEvent, MitmSettingsPatch, RecordQuery};

#[derive(RustEmbed)]
#[folder = "../mitm-ui/dist/"]
struct MitmAssets;

pub(crate) fn is_management_path(path: &str) -> bool {
    path == "/mitm" || path.starts_with("/mitm/")
}

pub(crate) fn router(basic_auth: HashMap<String, String>) -> Router<Arc<AppState>> {
    let routes = Router::new()
        .route("/mitm", get(index))
        .route("/mitm/", get(index))
        .route("/mitm/api/settings", get(get_settings).patch(patch_settings))
        .route("/mitm/api/targets", get(get_targets).post(add_target))
        .route("/mitm/api/targets/{id}", delete(delete_target))
        .route("/mitm/api/records", get(get_records).delete(clear_records))
        .route("/mitm/api/records/{id}", get(get_record))
        .route("/mitm/api/groups", get(get_groups))
        .route("/mitm/api/tls-errors", get(get_tls_errors))
        .route("/mitm/api/events", get(events))
        .route("/mitm/{*path}", get(asset_or_index));
    routes.route_layer(middleware::from_fn_with_state(Arc::new(basic_auth), require_basic_auth))
}

async fn require_basic_auth(
    State(basic_auth): State<Arc<HashMap<String, String>>>, headers: HeaderMap, request: Request, next: Next,
) -> Response {
    if basic_auth.is_empty() || check_auth(&headers, header::AUTHORIZATION, &basic_auth).is_err() {
        return unauthorized();
    }
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    response
}

fn unauthorized() -> Response {
    let mut response = (StatusCode::UNAUTHORIZED, "MITM management authentication required").into_response();
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"rust_http_proxy MITM\""));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    response
}

async fn index() -> Response {
    serve_asset("index.html", false)
}

async fn asset_or_index(Path(path): Path<String>) -> Response {
    if path.starts_with("api/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    if MitmAssets::get(&path).is_some() {
        serve_asset(&path, true)
    } else {
        serve_asset("index.html", false)
    }
}

fn serve_asset(path: &str, immutable: bool) -> Response {
    let Some(asset) = MitmAssets::get(path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let content_type = mime_guess::from_path(path).first_or_octet_stream().to_string();
    let mut response = Response::new(Body::from(asset.data.into_owned()));
    if let Ok(value) = HeaderValue::from_str(&content_type) {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    if immutable {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("private, max-age=31536000, immutable"));
    }
    response
}

async fn get_settings(State(state): State<Arc<AppState>>) -> Json<crate::mitm_manager::MitmSettings> {
    Json(state.mitm_manager.settings())
}

async fn patch_settings(
    State(state): State<Arc<AppState>>, Json(patch): Json<MitmSettingsPatch>,
) -> Result<Json<crate::mitm_manager::MitmSettings>, ApiError> {
    Ok(Json(state.mitm_manager.patch_settings(patch).await?))
}

async fn get_targets(State(state): State<Arc<AppState>>) -> Json<Vec<crate::mitm_manager::MitmTarget>> {
    Json(state.mitm_manager.targets())
}

#[derive(Deserialize)]
struct AddTarget {
    suffix: String,
}

async fn add_target(
    State(state): State<Arc<AppState>>, Json(target): Json<AddTarget>,
) -> Result<(StatusCode, Json<crate::mitm_manager::MitmTarget>), ApiError> {
    let target = state.mitm_manager.add_target(target.suffix).await?;
    Ok((StatusCode::CREATED, Json(target)))
}

async fn delete_target(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> Result<StatusCode, ApiError> {
    if state.mitm_manager.delete_target(id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound("MITM target not found".to_owned()))
    }
}

async fn get_records(
    State(state): State<Arc<AppState>>, Query(query): Query<RecordQuery>,
) -> Result<Json<crate::mitm_manager::RecordPage>, ApiError> {
    Ok(Json(state.mitm_manager.list_records(query).await?))
}

async fn get_record(
    State(state): State<Arc<AppState>>, Path(id): Path<String>,
) -> Result<Json<crate::mitm_manager::RecordDetail>, ApiError> {
    state
        .mitm_manager
        .get_record(id)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::NotFound("MITM record not found".to_owned()))
}

async fn get_groups(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<crate::mitm_manager::UrlHostGroup>>, ApiError> {
    Ok(Json(state.mitm_manager.groups().await?))
}

async fn get_tls_errors(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<crate::mitm_manager::TlsErrorGroup>>, ApiError> {
    Ok(Json(state.mitm_manager.tls_errors().await?))
}

async fn clear_records(State(state): State<Arc<AppState>>) -> Result<StatusCode, ApiError> {
    state.mitm_manager.clear_records().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn events(State(state): State<Arc<AppState>>) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let receiver = state.mitm_manager.subscribe();
    let stream = stream::unfold(receiver, |mut receiver| async move {
        let event = match receiver.recv().await {
            Ok(event) => event,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => MitmEvent {
                kind: "resync",
                record_id: None,
            },
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
        };
        let data = serde_json::to_string(&event).unwrap_or_else(|_| "{\"kind\":\"resync\"}".to_owned());
        Some((Ok(Event::default().event(event.kind).data(data)), receiver))
    });
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)).text("keep-alive"))
}

#[derive(Debug)]
enum ApiError {
    Manager(ManagerError),
    NotFound(String),
}

impl From<ManagerError> for ApiError {
    fn from(error: ManagerError) -> Self {
        Self::Manager(error)
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Manager(ManagerError::BadRequest(message)) => (StatusCode::BAD_REQUEST, message),
            Self::Manager(ManagerError::Conflict(message)) => (StatusCode::CONFLICT, message),
            Self::Manager(ManagerError::Database(message)) => (StatusCode::INTERNAL_SERVER_ERROR, message),
            Self::NotFound(message) => (StatusCode::NOT_FOUND, message),
        };
        (status, Json(ErrorBody { error: message })).into_response()
    }
}
