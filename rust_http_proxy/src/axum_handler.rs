use crate::metrics::METRICS;
use askama::Template;
use axum::extract::{ConnectInfo, MatchedPath, State};
use axum::response::{Html, IntoResponse, Response};
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
                .make_span_with(make_span)
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
    use std::cmp::Ordering;

    let mut headers = HeaderMap::new();

    // ss -ntp state established state close-wait 'sport <= 10000 && sport != 22  && dport > 1024'
    match std::process::Command::new("ss")
        .arg("-ntp")
        .arg("state")
        .arg("established")
        .arg("state")
        .arg("close-wait")
        .arg("sport <= 10000 && sport != 22  && dport > 1024")
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8(output.stdout).unwrap_or_default();
            let stderr = String::from_utf8(output.stderr).unwrap_or_default();
            debug!("ss command stdout: {}", stdout);
            if !stderr.is_empty() {
                warn!("ss command stderr: {}", stderr);
                return Err(AppError::new(io::Error::new(io::ErrorKind::Other, stderr)));
            }

            fn parse_ip_and_port(addr_port: &str) -> (String, u16) {
                // 如果是IPv6地址，格式通常是[ipv6]:port
                if addr_port.starts_with('[') {
                    if let Some(bracket_end) = addr_port.rfind(']') {
                        // 提取IPv6地址
                        let addr = addr_port[1..bracket_end].replace("::ffff:", "");

                        // 提取端口（在右括号后面的冒号之后）
                        if let Some(port_start) = addr_port[bracket_end..].find(':') {
                            if let Ok(port) = addr_port[bracket_end + port_start + 1..].parse::<u16>() {
                                return (addr, port);
                            }
                        }
                    }
                } else {
                    // IPv4地址，格式通常是ipv4:port
                    if let Some(colon_pos) = addr_port.rfind(':') {
                        let addr = addr_port[..colon_pos].to_string();
                        if let Ok(port) = addr_port[colon_pos + 1..].parse::<u16>() {
                            return (addr, port);
                        }
                    }
                }

                // 如果解析失败，返回默认值
                (addr_port.to_string(), 0)
            }

            // 解析进程信息，返回格式为"pid/command"
            fn parse_process_info(process_field: &str) -> String {
                if process_field.contains("pid=") {
                    // 匹配形如 users:(("sshd",pid=536,fd=4)) 的格式
                    let mut process_name = "";
                    let mut pid = "";

                    // 提取进程名
                    if let Some(name_start) = process_field.find("((\"") {
                        if let Some(name_end) = process_field[name_start + 3..].find("\"") {
                            process_name = &process_field[name_start + 3..name_start + 3 + name_end];
                        }
                    }

                    // 提取pid
                    if let Some(pid_start) = process_field.find("pid=") {
                        let pid_substr = &process_field[pid_start + 4..];
                        if let Some(pid_end) = pid_substr.find(|c: char| !c.is_ascii_digit()) {
                            pid = &pid_substr[..pid_end];
                        } else {
                            pid = pid_substr; // 如果没有找到非数字字符，使用整个子串
                        }
                    }

                    if !process_name.is_empty() && !pid.is_empty() {
                        return format!("{}/{}", pid, process_name);
                    }
                }
                "".to_string()
            }

            // 解析 ss 命令输出
            let mut connections = Vec::new();
            for line in stdout.lines().skip(1) {
                // 跳过标题行
                // 解析行
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 6 {
                    continue; // 格式不符合预期
                }

                // 提取本地地址和端口
                let local_addr_port = fields[3];
                let (local_addr, local_port) = parse_ip_and_port(local_addr_port);

                // 提取对端地址和端口
                let peer_addr_port = fields[4];
                let (peer_addr, peer_port) = parse_ip_and_port(peer_addr_port);

                // 提取进程信息
                let process_info = if fields.len() >= 6 {
                    parse_process_info(fields[5])
                } else {
                    "".to_string()
                };

                if local_port < 10000 && local_port != 22 && peer_port > 1024 {
                    connections.push((peer_addr, local_addr, local_port, process_info));
                }
            }

            // 按照连接信息进行分组和计数
            let mut connection_counts: HashMap<String, usize> = HashMap::new();
            for (peer_addr, local_addr, local_port, process_info) in connections {
                let connection_str =
                    format!("{:>15}   => {:>15}:{:<5} {}", peer_addr, local_addr, local_port, process_info);
                *connection_counts.entry(connection_str).or_insert(0) += 1;
            }

            // 按计数排序并格式化输出
            let mut sorted_connections: Vec<(String, usize)> = connection_counts.into_iter().collect();
            sorted_connections.sort_by(|a, b| {
                let mut order = b.1.cmp(&a.1);
                if order == Ordering::Equal {
                    order = a.0.cmp(&b.0);
                }
                order
            });

            let result = sorted_connections
                .iter()
                .map(|(connection, count)| format!("{:>4} {}", count, connection))
                .collect::<Vec<String>>()
                .join("\n");

            #[allow(clippy::expect_used)]
            headers.insert(http::header::REFRESH, HeaderValue::from_static("3")); // 设置刷新时间
            Ok((headers, result))
        }
        Err(e) => {
            warn!("ss command error: {}", e);
            Err(AppError::new(e))
        }
    }
}

#[cfg(target_os = "linux")]
async fn net_html(
    State(_): State<Arc<AppState>>, axum_extra::extract::Host(host): axum_extra::extract::Host,
) -> Result<impl IntoResponse, AppError> {
    Ok(HtmlTemplate(NetTemplate {
        hostname: host.to_string(),
    }))
}

#[cfg(target_os = "linux")]
async fn netx_html(
    State(_): State<Arc<AppState>>, axum_extra::extract::Host(host): axum_extra::extract::Host,
) -> Result<impl IntoResponse, AppError> {
    Ok(HtmlTemplate(NetXTemplate {
        hostname: host.to_string(),
    }))
}

#[cfg(target_os = "linux")]
async fn net_json(State(_): State<Arc<AppState>>) -> Result<axum::Json<crate::linux_monitor::Snapshot>, AppError> {
    use crate::linux_monitor::NET_MONITOR;
    Ok(axum::Json(NET_MONITOR.net_json().await))
}

#[derive(Template)]
#[template(path = "net_react.html")]
struct NetTemplate {
    hostname: String,
}

#[derive(Template)]
#[template(path = "net_legacy.html")]
struct NetXTemplate {
    hostname: String,
}

struct HtmlTemplate<T>(T);

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
