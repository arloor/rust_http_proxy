use crate::axum_handler::{AppState, HtmlTemplate};
use askama::Template;
use axum::extract::State;
use axum::response::IntoResponse;
use axum_bootstrap::AppError;
use http::{HeaderMap, HeaderValue};
use log::{debug, warn};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;

// Linux特定的处理函数
#[axum_macros::debug_handler]
pub async fn count_stream() -> Result<(HeaderMap, String), AppError> {
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

pub async fn net_html(
    State(_): State<Arc<AppState>>, axum_extra::extract::Host(host): axum_extra::extract::Host,
) -> Result<impl IntoResponse, AppError> {
    Ok(HtmlTemplate(NetTemplate {
        hostname: host.to_string(),
    }))
}

pub async fn netx_html(
    State(_): State<Arc<AppState>>, axum_extra::extract::Host(host): axum_extra::extract::Host,
) -> Result<impl IntoResponse, AppError> {
    Ok(HtmlTemplate(NetXTemplate {
        hostname: host.to_string(),
    }))
}

pub async fn net_json(State(_): State<Arc<AppState>>) -> Result<axum::Json<crate::linux_monitor::Snapshot>, AppError> {
    use crate::linux_monitor::NET_MONITOR;
    Ok(axum::Json(NET_MONITOR.net_json().await))
}

#[derive(Template)]
#[template(path = "net_react.html")]
#[allow(dead_code)]
pub struct NetTemplate {
    hostname: String,
}

#[derive(Template)]
#[template(path = "net_legacy.html")]
#[allow(dead_code)]
pub struct NetXTemplate {
    hostname: String,
}
