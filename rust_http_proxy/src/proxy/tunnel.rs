use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use hyper::Response;
use hyper::upgrade::{OnUpgrade, Upgraded};
use hyper_util::rt::TokioIo;
use io_x::{CounterIO, TimeoutIO};
use log::{debug, warn};
use prom_label::LabelImpl;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::pin;

use crate::METRICS;

use super::connect::connect_with_preference;
use super::labels::{AccessLabel, TunnelHandshakeLabel};

/// WebSocket 双向数据转发 - 统一版本
/// 支持可选的流量统计
pub(crate) async fn tunnel_websocket_upgraded(
    client: Upgraded, upstream: Upgraded, traffic_label: Option<AccessLabel>,
) -> io::Result<()> {
    let mut client_io = TokioIo::new(client);
    let mut upstream_io = TokioIo::new(upstream);

    // 如果提供了流量标签，则使用 CounterIO 进行流量统计
    if let Some(label) = traffic_label {
        let mut client_counter = CounterIO::new(client_io, METRICS.proxy_traffic.clone(), LabelImpl::new(label));
        let _ = tokio::io::copy_bidirectional(&mut client_counter, &mut upstream_io).await?;
    } else {
        // 不进行流量统计，直接转发
        let _ = tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await?;
    }

    Ok(())
}

/// 拨号并记录隧道建立耗时。计时只覆盖 TCP，不含之后的 TLS 或 CONNECT。
pub(super) async fn dial_timed_tunnel(target: &str, ipv6_first: Option<bool>) -> io::Result<TcpStream> {
    let started = Instant::now();
    let stream = connect_with_preference(target, ipv6_first).await?;
    METRICS
        .tunnel_bypass_setup_duration
        .get_or_create(&LabelImpl::new(TunnelHandshakeLabel {
            target: target.to_owned(),
        }))
        .observe(started.elapsed().as_millis() as f64);
    Ok(stream)
}

/// 直连 CONNECT 目标，流量按 `access_label` 计数。
pub(super) async fn dial_direct_tunnel(
    kind: &str, access_label: AccessLabel, client_socket_addr: SocketAddr, ipv6_first: Option<bool>,
) -> io::Result<CounterIO<TcpStream, LabelImpl<AccessLabel>>> {
    let target_stream = dial_timed_tunnel(&access_label.target, ipv6_first).await?;
    log_tunnel_path(kind, &access_label, client_socket_addr, target_stream.peer_addr());
    Ok(CounterIO::new(target_stream, METRICS.proxy_traffic.clone(), LabelImpl::new(access_label)))
}

fn log_tunnel_path(
    kind: &str, access_label: &AccessLabel, client_socket_addr: SocketAddr, peer_addr: io::Result<SocketAddr>,
) {
    debug!(
        "[{kind} {access_label}], [true path: {} -> {}]",
        socket_label(client_socket_addr),
        peer_addr.map(socket_label).unwrap_or_else(|_| "failed".to_owned())
    );
}

fn socket_label(addr: SocketAddr) -> String {
    format!("{}:{}", addr.ip().to_canonical(), addr.port())
}

/// 上游返回 101 时才接管双向隧道。非 101 的响应怎么交给客户端，由各调用方自己决定。
pub(crate) fn promote_websocket_upgrade<B>(
    response: &mut Response<B>, client_upgrade: OnUpgrade, traffic_label: Option<AccessLabel>, scenario: &'static str,
) -> bool {
    if response.status() != http::StatusCode::SWITCHING_PROTOCOLS {
        return false;
    }
    let upstream_upgrade = hyper::upgrade::on(response);
    spawn_websocket_tunnel(client_upgrade, upstream_upgrade, traffic_label, scenario);
    true
}

/// 启动 WebSocket 升级后的异步任务
/// 处理 upgrade future 的等待和双向数据转发
pub(crate) fn spawn_websocket_tunnel(
    client_upgrade: hyper::upgrade::OnUpgrade, upstream_upgrade: hyper::upgrade::OnUpgrade,
    traffic_label: Option<AccessLabel>, scenario: &'static str,
) {
    tokio::spawn(async move {
        match (client_upgrade.await, upstream_upgrade.await) {
            (Ok(client_upgraded), Ok(upstream_upgraded)) => {
                if let Err(e) = tunnel_websocket_upgraded(client_upgraded, upstream_upgraded, traffic_label).await {
                    warn!("[{scenario}] WebSocket tunnel error: {e:?}");
                }
            }
            (Err(e), _) => {
                warn!("[{scenario}] WebSocket client upgrade error: {e:?}");
            }
            (_, Err(e)) => {
                warn!("[{scenario}] WebSocket upstream upgrade error: {e:?}");
            }
        }
    });
}

// Build a tunnel between the client connection and the target connection.
pub(super) async fn tunnel<C, T>(client_io: C, target_io: T) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut client_io = client_io;
    let timed_target_io = TimeoutIO::new(target_io, crate::IDLE_TIMEOUT);
    pin!(timed_target_io);
    let (_from_client, _from_server) = tokio::io::copy_bidirectional(&mut client_io, &mut timed_target_io).await?;
    Ok(())
}
