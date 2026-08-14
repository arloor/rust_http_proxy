use std::io;

use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use io_x::{CounterIO, TimeoutIO};
use log::warn;
use prom_label::LabelImpl;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::pin;

use crate::METRICS;

use super::labels::AccessLabel;

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
pub(super) async fn tunnel<C, T>(client_io: C, target_io: CounterIO<T, LabelImpl<AccessLabel>>) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut client_io = client_io;
    let timed_target_io = TimeoutIO::new(target_io, crate::IDLE_TIMEOUT);
    pin!(timed_target_io);
    // https://github.com/sfackler/tokio-io-timeout/issues/12
    // timed_target_io.as_mut() // 一定要as_mut()，否则会move所有权
    // ._set_timeout_pinned(Duration::from_secs(crate::IDLE_SECONDS));
    let (_from_client, _from_server) = tokio::io::copy_bidirectional(&mut client_io, &mut timed_target_io).await?;
    Ok(())
}
