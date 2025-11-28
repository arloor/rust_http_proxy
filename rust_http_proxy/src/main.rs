//! Main entry point for rust_http_proxy CLI

use clap::Parser as _;
use rust_http_proxy::{config::Param, create_futures, DynError};

// 使用jemalloc作为全局内存分配器
#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> Result<(), DynError> {
    let (service_future, shutdown_tx) = create_futures(Param::parse())?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    runtime.spawn(async move {
        if (axum_bootstrap::wait_signal().await).is_ok() {
            let _ = shutdown_tx.send(());
        }
    });
    // Run it right now.
    let results = runtime.block_on(service_future);
    let _ = results.iter().all(|res| {
        if let Err(err) = res {
            log::error!("HTTP Proxy server exited with error: {err:?}");
        }
        res.is_ok()
    });
    Ok(())
}
