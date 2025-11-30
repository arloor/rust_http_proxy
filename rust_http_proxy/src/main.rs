#![deny(warnings)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
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
    #[allow(clippy::expect_used)]
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    // 使用 _guard 进入 runtime 上下文，这样 create_futures 内部的 tokio::spawn 才能正常工作
    let _guard = runtime.enter();
    let param = Param::parse();
    if let Err(log_init_error) = log_x::init_log(&param.log_dir, &param.log_file, "info") {
        return Err(format!("init log error:{log_init_error}").into());
    }
    let (service_future, shutdown_tx) = create_futures(param)?;

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
