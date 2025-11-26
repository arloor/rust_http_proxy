//! Main entry point for rust_http_proxy CLI

use clap::Parser as _;
use rust_http_proxy::{config::Param, run_service, DynError};

// 使用jemalloc作为全局内存分配器
#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> Result<(), DynError> {
    run_service(Param::parse()).await
}
