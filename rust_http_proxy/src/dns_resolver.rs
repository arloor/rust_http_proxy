//! 自定义 DNS Resolver，支持根据 IPv6 优先级调整解析结果顺序

use std::io;
use std::net::SocketAddr;
use std::task::{self, Poll};

use hyper_util::client::legacy::connect::dns::{GaiFuture, GaiResolver, Name};
use tower_service::Service;

/// 自定义 DNS Resolver，支持根据 ipv6_first 参数调整地址顺序
#[derive(Clone)]
pub struct CustomGaiDNSResolver {
    inner: GaiResolver,
    ipv6_first: Option<bool>,
}

impl CustomGaiDNSResolver {
    pub fn new(ipv6_first: Option<bool>) -> Self {
        Self {
            inner: GaiResolver::new(),
            ipv6_first,
        }
    }
}

/// 包装 GaiAddrs 以支持地址重排序
pub struct ReorderedAddrs {
    iter: std::vec::IntoIter<SocketAddr>,
}

impl Iterator for ReorderedAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl std::fmt::Debug for ReorderedAddrs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReorderedAddrs").finish()
    }
}

/// Future 包装器，用于重排序解析结果
pub struct ReorderFuture {
    inner: GaiFuture,
    ipv6_first: Option<bool>,
}

impl std::future::Future for ReorderFuture {
    type Output = Result<ReorderedAddrs, io::Error>;

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        match std::pin::Pin::new(&mut self.inner).poll(cx) {
            Poll::Ready(Ok(addrs)) => {
                let mut all_addrs: Vec<SocketAddr> = addrs.collect();

                // 仅当 ipv6_first 为 Some 时才调整顺序，否则保持 DNS 原始顺序
                if let Some(prefer_ipv6) = self.ipv6_first {
                    if prefer_ipv6 {
                        // IPv6 优先：先放所有 IPv6 地址，再放 IPv4 地址
                        all_addrs.sort_by_key(|addr| !addr.is_ipv6());
                    } else {
                        // IPv4 优先：先放所有 IPv4 地址，再放 IPv6 地址
                        all_addrs.sort_by_key(|addr| addr.is_ipv6());
                    }
                }

                Poll::Ready(Ok(ReorderedAddrs {
                    iter: all_addrs.into_iter(),
                }))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Service<Name> for CustomGaiDNSResolver {
    type Response = ReorderedAddrs;
    type Error = io::Error;
    type Future = ReorderFuture;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, name: Name) -> Self::Future {
        ReorderFuture {
            inner: self.inner.call(name),
            ipv6_first: self.ipv6_first,
        }
    }
}
