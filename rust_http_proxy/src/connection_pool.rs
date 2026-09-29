use std::collections::VecDeque;
use std::fmt::Display;
use std::time::{Duration, Instant};

use log::debug;
use lru_time_cache::LruCache;
use tokio::sync::Mutex;

pub(crate) const CONN_EXPIRE_TIMEOUT: Duration = Duration::from_secs(60);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const MAX_POOL_KEYS: usize = 1024;
pub(crate) const MAX_IDLE_HTTP1_PER_KEY: usize = 5;
pub(crate) const MAX_IDLE_HTTP2_PER_KEY: usize = 1;

pub(crate) trait PooledConn {
    fn is_closed(&self) -> bool;
    fn is_ready(&self) -> bool;
}

type IdleQueues<K, C> = LruCache<K, VecDeque<(C, Instant)>>;
type PoolCache<K, C> = std::sync::Arc<Mutex<IdleQueues<K, C>>>;

pub(crate) struct IdlePool<K, C> {
    cache: PoolCache<K, C>,
}

impl<K, C> Clone for IdlePool<K, C> {
    fn clone(&self) -> Self {
        Self {
            cache: self.cache.clone(),
        }
    }
}

impl<K, C> IdlePool<K, C>
where
    K: Clone + Ord + Display + Send + Sync + 'static,
    C: PooledConn + Send + 'static,
{
    pub(crate) fn new() -> Self {
        let pool = Self::without_cleanup();
        pool.spawn_cleanup();
        pool
    }

    fn without_cleanup() -> Self {
        Self {
            cache: std::sync::Arc::new(Mutex::new(LruCache::with_expiry_duration_and_capacity(
                CONN_EXPIRE_TIMEOUT,
                MAX_POOL_KEYS,
            ))),
        }
    }

    fn spawn_cleanup(&self) -> tokio::task::JoinHandle<()> {
        let cache = std::sync::Arc::downgrade(&self.cache);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            loop {
                interval.tick().await;
                let Some(cache) = cache.upgrade() else {
                    break;
                };
                Self::cleanup(&cache).await;
            }
        })
    }

    async fn cleanup(cache: &Mutex<IdleQueues<K, C>>) {
        let mut cache = cache.lock().await;
        let now = Instant::now();
        let mut removed = 0usize;
        let keys = cache.iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
        let mut empty_keys = Vec::new();
        for key in keys {
            if let Some(queue) = cache.get_mut(&key) {
                let before = queue.len();
                queue.retain(|(connection, created_at)| {
                    now.duration_since(*created_at) < CONN_EXPIRE_TIMEOUT && !connection.is_closed()
                });
                removed += before - queue.len();
                if queue.is_empty() {
                    empty_keys.push(key);
                }
            }
        }
        for key in empty_keys {
            cache.remove(&key);
        }
        debug!("Connection cleanup completed: removed {removed} connections in {:?}", now.elapsed());
    }

    pub(crate) async fn take(&self, key: &K) -> Option<C> {
        let mut cache = self.cache.lock().await;
        let Some(queue) = cache.get_mut(key) else {
            debug!("HTTP client for host: {key} not found in cache");
            return None;
        };
        debug!("HTTP client for host: {key} found in cache, len: {}", queue.len());
        while let Some((connection, created_at)) = queue.pop_front() {
            if created_at.elapsed() >= CONN_EXPIRE_TIMEOUT {
                debug!("HTTP connection for host: {key} expired");
                continue;
            }
            if connection.is_closed() {
                debug!("HTTP connection for host: {key} is closed");
                continue;
            }
            if !connection.is_ready() {
                debug!("HTTP connection for host: {key} is not ready");
                continue;
            }
            return Some(connection);
        }
        None
    }

    /// 同一种连接达到上限时，只丢掉队列里最早的那条同类连接。
    pub(crate) async fn insert_same_class(
        &self, key: K, connection: C, max_idle: usize, same_class: impl Fn(&C) -> bool + Send,
    ) {
        let mut cache = self.cache.lock().await;
        let queue = cache.entry(key).or_insert_with(VecDeque::new);
        let same_kind = queue.iter().filter(|(candidate, _)| same_class(candidate)).count();
        if same_kind >= max_idle
            && let Some(index) = queue.iter().position(|(candidate, _)| same_class(candidate))
        {
            queue.remove(index);
        }
        queue.push_back((connection, Instant::now()));
    }

    /// 队列长度达到上限时，从队头丢掉最早的连接，不区分类别。
    pub(crate) async fn insert_oldest(&self, key: K, connection: C, max_idle: usize) {
        let mut cache = self.cache.lock().await;
        let queue = cache.entry(key).or_insert_with(VecDeque::new);
        while queue.len() >= max_idle {
            queue.pop_front();
        }
        queue.push_back((connection, Instant::now()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct FakeConn {
        closed: bool,
        ready: bool,
        class: u8,
    }

    impl PooledConn for FakeConn {
        fn is_closed(&self) -> bool {
            self.closed
        }

        fn is_ready(&self) -> bool {
            self.ready
        }
    }

    fn conn(class: u8) -> FakeConn {
        FakeConn {
            closed: false,
            ready: true,
            class,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cleanup_exits_after_last_pool_owner_is_dropped() {
        let pool = IdlePool::<String, FakeConn>::without_cleanup();
        let cleanup = pool.spawn_cleanup();
        let cache = std::sync::Arc::downgrade(&pool.cache);
        let clone = pool.clone();
        drop(pool);
        tokio::task::yield_now().await;
        assert!(cache.upgrade().is_some());
        assert!(!cleanup.is_finished());
        drop(clone);
        assert!(cache.upgrade().is_none());
        tokio::time::advance(CLEANUP_INTERVAL).await;
        cleanup.await.unwrap();
    }

    #[tokio::test]
    async fn expired_connections_are_neither_reused_nor_retained() {
        let pool = IdlePool::<String, FakeConn>::without_cleanup();
        let expired = Instant::now() - CONN_EXPIRE_TIMEOUT;
        for key in ["take", "cleanup"] {
            pool.cache
                .lock()
                .await
                .insert(key.to_owned(), VecDeque::from([(conn(1), expired)]));
        }
        assert!(pool.take(&"take".to_owned()).await.is_none());
        IdlePool::<String, FakeConn>::cleanup(&pool.cache).await;
        assert!(pool.cache.lock().await.is_empty());
    }

    #[tokio::test]
    async fn same_class_eviction_keeps_other_classes() {
        let pool = IdlePool::<String, FakeConn>::without_cleanup();
        pool.insert_same_class("origin".to_owned(), conn(1), 1, |candidate| candidate.class == 1)
            .await;
        pool.insert_same_class("origin".to_owned(), conn(2), 1, |candidate| candidate.class == 2)
            .await;
        pool.insert_same_class("origin".to_owned(), conn(2), 1, |candidate| candidate.class == 2)
            .await;

        let first = pool.take(&"origin".to_owned()).await.expect("http1 connection");
        let second = pool
            .take(&"origin".to_owned())
            .await
            .expect("replacement http2 connection");
        assert_eq!(first.class, 1);
        assert_eq!(second.class, 2);
        assert!(pool.take(&"origin".to_owned()).await.is_none());
    }

    #[tokio::test]
    async fn oldest_eviction_drops_the_front_of_the_queue() {
        let pool = IdlePool::<String, FakeConn>::without_cleanup();
        pool.insert_oldest("origin".to_owned(), conn(1), 1).await;
        pool.insert_oldest("origin".to_owned(), conn(2), 1).await;

        let kept = pool.take(&"origin".to_owned()).await.expect("newest connection");
        assert_eq!(kept.class, 2);
        assert!(pool.take(&"origin".to_owned()).await.is_none());
    }

    #[tokio::test]
    async fn take_skips_closed_or_unready_connections() {
        let pool = IdlePool::<String, FakeConn>::without_cleanup();
        pool.insert_oldest(
            "origin".to_owned(),
            FakeConn {
                closed: true,
                ready: true,
                class: 1,
            },
            5,
        )
        .await;
        pool.insert_oldest(
            "origin".to_owned(),
            FakeConn {
                closed: false,
                ready: false,
                class: 2,
            },
            5,
        )
        .await;
        pool.insert_oldest("origin".to_owned(), conn(3), 5).await;

        let usable = pool.take(&"origin".to_owned()).await.expect("ready connection");
        assert_eq!(usable.class, 3);
    }
}
