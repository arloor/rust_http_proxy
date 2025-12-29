# CounterHyperIO 实现总结

## 完成的工作

本次实现为 Rust HTTP 代理项目添加了 hyper HTTP 客户端连接的流量统计功能。

### 1. 核心组件

#### CounterHyperIO<T, R>

位置: [proxy.rs](rust_http_proxy/src/proxy.rs#L1057)

**功能:** 为实现 `hyper::rt::Read` 和 `hyper::rt::Write` 的 IO 类型添加 Prometheus 流量统计。

**实现的 Traits:**

- `hyper::rt::Read` - 透传读取操作
- `hyper::rt::Write` - 在写入时统计字节数
- `hyper_util::client::legacy::connect::Connection` - 使其可用于 hyper legacy client

**使用 pin_project_lite 实现:**

```rust
pin_project_lite::pin_project! {
    pub struct CounterHyperIO<T, R> {
        #[pin]
        inner: T,
        traffic_counter: Family<R, Counter>,
        label: R,
    }
}
```

#### CounterConnector<C, R, F>

位置: [proxy.rs](rust_http_proxy/src/proxy.rs#L746)

**功能:** 装饰器模式的 Connector，为每个 HTTP 连接动态生成 label 并添加流量统计。

**特点:**

- 实现了 `tower::Service<Uri>`
- 支持 `Clone`，可用于连接池
- 基于 URI 动态生成 Label（通过函数 F）
- 返回包装后的 `CounterHyperIO`

**泛型参数:**

- `C`: 内部 Connector（如 `HttpsConnector`）
- `R`: Label 类型
- `F`: Label 生成函数 `Fn(&Uri) -> R`

#### ReverseProxyTrafficLabel

位置: [proxy.rs](rust_http_proxy/src/proxy.rs#L801)

**功能:** 示例 Label 结构，包含目标地址信息。

```rust
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ReverseProxyTrafficLabel {
    pub target: String,
}
```

### 2. 辅助函数

#### build_hyper_legacy_client_with_counter

位置: [proxy.rs](rust_http_proxy/src/proxy.rs#L820)

**功能:** 创建带流量统计功能的 hyper legacy client。

**签名:**

```rust
fn build_hyper_legacy_client_with_counter<R, F>(
    traffic_counter: Family<R, Counter>,
    label_fn: F,
) -> legacy::Client<CounterConnector<hyper_rustls::HttpsConnector<HttpConnector>, R, F>, Incoming>
where
    R: prom_label::Label + Clone + Send + Sync + 'static,
    F: Fn(&Uri) -> R + Clone + Send + 'static
```

### 3. 依赖变更

在 `Cargo.toml` 中添加了 `tower` 依赖:

```toml
tower = "0.5"
```

### 4. 文档和示例

- **使用说明:** [COUNTER_HYPER_IO_USAGE.md](COUNTER_HYPER_IO_USAGE.md)
- **代码示例:** [examples/counter_hyper_io_example.rs](examples/counter_hyper_io_example.rs)
- **单元测试:** [proxy.rs::test](rust_http_proxy/src/proxy.rs#L1219)

## 技术要点

### 1. Pin 安全性

使用 `pin_project_lite` 正确处理 Pin 投影，确保内部 IO 类型的 Pin 安全性。

### 2. 异步兼容性

实现了 `hyper::rt::Read/Write`，与 hyper 的异步 IO 模型完全兼容。

### 3. Tower Service

通过实现 `tower::Service<Uri>` 使 `CounterConnector` 可以作为标准的 HTTP connector 使用。

### 4. 类型安全

使用泛型参数确保编译时的类型安全，Label 类型必须实现 `prom_label::Label` trait。

### 5. 线程安全

所有组件都是 `Send + Sync`，可安全用于多线程环境。

## 当前限制

### 读取流量统计

由于 `hyper::rt::ReadBufCursor` 的 API 设计（它在 `poll_read` 中被消费），目前无法准确统计读取的字节数。

**解决方案建议:**

- 当前实现只统计写入（请求）流量
- 如需统计响应流量，可在更高层（response body 层）进行包装

### 类型复杂度

使用 `CounterConnector` 会使 client 类型变得复杂。可通过以下方式缓解：

- 使用 `Box<dyn Any>`
- 使用 type alias
- 在内部使用，不暴露到公共 API

## 使用示例

```rust
use prometheus_client::metrics::{counter::Counter, family::Family};

// 1. 创建流量计数器
let traffic_counter: Family<ReverseProxyTrafficLabel, Counter> = Family::default();

// 2. 创建带计数功能的 client
let client = build_hyper_legacy_client_with_counter(
    traffic_counter.clone(),
    |uri: &Uri| ReverseProxyTrafficLabel {
        target: uri.authority()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
    }
);

// 3. 使用 client 发送请求（流量会自动统计）
let response = client.get(uri).await?;

// 4. 查询统计数据
let bytes = traffic_counter
    .get_or_create(&ReverseProxyTrafficLabel {
        target: "example.com:443".to_string()
    })
    .get();
```

## 测试结果

所有测试通过:

```
running 3 tests
test proxy::test::test_aa ... ok
test proxy::test::test_counter_hyper_io_creation ... ok
test proxy::test::test_reverse_proxy_traffic_label ... ok

test result: ok. 3 passed; 0 failed; 0 ignored
```

## 未来改进方向

1. **双向流量统计:** 研究更好的方法来统计读取流量
2. **性能优化:** 测试高并发场景下的性能影响
3. **更多 Label 示例:** 提供更多实用的 Label 结构
4. **集成测试:** 添加端到端的集成测试
5. **文档完善:** 添加更多使用场景的文档

## 相关文件

- 核心实现: `rust_http_proxy/src/proxy.rs`
- 使用文档: `COUNTER_HYPER_IO_USAGE.md`
- 示例代码: `examples/counter_hyper_io_example.rs`
- 依赖配置: `rust_http_proxy/Cargo.toml`
