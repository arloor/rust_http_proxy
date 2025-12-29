# CounterHyperIO 使用说明

## 概述

`CounterHyperIO` 和 `CounterConnector` 是为 hyper HTTP 客户端连接添加流量统计功能的装饰器组件。

## 主要组件

### 1. CounterHyperIO<T, R>

一个包装器，为实现了 `hyper::rt::Read` 和 `hyper::rt::Write` 的 IO 类型添加 Prometheus 计数器功能。

**特点:**

- 实现了 `hyper::rt::Read` - 透传读取操作（由于 API 限制，暂不统计读取字节数）
- 实现了 `hyper::rt::Write` - 在写入时统计字节数
- 实现了 `hyper_util::client::legacy::connect::Connection` - 可用于 hyper legacy client

**泛型参数:**

- `T`: 内部 IO 类型，需要实现 `hyper::rt::Read + hyper::rt::Write`
- `R`: Label 类型，需要实现 `prom_label::Label`

### 2. CounterConnector<C, R, F>

一个 `tower::Service<Uri>` 实现，用于包装 HTTP(S) Connector 并为每个连接添加流量统计。

**特点:**

- 基于 URI 动态生成 Label
- 为每个连接创建 `CounterHyperIO` 包装器
- 实现了 `Clone`，可用于 hyper client 池

**泛型参数:**

- `C`: 内部 Connector 类型
- `R`: Label 类型
- `F`: Label 生成函数 `Fn(&Uri) -> R`

### 3. ReverseProxyTrafficLabel

示例 Label 结构，包含目标地址信息。

## 使用方式

### 基本使用

```rust
use http::Uri;
use prometheus_client::metrics::{counter::Counter, family::Family};

// 1. 创建流量计数器
let traffic_counter: Family<ReverseProxyTrafficLabel, Counter> =
    Family::default();

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
```

### 自定义 Label

你可以创建自己的 Label 结构来满足特定需求：

```rust
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct MyTrafficLabel {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl prom_label::Label for MyTrafficLabel {}

// 使用自定义 label
let client = build_hyper_legacy_client_with_counter(
    my_traffic_counter,
    |uri: &Uri| MyTrafficLabel {
        scheme: uri.scheme_str().unwrap_or("http").to_string(),
        host: uri.host().unwrap_or("unknown").to_string(),
        port: uri.port_u16().unwrap_or(80),
    }
);
```

## 限制和注意事项

### 读取流量统计

由于 `hyper::rt::ReadBufCursor` 的 API 设计（它在 `poll_read` 中被消费），目前无法准确统计读取的字节数。当前实现只统计写入（请求）的流量。

如果需要统计双向流量，建议在更高层（如请求/响应 body 层）进行包装。

### 性能考虑

- 流量统计使用原子操作，开销很小
- Label 的 clone 成本取决于 Label 结构的复杂度
- Prometheus 内部使用 Arc 和 RwLock，对高并发场景友好

### 类型复杂度

使用 `CounterConnector` 会使 client 的类型变得复杂。如果不需要在类型签名中暴露，可以使用 `Box<dyn>` 或者 type alias。

## 代码位置

- `CounterHyperIO`: [proxy.rs](rust_http_proxy/src/proxy.rs#L1057-L1168)
- `CounterConnector`: [proxy.rs](rust_http_proxy/src/proxy.rs#L746-L795)
- `build_hyper_legacy_client_with_counter`: [proxy.rs](rust_http_proxy/src/proxy.rs#L820-L849)

## 示例输出

使用后，Prometheus metrics 会包含类似这样的数据：

```
# HELP proxy_traffic_total Total proxy traffic
# TYPE proxy_traffic_total counter
proxy_traffic{target="example.com:443"} 12345
proxy_traffic{target="api.github.com:443"} 67890
```
