// CounterHyperIO 使用示例
// 这个文件展示如何使用 CounterHyperIO 和 CounterConnector 来为 hyper client 添加流量统计

use http::Uri;
use hyper::body::Incoming;
use hyper_util::client::legacy;
use hyper_util::client::legacy::connect::HttpConnector;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::{counter::Counter, family::Family};
use prometheus_client::registry::Registry;
use std::sync::Arc;

// 假设这些是从 proxy.rs 导入的
use rust_http_proxy::proxy::{
    build_hyper_legacy_client_with_counter, CounterConnector, ReverseProxyTrafficLabel,
};

/// 示例 1: 使用预定义的 ReverseProxyTrafficLabel
pub fn example_with_predefined_label() {
    // 创建 Prometheus registry 和 traffic counter
    let mut registry = Registry::default();
    let traffic_counter: Family<ReverseProxyTrafficLabel, Counter> = Family::default();
    registry.register("http_client_traffic", "HTTP client traffic in bytes", traffic_counter.clone());

    // 创建带流量统计的 client
    let client = build_hyper_legacy_client_with_counter(traffic_counter.clone(), |uri: &Uri| {
        ReverseProxyTrafficLabel {
            target: uri
                .authority()
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        }
    });

    // 使用 client 发送请求
    // let response = client.get(uri).await?;
    // 流量会自动统计到 traffic_counter 中
}

/// 示例 2: 使用自定义 Label
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DetailedTrafficLabel {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl prom_label::Label for DetailedTrafficLabel {}

pub fn example_with_custom_label() {
    let mut registry = Registry::default();
    let traffic_counter: Family<DetailedTrafficLabel, Counter> = Family::default();
    registry.register(
        "http_client_detailed_traffic",
        "HTTP client traffic with detailed labels",
        traffic_counter.clone(),
    );

    // 创建带自定义 label 的 client
    let client = build_hyper_legacy_client_with_counter(traffic_counter.clone(), |uri: &Uri| {
        DetailedTrafficLabel {
            scheme: uri.scheme_str().unwrap_or("http").to_string(),
            host: uri.host().unwrap_or("unknown").to_string(),
            port: uri.port_u16().unwrap_or_else(|| {
                if uri.scheme_str() == Some("https") {
                    443
                } else {
                    80
                }
            }),
        }
    });

    // 使用 client
    // ...
}

/// 示例 3: 在结构体中使用
pub struct MyService {
    // 使用类型别名简化复杂的类型签名
    client: Box<dyn std::any::Any + Send + Sync>,
    traffic_counter: Family<ReverseProxyTrafficLabel, Counter>,
}

impl MyService {
    pub fn new() -> Self {
        let traffic_counter: Family<ReverseProxyTrafficLabel, Counter> = Family::default();

        let client = build_hyper_legacy_client_with_counter(traffic_counter.clone(), |uri: &Uri| {
            ReverseProxyTrafficLabel {
                target: uri
                    .authority()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
            }
        });

        Self {
            client: Box::new(client),
            traffic_counter,
        }
    }

    pub fn get_metrics(&self) -> &Family<ReverseProxyTrafficLabel, Counter> {
        &self.traffic_counter
    }
}

/// 示例 4: 简单的按目标 host 统计
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct HostOnlyLabel {
    pub host: String,
}

impl prom_label::Label for HostOnlyLabel {}

pub fn example_host_only() {
    let traffic_counter: Family<HostOnlyLabel, Counter> = Family::default();

    let client = build_hyper_legacy_client_with_counter(traffic_counter.clone(), |uri: &Uri| {
        HostOnlyLabel {
            host: uri.host().unwrap_or("unknown").to_string(),
        }
    });

    // 使用后，可以查询特定 host 的流量
    // let bytes = traffic_counter
    //     .get_or_create(&HostOnlyLabel { host: "example.com".to_string() })
    //     .get();
}

/// 示例 5: 在异步环境中使用
pub async fn example_async_usage() -> Result<(), Box<dyn std::error::Error>> {
    let traffic_counter: Family<ReverseProxyTrafficLabel, Counter> = Family::default();

    let client = build_hyper_legacy_client_with_counter(traffic_counter.clone(), |uri: &Uri| {
        ReverseProxyTrafficLabel {
            target: uri
                .authority()
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        }
    });

    // 发送请求
    let uri = "https://httpbin.org/get".parse::<Uri>()?;

    // 注意：实际使用需要构建完整的请求
    // let request = http::Request::builder()
    //     .uri(uri)
    //     .body(hyper::body::Body::empty())?;
    // let response = client.request(request).await?;

    // 查看统计
    let label = ReverseProxyTrafficLabel {
        target: "httpbin.org:443".to_string(),
    };
    let bytes = traffic_counter.get_or_create(&label).get();
    println!("Traffic to httpbin.org:443: {} bytes", bytes);

    Ok(())
}

// 注意：由于 CounterHyperIO 目前只统计写入（请求）流量，
// 如果需要统计响应流量，建议在 response body 层面进行额外的包装
