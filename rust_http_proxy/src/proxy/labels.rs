use std::fmt::{Display, Formatter};

use prometheus_client::encoding::EncodeLabelSet;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ReqLabels {
    // Use your own enum types to represent label values.
    pub referer: String,
    // Or just a plain string.
    pub path: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet, PartialOrd, Ord)]
pub struct AccessLabel {
    pub client: String,
    pub relay_over_tls: Option<bool>, // 只有bypass时，该字段才为Some
    pub target: String,
    pub username: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet, PartialOrd, Ord)]
pub struct TunnelHandshakeLabel {
    pub target: String,
    // pub final_target: Option<String>, // 是否是通过bypass中继的
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet, PartialOrd, Ord)]
pub struct ReverseProxyReqLabel {
    pub client: String,
    pub origin: String,
    pub upstream: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct NetDirectionLabel {
    pub direction: &'static str,
}

impl Display for AccessLabel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.client, self.target)
    }
}
