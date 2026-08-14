mod connect;
mod forward;
mod handler;
mod http;
mod labels;
mod mitm;
mod padding;
mod reverse;
mod serving;
mod tunnel;

pub use handler::ProxyHandler;
pub use http::{empty_body, full_body};
#[cfg_attr(not(all(target_os = "linux", feature = "bpf")), allow(unused_imports))]
pub use labels::NetDirectionLabel;
pub use labels::{AccessLabel, ReqLabels, ReverseProxyReqLabel, TunnelHandshakeLabel};

pub(crate) use connect::{
    EitherTlsStream, HttpClientStream, build_tls_connector, build_tls_connector_with_http_alpn,
    build_tls_connector_with_http1_alpn, connect_with_preference,
};
pub(crate) use http::SchemeHostPort;
pub(crate) use tunnel::spawn_websocket_tunnel;
