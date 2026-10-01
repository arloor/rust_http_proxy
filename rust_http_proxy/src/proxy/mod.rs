mod connect;
mod forward;
mod handler;
mod http;
mod labels;
mod mitm;
mod padding;
mod parent_connect;
mod reverse;
mod serving;
mod tunnel;

pub use handler::ProxyHandler;
pub use http::{empty_body, full_body};
#[cfg_attr(not(all(target_os = "linux", feature = "bpf")), allow(unused_imports))]
pub use labels::NetDirectionLabel;
pub use labels::{AccessLabel, ReqLabels, ReverseProxyReqLabel, TunnelHandshakeLabel};

pub(crate) use connect::{
    EitherTlsStream, HttpClientStream, build_tls_connector_with_http_alpn, build_tls_connector_with_http1_alpn,
    build_tls_connector_with_http2_alpn, connect_with_preference, tls_server_name, tls_server_name_for_authority,
};
pub(crate) use http::{SchemeHostPort, boxed_io_body, bracket_ipv6_host, origin_form};
pub(crate) use parent_connect::open_parent_tunnel;
pub(crate) use tunnel::promote_websocket_upgrade;
