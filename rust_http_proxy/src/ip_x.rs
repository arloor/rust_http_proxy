use std::io;

#[cfg(not(feature = "pnet"))]
pub fn local_ip() -> io::Result<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    socket.local_addr().map(|local_addr| local_addr.ip().to_string())
}

#[cfg(feature = "pnet")]
pub fn local_ip() -> io::Result<String> {
    let all_interfaces = pnet::datalink::interfaces();
    let all_interfaces = all_interfaces
        .iter()
        .filter(|iface| {
            !crate::linux_monitor::IGNORED_INTERFACES
                .iter()
                .any(|&ignored| iface.name.starts_with(ignored))
        })
        .collect::<Vec<_>>();

    let result = all_interfaces
        .iter()
        .find(|interface| interface.is_up() && !interface.is_loopback() && !interface.ips.is_empty())
        .map(|interface| {
            interface
                .ips
                .iter()
                .find(|ip| ip.is_ipv4())
                .map(|ip| ip.ip().to_string())
        });
    match result {
        Some(ip) => ip.ok_or(io::Error::new(io::ErrorKind::NotFound, "No ipv4 found")),
        None => Err(io::Error::new(io::ErrorKind::NotFound, "No ip found")),
    }
}

pub struct SocketAddrFormat<'a>(pub &'a std::net::SocketAddr);

impl std::fmt::Display for SocketAddrFormat<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "https://ip.im/{} {}", self.0.ip().to_canonical(), self.0.port())
    }
}
