use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;

pub(crate) fn _ipv6_mapped_to_ipv4(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6_addr) => {
            if v6_addr.segments()[..6] == [0, 0, 0, 0, 0, 0xFFFF] {
                #[cfg(debug_assertions)]
                log::info!(
                    "found IPv4-mapped IPv6 address: \"{}\", converting to IPv4",
                    addr
                );
                // 提取IPv4部分并转换为SocketAddr::V4
                let ip4_bits: [u16; 2] = [v6_addr.segments()[6], v6_addr.segments()[7]];
                Ipv4Addr::new(
                    (ip4_bits[0] >> 8) as u8,
                    ip4_bits[0] as u8,
                    (ip4_bits[1] >> 8) as u8,
                    ip4_bits[1] as u8,
                )
                .into()
            } else {
                // 不是IPv4映射的IPv6地址，直接返回原地址
                addr
            }
        }
        IpAddr::V4(_) => {
            // 已经是IPv4地址，直接返回
            addr
        }
    }
}

#[cfg(not(feature = "pnet"))]
pub fn local_ip() -> io::Result<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    socket
        .local_addr()
        .map(|local_addr| local_addr.ip().to_string())
}

#[cfg(feature = "pnet")]
pub fn local_ip() -> io::Result<String> {
    let all_interfaces = pnet::datalink::interfaces();
    let all_interfaces = all_interfaces
        .iter()
        .filter(|iface| {
            !crate::net_monitor::IGNORED_INTERFACES
                .iter()
                .any(|&ignored| iface.name.starts_with(ignored))
        })
        .collect::<Vec<_>>();

    let result = all_interfaces
        .iter()
        .find(|interface| {
            interface.is_up() && !interface.is_loopback() && !interface.ips.is_empty()
        })
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

impl<'a> std::fmt::Display for SocketAddrFormat<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "https://ip.im/{} {}",
            self.0.ip().to_canonical(),
            self.0.port()
        )
    }
}
