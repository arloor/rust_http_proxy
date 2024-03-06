use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::UdpSocket;

use log::info;

pub(crate) fn ipv6_mapped_to_ipv4(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6_addr) => {
            if v6_addr.segments()[..6] == [0, 0, 0, 0, 0, 0xFFFF] {
                #[cfg(debug_assertions)]
                {
                    // 在 debug 模式下执行
                    info!(
                        "found IPv4-mapped IPv6 address: \"{}\", converting to IPv4",addr
                    );
                }
                // 提取IPv4部分并转换为SocketAddr::V4
                let ip4_bits: [u16; 2] = [
                    v6_addr.segments()[6],
                    v6_addr.segments()[7],
                ];
                Ipv4Addr::new(
                    (ip4_bits[0] >> 8) as u8,
                    ip4_bits[0] as u8,
                    (ip4_bits[1] >> 8) as u8,
                    ip4_bits[1] as u8,
                ).into()

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

pub fn local_ip() -> io::Result<String> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    socket
        .local_addr()
        .map(|local_addr| local_addr.ip().to_string())
}