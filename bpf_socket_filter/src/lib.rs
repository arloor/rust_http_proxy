#![deny(warnings)]
use libc::{
    bind, close, if_nametoindex, sockaddr_ll, socket, AF_PACKET, PF_PACKET, SOCK_CLOEXEC,
    SOCK_NONBLOCK, SOCK_RAW,
};
use prog::*;
use std::os::fd::AsRawFd;
use std::os::unix::io::RawFd;
use std::{ffi::CString, os::fd::AsFd};
//https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/sockfilter.bpf.c
#[path = "bpf/program.skel.rs"]
mod prog;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::MapFlags;
use pnet::datalink;
use std::mem::size_of_val;
use log::{info, warn};

pub struct SocketFilter {
    skel: ProgramSkel<'static>,
}

impl SocketFilter {
    pub fn get_value(&self) -> u64 {
        get_value(&self.skel)
    }
}

impl Default for SocketFilter {
    fn default() -> Self {
        bump_memlock_rlimit().expect("Failed to increase rlimit");
        let skel = open_and_load_socket_filter_prog();
        let all_interfaces = datalink::interfaces();
        // 遍历接口列表
        for iface in all_interfaces {
            if iface.name.starts_with("lo")||iface.name.starts_with("podman")||iface.name.starts_with("veth")||iface.name.starts_with("flannel")||iface.name.starts_with("cni0")||iface.name.starts_with("utun") {
                continue;
            }
            info!("load bpf socket filter for Interface: {}", iface.name);
            set_socket_opt_bpf(&skel, iface.name.as_str());
        }
        SocketFilter { skel }
    }
}

pub fn open_and_load_socket_filter_prog() -> ProgramSkel<'static> {
    let builder = ProgramSkelBuilder::default();

    let open_skel = builder.open().expect("Failed to open BPF program");
    open_skel.load().expect("Failed to load BPF program")
}
type DynError = Box<dyn std::error::Error>;
fn bump_memlock_rlimit() -> Result<(),DynError> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        warn!("Failed to increase rlimit");
    }

    Ok(())
}

pub fn set_socket_opt_bpf(skel: &ProgramSkel<'static>, name: &str) {
    unsafe {
        let sock = open_raw_sock(name).expect("Failed to open raw socket");

        let prog_fd = skel.progs().bpf_program().as_fd().as_raw_fd();
        let value = &prog_fd as *const i32;
        let option_len = size_of_val(&prog_fd) as libc::socklen_t;

        let sockopt = libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_BPF,
            value as *const libc::c_void,
            option_len,
        );
        assert_eq!(sockopt, 0, "Failed to set socket option");
    };
}

pub fn get_value(skel: &ProgramSkel<'static>) -> u64 {
    let maps = skel.maps();
    let map = maps.map();

    let key = unsafe { plain::as_bytes(&(libc::IPPROTO_ICMP as u32)) };
    let mut value: u64 = 0;
    if let Ok(Some(buf)) = map.lookup(key, MapFlags::ANY) {
        plain::copy_from_bytes(&mut value, &buf).expect("Invalid buffer");
    }
    value
}

pub fn open_raw_sock(name: &str) -> Result<RawFd, String> {
    unsafe {
        let protocol = (libc::ETH_P_ALL as libc::c_short).to_be() as libc::c_int;
        let sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
        if sock < 0 {
            return Err("Failed to create raw socket".to_string());
        }

        let name_cstring = CString::new(name).unwrap();
        let sll = sockaddr_ll {
            sll_family: AF_PACKET as u16,
            sll_protocol: protocol as u16,
            sll_ifindex: if_nametoindex(name_cstring.as_ptr()) as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };

        if bind(
            sock,
            &sll as *const _ as *const _,
            std::mem::size_of::<sockaddr_ll>() as u32,
        ) < 0
        {
            let err = CString::new("Failed to bind to interface: ".to_string() + name).unwrap();
            close(sock);
            return Err(err.to_str().unwrap().to_string()
                + ": "
                + &std::io::Error::last_os_error().to_string());
        }

        Ok(sock)
    }
}
