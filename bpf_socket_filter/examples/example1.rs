use std::{thread::sleep, time::Duration};

use bpf_socket_filter as socket_filter;

fn main() {
    let socket_filter = socket_filter::SocketFilter::default();
    loop{
        let value = socket_filter.get_current_outbound_bytes();
        println!("current outbound bytes: {}",value);
        sleep(Duration::from_secs(1));
    }
}