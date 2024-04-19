use std::{thread::sleep, time::Duration};

extern crate bpf_socket_filter as socket_filter;

fn main() {
    let mut socket_filter = socket_filter::SocketFilter::default();
    loop{
        let value = socket_filter.get_value();
        println!("{}",value);
        sleep(Duration::from_secs(1));
    }
}