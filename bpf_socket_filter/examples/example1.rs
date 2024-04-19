use std::{thread::sleep, time::Duration};

extern crate bpf_socket_filter as socket_filter;

fn main() {
    let mut skel = socket_filter::open_and_load_socket_filter_prog();
    socket_filter::set_socket_opt_bpf(&skel, "ens5");
    socket_filter::set_socket_opt_bpf(&skel, "lo");
    loop{
        let value = socket_filter::get_value(&mut skel);
        println!("{}",value);
        sleep(Duration::from_secs(1));
    }
}