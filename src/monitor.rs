use std::collections::VecDeque;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

#[derive(Debug)]
#[derive(Clone)]
pub struct Point {
    pub time: String,
    pub value: u64,
}

impl Point {
    pub fn new(time: String, value: u64) -> Point {
        Point {
            time,
            value,
        }
    }
}


pub struct Monitor {
    buffer: Arc<RwLock<VecDeque<Point>>>,
}

impl Monitor {
    pub fn new() -> Monitor {
        Monitor {
            buffer: Arc::new(RwLock::new(VecDeque::<Point>::new())),
        }
    }
    // Inter-|   Receive                                                |  Transmit
    //  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    //     lo: 199123505  183957    0    0    0     0          0         0 199123505  183957    0    0    0     0       0          0
    //   ens5: 194703959  424303    0    0    0     0          0         0 271636211  425623    0    0    0     0       0          0

    pub fn get_buffer(&self) -> Arc<RwLock<VecDeque<Point>>> {
        return self.buffer.clone();
    }
    pub fn start(&self) {
        if cfg!(target_os="linux") {
            let to_move = self.buffer.clone();
            tokio::spawn(async move {
                let start = SystemTime::now();
                loop {
                    {
                        let mut buffer = to_move.write().await;
                        let i = SystemTime::now().duration_since(start).unwrap().as_secs();
                        if let Ok(mut content) = fs::read_to_string("/proc/net/dev") {
                            content = content.replace("\r\n", "\n");
                            let strs = content.split("\n");
                            for str in strs {
                                let array: Vec<&str> = str.split_whitespace().collect();
                                if array.len() == 17 {
                                    if array.get(0).unwrap().to_string() != "lo:" {
                                        buffer.push_back(Point::new(i.to_string(), array.get(9).unwrap().parse::<u64>().unwrap_or(0)))
                                    }
                                }
                            }
                        }
                        if buffer.len() > 60 {
                            buffer.pop_front();
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            });
        }
    }
}


