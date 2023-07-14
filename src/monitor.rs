use std::collections::VecDeque;
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

    pub fn get_buffer(&self) -> Arc<RwLock<VecDeque<Point>>> {
        return self.buffer.clone();
    }
    pub fn start(&self) {
        // if cfg!(target_os="linux") {
        let to_move = self.buffer.clone();
        tokio::spawn(async move {
            let start = SystemTime::now();
            loop {
                {
                    let mut buffer = to_move.write().await;
                    let i = SystemTime::now().duration_since(start).unwrap().as_secs();
                    let point = Point::new(
                        format!("time {}",i.to_string(),), i,
                    );
                    buffer.push_back(point);
                    if buffer.len() > 60 {
                        buffer.pop_front();
                    }
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        // }
    }
}



