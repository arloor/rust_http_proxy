use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;

// #[derive(Debug)]
// #[derive()]
// pub struct Point {
//     time: String,
//     value: u64,
// }
//
// impl Point {
//     pub fn to_string(&self) -> String{
//         format!("{}->{:?}",self.time,self.value)
//     }
// }


pub struct Monitor {
    buffer: Arc<RwLock<VecDeque<u64>>>,
}

impl Monitor {
    pub fn new() -> Monitor {
        Monitor {
            buffer: Arc::new(RwLock::new(VecDeque::<u64>::new())),
        }
    }

    pub fn get_buffer(&self) -> Arc<RwLock<VecDeque<u64>>> {
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
                    buffer.push_front(i);
                    if buffer.len() > 60 {
                        buffer.pop_back();
                    }
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        // }
    }
}



