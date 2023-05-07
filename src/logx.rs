use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::encode::pattern::PatternEncoder;
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::config::{Appender, Config, Root};

pub fn init_log(log_path: &str) {
    let window_size = 3; // proxy.log, proxy.log0, proxy.log1, proxy.log2
    let fixed_window_roller =
        FixedWindowRoller::builder().build(format!("{}.{}",log_path,"{}").as_str(), window_size).unwrap();
    let size_limit = 10 * 1024 * 1024; // 10MB as max log file size to roll
    let size_trigger = SizeTrigger::new(size_limit);
    let compound_policy = CompoundPolicy::new(Box::new(size_trigger), Box::new(fixed_window_roller));
    let pattern = "{d} - {l} - {m}{n}";
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .build();

    let file = RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(pattern)))
        .build(log_path, Box::new(compound_policy)).unwrap();
    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .appender(Appender::builder().build("file", Box::new(file)))
        .build(Root::builder().appender("stdout").appender("file").build(LevelFilter::Info))
        .unwrap();

    let _ = log4rs::init_config(config).unwrap();
}