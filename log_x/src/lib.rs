use std::{fs, io, path};

use flexi_logger::{
    Cleanup, Criterion, DeferredNow, Duplicate, FileSpec, FlexiLoggerError, Logger, LoggerHandle,
    Naming,
};
use log::{info, Record};

pub fn init_log(log_dir: &str, log_file: &str) -> Result<LoggerHandle, FlexiLoggerError> {
    // 转换成绝对路径
    let log_dir_path = path::absolute(log_dir)?;
    if !log_dir_path.exists() {
        fs::create_dir_all(log_dir_path.clone())?;
    }
    let log_dir = log_dir_path.as_path().to_str().ok_or(io::Error::new(
        io::ErrorKind::InvalidInput,
        "error parse absolute path of log dir",
    ))?;
    let logger = if cfg!(debug_assertions) {
        Logger::try_with_env_or_str("debug,rustls=error")?
    } else {
        Logger::try_with_env_or_str("info,rustls=error")?
    };
    let log = logger
        .log_to_file(
            FileSpec::default()
                .directory(log_dir)
                .basename(log_file)
                .suffix(""),
        )
        .duplicate_to_stdout(Duplicate::All)
        .rotate(
            Criterion::Size(10_000_000), // 例如, 每 10MB 切割
            Naming::Timestamps,
            Cleanup::KeepLogFiles(3), // 保留最新的3个日志文件
        )
        .append()
        .format(my_format)
        .create_symlink(format!("{}/{}", log_dir, log_file))
        .start();
    let symlink_path = log_dir_path.join(log_file);
    let symlink_path = symlink_path
        .to_str()
        .ok_or(io::Error::new(io::ErrorKind::InvalidData, "cannot parse"))?;
    info!("log is output to {}", symlink_path);
    log
}

fn my_format(
    w: &mut dyn std::io::Write,
    now: &mut DeferredNow,
    record: &Record,
) -> Result<(), std::io::Error> {
    write!(
        w,
        "{} [{}] [{}:{}] {}",
        // now.format("%Y-%m-%d %H:%M:%S%.6f"),
        now.format("%Y-%m-%d %H:%M:%S"),
        record.level(),
        record.file().unwrap_or("<unnamed>"),
        record.line().unwrap_or(0),
        &record.args()
    )
}
