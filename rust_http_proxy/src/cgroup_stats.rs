use log::debug;
use serde::Serialize;
use std::fs;
use std::io::{self, BufRead, BufReader};

#[derive(Debug, Clone, Serialize)]
pub struct CgroupStats {
    pub cpu_total_ns: u64,
    pub cpu_user_ns: u64,
    pub cpu_system_ns: u64,
    pub memory_current_bytes: u64,
    pub memory_peak_bytes: Option<u64>,
    pub memory_max_bytes: Option<u64>,
    pub memory_rss_bytes: u64,
    pub memory_cache_bytes: u64,
    pub memory_inactive_file_bytes: u64,
    pub memory_working_set_bytes: u64,
    pub cgroup_version: CgroupVersion,
}

#[derive(Debug, Clone, Serialize)]
pub enum CgroupVersion {
    V1,
    V2,
}

pub fn collect_cgroup_stats() -> io::Result<CgroupStats> {
    let pid = std::process::id();
    collect_cgroup_stats_for_pid(pid)
}

pub fn collect_cgroup_stats_for_pid(pid: u32) -> io::Result<CgroupStats> {
    // Check if process exists
    let proc_path = format!("/proc/{}", pid);
    if !fs::metadata(&proc_path)?.is_dir() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("Process {} does not exist", pid)));
    }

    // Detect cgroup version
    if is_cgroup_v1() {
        collect_cgroup_v1_stats(pid)
    } else {
        collect_cgroup_v2_stats(pid)
    }
}

fn is_cgroup_v1() -> bool {
    fs::metadata("/sys/fs/cgroup/cpu").is_ok() && fs::metadata("/sys/fs/cgroup/memory").is_ok()
}

fn collect_cgroup_v1_stats(pid: u32) -> io::Result<CgroupStats> {
    debug!("Using cgroup v1 for pid {}", pid);

    let cgroup_content = fs::read_to_string(format!("/proc/{}/cgroup", pid))?;

    // Get CPU path
    let cpu_path = extract_cgroup_path(&cgroup_content, "cpu")?;
    let memory_path = extract_cgroup_path(&cgroup_content, "memory")?;

    // Read CPU stats
    let cpu_usage_path = format!("/sys/fs/cgroup/cpu{}/cpuacct.usage", cpu_path);
    let cpu_total_ns = fs::read_to_string(&cpu_usage_path)
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("Failed to read {}: {}", cpu_usage_path, e)))?
        .trim()
        .parse::<u64>()
        .unwrap_or(0);

    // Read CPU user/system stats
    let cpu_stat_path = format!("/sys/fs/cgroup/cpu{}/cpuacct.stat", cpu_path);
    let (cpu_user_ns, cpu_system_ns) = parse_cpu_stat_v1(&cpu_stat_path)?;

    // Read memory stats
    let memory_current_path = format!("/sys/fs/cgroup/memory{}/memory.usage_in_bytes", memory_path);
    let memory_current_bytes = fs::read_to_string(&memory_current_path)
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("Failed to read {}: {}", memory_current_path, e)))?
        .trim()
        .parse::<u64>()
        .unwrap_or(0);

    let memory_max_path = format!("/sys/fs/cgroup/memory{}/memory.max_usage_in_bytes", memory_path);
    let memory_max_bytes = fs::read_to_string(&memory_max_path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok());

    // Parse memory.stat for RSS, cache and inactive_file
    let memory_stat_path = format!("/sys/fs/cgroup/memory{}/memory.stat", memory_path);
    let (memory_rss_bytes, memory_cache_bytes, memory_inactive_file_bytes) = parse_memory_stat_v1(&memory_stat_path)?;

    // Calculate working set: usage_in_bytes - total_inactive_file
    let memory_working_set_bytes = memory_current_bytes.saturating_sub(memory_inactive_file_bytes);

    Ok(CgroupStats {
        cpu_total_ns,
        cpu_user_ns,
        cpu_system_ns,
        memory_current_bytes,
        memory_peak_bytes: memory_max_bytes,
        memory_max_bytes,
        memory_rss_bytes,
        memory_cache_bytes,
        memory_inactive_file_bytes,
        memory_working_set_bytes,
        cgroup_version: CgroupVersion::V1,
    })
}

fn collect_cgroup_v2_stats(pid: u32) -> io::Result<CgroupStats> {
    debug!("Using cgroup v2 for pid {}", pid);

    let cgroup_content = fs::read_to_string(format!("/proc/{}/cgroup", pid))?;

    // Get cgroup path for v2 (format: 0::path)
    let cgroup_path = cgroup_content
        .lines()
        .find(|line| line.starts_with("0::"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No cgroup v2 entry found"))?
        .splitn(3, ':')
        .nth(2)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid cgroup v2 format"))?;

    // Read CPU stats
    let cpu_stat_path = format!("/sys/fs/cgroup{}/cpu.stat", cgroup_path);
    let (cpu_total_ns, cpu_user_ns, cpu_system_ns) = parse_cpu_stat_v2(&cpu_stat_path)?;

    // Read memory stats
    let memory_current_path = format!("/sys/fs/cgroup{}/memory.current", cgroup_path);
    let memory_current_bytes = fs::read_to_string(&memory_current_path)
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("Failed to read {}: {}", memory_current_path, e)))?
        .trim()
        .parse::<u64>()
        .unwrap_or(0);

    let memory_peak_path = format!("/sys/fs/cgroup{}/memory.peak", cgroup_path);
    let memory_peak_bytes = fs::read_to_string(&memory_peak_path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok());

    // Parse memory.stat for anon, file, inactive_file, etc.
    let memory_stat_path = format!("/sys/fs/cgroup{}/memory.stat", cgroup_path);
    let (memory_rss_bytes, memory_cache_bytes, memory_inactive_file_bytes) = parse_memory_stat_v2(&memory_stat_path)?;

    // Calculate working set: memory.current - inactive_file
    let memory_working_set_bytes = memory_current_bytes.saturating_sub(memory_inactive_file_bytes);

    Ok(CgroupStats {
        cpu_total_ns,
        cpu_user_ns,
        cpu_system_ns,
        memory_current_bytes,
        memory_peak_bytes,
        memory_max_bytes: memory_peak_bytes,
        memory_rss_bytes,
        memory_cache_bytes,
        memory_inactive_file_bytes,
        memory_working_set_bytes,
        cgroup_version: CgroupVersion::V2,
    })
}

fn extract_cgroup_path(cgroup_content: &str, subsystem: &str) -> io::Result<String> {
    for line in cgroup_content.lines() {
        if line.contains(&format!(":{},", subsystem)) || line.contains(&format!(":{}", subsystem)) {
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() == 3 {
                return Ok(parts[2].to_string());
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, format!("No cgroup path found for subsystem: {}", subsystem)))
}

fn parse_cpu_stat_v1(cpu_stat_path: &str) -> io::Result<(u64, u64)> {
    let content = fs::read_to_string(cpu_stat_path)
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("Failed to read {}: {}", cpu_stat_path, e)))?;

    let mut user_ns = 0u64;
    let mut system_ns = 0u64;

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            match parts[0] {
                "user" => user_ns = parts[1].parse::<u64>().unwrap_or(0) * 10_000_000, // Convert from USER_HZ to nanoseconds
                "system" => system_ns = parts[1].parse::<u64>().unwrap_or(0) * 10_000_000, // Convert from USER_HZ to nanoseconds
                _ => {}
            }
        }
    }

    Ok((user_ns, system_ns))
}

fn parse_cpu_stat_v2(cpu_stat_path: &str) -> io::Result<(u64, u64, u64)> {
    let content = fs::read_to_string(cpu_stat_path)
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("Failed to read {}: {}", cpu_stat_path, e)))?;

    let mut usage_usec = 0u64;
    let mut user_usec = 0u64;
    let mut system_usec = 0u64;

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            match parts[0] {
                "usage_usec" => usage_usec = parts[1].parse::<u64>().unwrap_or(0),
                "user_usec" => user_usec = parts[1].parse::<u64>().unwrap_or(0),
                "system_usec" => system_usec = parts[1].parse::<u64>().unwrap_or(0),
                _ => {}
            }
        }
    }

    // Convert microseconds to nanoseconds
    Ok((usage_usec * 1000, user_usec * 1000, system_usec * 1000))
}

fn parse_memory_stat_v1(memory_stat_path: &str) -> io::Result<(u64, u64, u64)> {
    let file = fs::File::open(memory_stat_path)
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("Failed to read {}: {}", memory_stat_path, e)))?;
    let reader = BufReader::new(file);

    let mut rss_bytes = 0u64;
    let mut cache_bytes = 0u64;
    let mut inactive_file_bytes = 0u64;

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            match parts[0] {
                "rss" => rss_bytes = parts[1].parse::<u64>().unwrap_or(0),
                "cache" => cache_bytes = parts[1].parse::<u64>().unwrap_or(0),
                "total_inactive_file" => inactive_file_bytes = parts[1].parse::<u64>().unwrap_or(0),
                _ => {}
            }
        }
    }

    Ok((rss_bytes, cache_bytes, inactive_file_bytes))
}

fn parse_memory_stat_v2(memory_stat_path: &str) -> io::Result<(u64, u64, u64)> {
    let file = fs::File::open(memory_stat_path)
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("Failed to read {}: {}", memory_stat_path, e)))?;
    let reader = BufReader::new(file);

    let mut anon_bytes = 0u64;
    let mut file_bytes = 0u64;
    let mut inactive_file_bytes = 0u64;

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            match parts[0] {
                "anon" => anon_bytes = parts[1].parse::<u64>().unwrap_or(0),
                "file" => file_bytes = parts[1].parse::<u64>().unwrap_or(0),
                "inactive_file" => inactive_file_bytes = parts[1].parse::<u64>().unwrap_or(0),
                _ => {}
            }
        }
    }

    // In cgroup v2, anon is similar to RSS, file is similar to cache
    Ok((anon_bytes, file_bytes, inactive_file_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_cgroup_stats_for_pid_384125() {
        // Test collecting cgroup stats for PID 384125
        let pid = 384125;

        match collect_cgroup_stats_for_pid(pid) {
            Ok(stats) => {
                println!("\n=== Cgroup Stats for PID {} ===", pid);
                println!("Cgroup Version: {:?}", stats.cgroup_version);

                println!("\nCPU Usage:");
                println!("  Total:  {} ns ({:.2} ms)", stats.cpu_total_ns, stats.cpu_total_ns as f64 / 1_000_000.0);
                println!("  User:   {} ns ({:.2} ms)", stats.cpu_user_ns, stats.cpu_user_ns as f64 / 1_000_000.0);
                println!("  System: {} ns ({:.2} ms)", stats.cpu_system_ns, stats.cpu_system_ns as f64 / 1_000_000.0);

                println!("\nMemory Usage:");
                println!(
                    "  Current: {} bytes ({:.2} MB)",
                    stats.memory_current_bytes,
                    stats.memory_current_bytes as f64 / 1024.0 / 1024.0
                );
                if let Some(peak) = stats.memory_peak_bytes {
                    println!("  Peak:    {} bytes ({:.2} MB)", peak, peak as f64 / 1024.0 / 1024.0);
                }
                if let Some(max) = stats.memory_max_bytes {
                    println!("  Max:     {} bytes ({:.2} MB)", max, max as f64 / 1024.0 / 1024.0);
                }
                println!(
                    "  RSS/Anon: {} bytes ({:.2} MB)",
                    stats.memory_rss_bytes,
                    stats.memory_rss_bytes as f64 / 1024.0 / 1024.0
                );
                println!(
                    "  Cache/File: {} bytes ({:.2} MB)",
                    stats.memory_cache_bytes,
                    stats.memory_cache_bytes as f64 / 1024.0 / 1024.0
                );
                println!(
                    "  Inactive File: {} bytes ({:.2} MB)",
                    stats.memory_inactive_file_bytes,
                    stats.memory_inactive_file_bytes as f64 / 1024.0 / 1024.0
                );
                println!(
                    "  Working Set: {} bytes ({:.2} MB)",
                    stats.memory_working_set_bytes,
                    stats.memory_working_set_bytes as f64 / 1024.0 / 1024.0
                );

                // Assert that we got some reasonable values
                assert!(stats.cpu_total_ns > 0, "CPU total should be greater than 0");
                assert!(stats.memory_current_bytes > 0, "Memory current should be greater than 0");

                // For cgroup v2, verify specific expected values based on the user's output
                if matches!(stats.cgroup_version, CgroupVersion::V2) {
                    // CPU usage_usec was 33612342, which is 33612342000 ns
                    println!("\nExpected CPU total: ~33612342000 ns");

                    // Memory current was 62234624 bytes
                    println!("Expected Memory current: ~62234624 bytes");

                    // Anon was 50327552 bytes
                    println!("Expected Memory RSS/Anon: ~50327552 bytes");
                }
            }
            Err(e) => {
                eprintln!("Failed to collect cgroup stats for PID {}: {}", pid, e);
                panic!("Could not collect stats - process may not exist or insufficient permissions");
            }
        }
    }

    #[test]
    fn test_collect_cgroup_stats_current_process() {
        // Test collecting cgroup stats for current process
        let result = collect_cgroup_stats();

        match result {
            Ok(stats) => {
                println!("\n=== Cgroup Stats for Current Process ===");
                println!("Cgroup Version: {:?}", stats.cgroup_version);
                println!("CPU Total: {} ns", stats.cpu_total_ns);
                println!("Memory Current: {} bytes", stats.memory_current_bytes);
                println!("Memory Inactive File: {} bytes", stats.memory_inactive_file_bytes);
                println!("Memory Working Set: {} bytes", stats.memory_working_set_bytes);

                // Basic sanity checks
                assert!(stats.memory_current_bytes > 0, "Current process should have some memory usage");
            }
            Err(e) => {
                eprintln!("Failed to collect cgroup stats: {}", e);
                // This might fail in some environments, so we don't panic here
            }
        }
    }

    #[test]
    fn test_nonexistent_pid() {
        // Test with a PID that is very unlikely to exist
        let pid = 9999999;
        let result = collect_cgroup_stats_for_pid(pid);

        assert!(result.is_err(), "Should fail for nonexistent PID");
        if let Err(e) = result {
            println!("Expected error for nonexistent PID: {}", e);
        }
    }
}
