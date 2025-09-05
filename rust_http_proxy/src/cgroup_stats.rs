use std::fs;
use std::io::{self, BufRead, BufReader};
use log::debug;
use serde::Serialize;

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
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Process {} does not exist", pid),
        ));
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
    
    // Parse memory.stat for RSS and cache
    let memory_stat_path = format!("/sys/fs/cgroup/memory{}/memory.stat", memory_path);
    let (memory_rss_bytes, memory_cache_bytes) = parse_memory_stat_v1(&memory_stat_path)?;
    
    Ok(CgroupStats {
        cpu_total_ns,
        cpu_user_ns,
        cpu_system_ns,
        memory_current_bytes,
        memory_peak_bytes: memory_max_bytes,
        memory_max_bytes,
        memory_rss_bytes,
        memory_cache_bytes,
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
    
    // Parse memory.stat for anon, file, etc.
    let memory_stat_path = format!("/sys/fs/cgroup{}/memory.stat", cgroup_path);
    let (memory_rss_bytes, memory_cache_bytes) = parse_memory_stat_v2(&memory_stat_path)?;
    
    Ok(CgroupStats {
        cpu_total_ns,
        cpu_user_ns,
        cpu_system_ns,
        memory_current_bytes,
        memory_peak_bytes,
        memory_max_bytes: memory_peak_bytes,
        memory_rss_bytes,
        memory_cache_bytes,
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
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("No cgroup path found for subsystem: {}", subsystem),
    ))
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

fn parse_memory_stat_v1(memory_stat_path: &str) -> io::Result<(u64, u64)> {
    let file = fs::File::open(memory_stat_path)
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("Failed to read {}: {}", memory_stat_path, e)))?;
    let reader = BufReader::new(file);
    
    let mut rss_bytes = 0u64;
    let mut cache_bytes = 0u64;
    
    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            match parts[0] {
                "rss" => rss_bytes = parts[1].parse::<u64>().unwrap_or(0),
                "cache" => cache_bytes = parts[1].parse::<u64>().unwrap_or(0),
                _ => {}
            }
        }
    }
    
    Ok((rss_bytes, cache_bytes))
}

fn parse_memory_stat_v2(memory_stat_path: &str) -> io::Result<(u64, u64)> {
    let file = fs::File::open(memory_stat_path)
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("Failed to read {}: {}", memory_stat_path, e)))?;
    let reader = BufReader::new(file);
    
    let mut anon_bytes = 0u64;
    let mut file_bytes = 0u64;
    
    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            match parts[0] {
                "anon" => anon_bytes = parts[1].parse::<u64>().unwrap_or(0),
                "file" => file_bytes = parts[1].parse::<u64>().unwrap_or(0),
                _ => {}
            }
        }
    }
    
    // In cgroup v2, anon is similar to RSS, file is similar to cache
    Ok((anon_bytes, file_bytes))
}