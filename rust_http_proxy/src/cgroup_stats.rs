use log::debug;
use serde::Serialize;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const V1_UNLIMITED_THRESHOLD: u64 = i64::MAX as u64 - 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CgroupVersion {
    V1,
    V2,
}

#[derive(Debug, Clone)]
struct ControllerPath {
    version: CgroupVersion,
    directory: PathBuf,
}

#[derive(Debug, Clone)]
pub struct CgroupPaths {
    cpu: Option<ControllerPath>,
    memory: Option<ControllerPath>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CgroupCpuStats {
    pub total_ns: u64,
    pub user_ns: u64,
    pub system_ns: u64,
    pub cgroup_version: CgroupVersion,
}

#[derive(Debug, Clone, Serialize)]
pub struct CgroupMemoryStats {
    pub current_bytes: u64,
    pub peak_bytes: Option<u64>,
    pub limit_bytes: Option<u64>,
    pub anon_bytes: u64,
    pub active_file_bytes: u64,
    pub inactive_file_bytes: u64,
    pub kernel_bytes: Option<u64>,
    pub working_set_bytes: u64,
    pub cgroup_version: CgroupVersion,
}

#[derive(Debug)]
struct CgroupMount {
    version: CgroupVersion,
    root: PathBuf,
    mount_point: PathBuf,
    controllers: Vec<String>,
}

#[derive(Debug)]
struct CgroupMembership {
    controllers: Vec<String>,
    path: PathBuf,
}

pub fn discover_cgroup_paths() -> io::Result<CgroupPaths> {
    discover_cgroup_paths_for_pid(std::process::id())
}

pub fn discover_cgroup_paths_for_pid(pid: u32) -> io::Result<CgroupPaths> {
    let cgroup_content = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    let mountinfo_content = fs::read_to_string("/proc/self/mountinfo")?;
    discover_cgroup_paths_from(&cgroup_content, &mountinfo_content)
}

pub fn collect_cgroup_cpu_stats(paths: &CgroupPaths) -> io::Result<CgroupCpuStats> {
    let controller = paths
        .cpu
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "CPU cgroup controller is not mounted"))?;

    debug!("Collecting cgroup {:?} CPU stats from {}", controller.version, controller.directory.display());
    match controller.version {
        CgroupVersion::V1 => collect_cgroup_v1_cpu_stats(&controller.directory),
        CgroupVersion::V2 => collect_cgroup_v2_cpu_stats(&controller.directory),
    }
}

pub fn collect_cgroup_memory_stats(paths: &CgroupPaths) -> io::Result<CgroupMemoryStats> {
    let controller = paths
        .memory
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "memory cgroup controller is not mounted"))?;

    debug!("Collecting cgroup {:?} memory stats from {}", controller.version, controller.directory.display());
    match controller.version {
        CgroupVersion::V1 => collect_cgroup_v1_memory_stats(&controller.directory),
        CgroupVersion::V2 => collect_cgroup_v2_memory_stats(&controller.directory),
    }
}

fn discover_cgroup_paths_from(cgroup_content: &str, mountinfo_content: &str) -> io::Result<CgroupPaths> {
    let memberships = parse_cgroup_memberships(cgroup_content)?;
    let mounts = parse_cgroup_mounts(mountinfo_content)?;

    let unified = memberships
        .iter()
        .find(|entry| entry.controllers.is_empty())
        .and_then(|membership| {
            mounts
                .iter()
                .find(|mount| mount.version == CgroupVersion::V2)
                .map(|mount| ControllerPath {
                    version: CgroupVersion::V2,
                    directory: resolve_cgroup_directory(mount, &membership.path),
                })
        });

    // A hybrid host can put a controller on v1 while retaining a v2 unified
    // hierarchy for other controllers. Resolve CPU and memory independently.
    let cpu = resolve_v1_controller("cpuacct", &memberships, &mounts).or_else(|| unified.clone());
    let memory = resolve_v1_controller("memory", &memberships, &mounts).or(unified);
    if cpu.is_none() && memory.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No usable cgroup v1 or v2 mounts found in /proc/self/mountinfo",
        ));
    }

    Ok(CgroupPaths { cpu, memory })
}

fn resolve_v1_controller(
    controller_name: &str, memberships: &[CgroupMembership], mounts: &[CgroupMount],
) -> Option<ControllerPath> {
    let membership = memberships
        .iter()
        .find(|entry| entry.controllers.iter().any(|controller| controller == controller_name))?;
    let mount = mounts.iter().find(|mount| {
        mount.version == CgroupVersion::V1 && mount.controllers.iter().any(|controller| controller == controller_name)
    })?;

    Some(ControllerPath {
        version: CgroupVersion::V1,
        directory: resolve_cgroup_directory(mount, &membership.path),
    })
}

fn resolve_cgroup_directory(mount: &CgroupMount, membership_path: &Path) -> PathBuf {
    let relative = if mount.root == Path::new("/") {
        membership_path.strip_prefix("/").unwrap_or(membership_path)
    } else if let Ok(relative) = membership_path.strip_prefix(&mount.root) {
        relative
    } else {
        // In a cgroup namespace, /proc/<pid>/cgroup is relative to the namespace
        // root while mountinfo still reports the underlying cgroup mount root.
        membership_path.strip_prefix("/").unwrap_or(membership_path)
    };
    mount.mount_point.join(relative)
}

fn parse_cgroup_memberships(content: &str) -> io::Result<Vec<CgroupMembership>> {
    let mut memberships = Vec::new();
    for line in content.lines().filter(|line| !line.trim().is_empty()) {
        let mut parts = line.splitn(3, ':');
        let _hierarchy_id = parts.next();
        let controllers = parts
            .next()
            .ok_or_else(|| invalid_data(format!("Invalid /proc/<pid>/cgroup line: {line}")))?;
        let path = parts
            .next()
            .ok_or_else(|| invalid_data(format!("Invalid /proc/<pid>/cgroup line: {line}")))?;
        memberships.push(CgroupMembership {
            controllers: controllers
                .split(',')
                .filter(|controller| !controller.is_empty())
                .map(str::to_owned)
                .collect(),
            path: PathBuf::from(path),
        });
    }

    if memberships.is_empty() {
        return Err(invalid_data("/proc/<pid>/cgroup contains no cgroup memberships"));
    }
    Ok(memberships)
}

fn parse_cgroup_mounts(content: &str) -> io::Result<Vec<CgroupMount>> {
    let mut mounts = Vec::new();
    for line in content.lines() {
        let Some((mount_fields, filesystem_fields)) = line.split_once(" - ") else {
            continue;
        };
        let mount_fields: Vec<&str> = mount_fields.split_whitespace().collect();
        let filesystem_fields: Vec<&str> = filesystem_fields.split_whitespace().collect();
        if mount_fields.len() < 5 || filesystem_fields.len() < 3 {
            continue;
        }

        let version = match filesystem_fields[0] {
            "cgroup" => CgroupVersion::V1,
            "cgroup2" => CgroupVersion::V2,
            _ => continue,
        };
        let controllers = if version == CgroupVersion::V1 {
            filesystem_fields[2].split(',').map(str::to_owned).collect()
        } else {
            Vec::new()
        };
        mounts.push(CgroupMount {
            version,
            root: PathBuf::from(unescape_mountinfo_path(mount_fields[3])),
            mount_point: PathBuf::from(unescape_mountinfo_path(mount_fields[4])),
            controllers,
        });
    }

    Ok(mounts)
}

fn unescape_mountinfo_path(path: &str) -> String {
    path.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

fn collect_cgroup_v1_cpu_stats(directory: &Path) -> io::Result<CgroupCpuStats> {
    let total_ns = read_required_u64(&directory.join("cpuacct.usage"))?;
    let (user_ns, system_ns) = parse_cpu_stat_v1(&directory.join("cpuacct.stat"))?;
    Ok(CgroupCpuStats {
        total_ns,
        user_ns,
        system_ns,
        cgroup_version: CgroupVersion::V1,
    })
}

fn collect_cgroup_v2_cpu_stats(directory: &Path) -> io::Result<CgroupCpuStats> {
    let (total_ns, user_ns, system_ns) = parse_cpu_stat_v2(&directory.join("cpu.stat"))?;
    Ok(CgroupCpuStats {
        total_ns,
        user_ns,
        system_ns,
        cgroup_version: CgroupVersion::V2,
    })
}

fn collect_cgroup_v1_memory_stats(directory: &Path) -> io::Result<CgroupMemoryStats> {
    let current_bytes = read_required_u64(&directory.join("memory.usage_in_bytes"))?;
    let peak_bytes = read_optional_u64(&directory.join("memory.max_usage_in_bytes"))?;
    let limit_bytes = read_required_u64(&directory.join("memory.limit_in_bytes"))?;
    let limit_bytes = (limit_bytes < V1_UNLIMITED_THRESHOLD).then_some(limit_bytes);
    let hierarchy_enabled = read_optional_u64(&directory.join("memory.use_hierarchy"))?.map(|value| value != 0);
    let (anon_bytes, active_file_bytes, inactive_file_bytes) =
        parse_memory_stat_v1(&directory.join("memory.stat"), hierarchy_enabled)?;
    let kernel_bytes = read_optional_u64(&directory.join("memory.kmem.usage_in_bytes"))?;

    Ok(CgroupMemoryStats {
        current_bytes,
        peak_bytes,
        limit_bytes,
        anon_bytes,
        active_file_bytes,
        inactive_file_bytes,
        kernel_bytes,
        working_set_bytes: current_bytes.saturating_sub(inactive_file_bytes),
        cgroup_version: CgroupVersion::V1,
    })
}

fn collect_cgroup_v2_memory_stats(directory: &Path) -> io::Result<CgroupMemoryStats> {
    let current_bytes = read_required_u64(&directory.join("memory.current"))?;
    let peak_bytes = read_optional_u64(&directory.join("memory.peak"))?;
    let limit_bytes = read_memory_limit_v2(&directory.join("memory.max"))?;
    let (anon_bytes, active_file_bytes, inactive_file_bytes, kernel_bytes) =
        parse_memory_stat_v2(&directory.join("memory.stat"))?;

    Ok(CgroupMemoryStats {
        current_bytes,
        peak_bytes,
        limit_bytes,
        anon_bytes,
        active_file_bytes,
        inactive_file_bytes,
        kernel_bytes,
        working_set_bytes: current_bytes.saturating_sub(inactive_file_bytes),
        cgroup_version: CgroupVersion::V2,
    })
}

fn read_required_u64(path: &Path) -> io::Result<u64> {
    let content = fs::read_to_string(path).map_err(|error| contextual_io_error(path, error))?;
    parse_u64(content.trim(), &path.display().to_string())
}

fn read_optional_u64(path: &Path) -> io::Result<Option<u64>> {
    match fs::read_to_string(path) {
        Ok(content) => parse_u64(content.trim(), &path.display().to_string()).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(contextual_io_error(path, error)),
    }
}

fn read_memory_limit_v2(path: &Path) -> io::Result<Option<u64>> {
    let content = fs::read_to_string(path).map_err(|error| contextual_io_error(path, error))?;
    parse_memory_limit_v2(content.trim(), &path.display().to_string())
}

fn parse_memory_limit_v2(value: &str, source: &str) -> io::Result<Option<u64>> {
    if value == "max" {
        Ok(None)
    } else {
        parse_u64(value, source).map(Some)
    }
}

fn parse_cpu_stat_v1(path: &Path) -> io::Result<(u64, u64)> {
    let content = fs::read_to_string(path).map_err(|error| contextual_io_error(path, error))?;
    let user_ticks = required_key(&content, "user", path)?;
    let system_ticks = required_key(&content, "system", path)?;
    let user_ns = user_ticks
        .checked_mul(10_000_000)
        .ok_or_else(|| invalid_data(format!("user CPU time overflows nanoseconds in {}", path.display())))?;
    let system_ns = system_ticks
        .checked_mul(10_000_000)
        .ok_or_else(|| invalid_data(format!("system CPU time overflows nanoseconds in {}", path.display())))?;
    Ok((user_ns, system_ns))
}

fn parse_cpu_stat_v2(path: &Path) -> io::Result<(u64, u64, u64)> {
    let content = fs::read_to_string(path).map_err(|error| contextual_io_error(path, error))?;
    let usage_usec = required_key(&content, "usage_usec", path)?;
    let user_usec = required_key(&content, "user_usec", path)?;
    let system_usec = required_key(&content, "system_usec", path)?;
    Ok((
        usec_to_ns(usage_usec, "usage_usec", path)?,
        usec_to_ns(user_usec, "user_usec", path)?,
        usec_to_ns(system_usec, "system_usec", path)?,
    ))
}

fn usec_to_ns(value: u64, field: &str, path: &Path) -> io::Result<u64> {
    value
        .checked_mul(1000)
        .ok_or_else(|| invalid_data(format!("{field} overflows nanoseconds in {}", path.display())))
}

fn parse_memory_stat_v1(path: &Path, hierarchy_enabled: Option<bool>) -> io::Result<(u64, u64, u64)> {
    let content = fs::read_to_string(path).map_err(|error| contextual_io_error(path, error))?;
    parse_memory_stat_v1_content(&content, path, hierarchy_enabled)
}

fn parse_memory_stat_v1_content(
    content: &str, path: &Path, hierarchy_enabled: Option<bool>,
) -> io::Result<(u64, u64, u64)> {
    let has_hierarchical_fields = ["total_rss", "total_active_file", "total_inactive_file"]
        .iter()
        .all(|key| has_key(content, key));
    let use_hierarchical_fields = hierarchy_enabled.unwrap_or(has_hierarchical_fields);
    let prefix = if use_hierarchical_fields { "total_" } else { "" };

    Ok((
        required_key(content, &format!("{prefix}rss"), path)?,
        required_key(content, &format!("{prefix}active_file"), path)?,
        required_key(content, &format!("{prefix}inactive_file"), path)?,
    ))
}

fn parse_memory_stat_v2(path: &Path) -> io::Result<(u64, u64, u64, Option<u64>)> {
    let content = fs::read_to_string(path).map_err(|error| contextual_io_error(path, error))?;
    Ok((
        required_key(&content, "anon", path)?,
        required_key(&content, "active_file", path)?,
        required_key(&content, "inactive_file", path)?,
        optional_key(&content, "kernel", path)?,
    ))
}

fn has_key(content: &str, key: &str) -> bool {
    content.lines().any(|line| line.split_whitespace().next() == Some(key))
}

fn optional_key(content: &str, key: &str, path: &Path) -> io::Result<Option<u64>> {
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some(key) {
            let value = parts
                .next()
                .ok_or_else(|| invalid_data(format!("Missing value for {key} in {}", path.display())))?;
            return parse_u64(value, &format!("{key} in {}", path.display())).map(Some);
        }
    }
    Ok(None)
}

fn required_key(content: &str, key: &str, path: &Path) -> io::Result<u64> {
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() == Some(key) {
            let value = parts
                .next()
                .ok_or_else(|| invalid_data(format!("Missing value for {key} in {}", path.display())))?;
            return parse_u64(value, &format!("{key} in {}", path.display()));
        }
    }
    Err(invalid_data(format!("Missing required key {key} in {}", path.display())))
}

fn parse_u64(value: &str, source: &str) -> io::Result<u64> {
    value
        .parse::<u64>()
        .map_err(|error| invalid_data(format!("Invalid unsigned integer for {source}: {error}")))
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn contextual_io_error(path: &Path, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("Failed to read {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_combined_v1_controller_mounts() -> io::Result<()> {
        let cgroup = "5:memory:/docker/abc/child\n4:cpuacct,cpu:/docker/abc/child\n";
        let mountinfo = concat!(
            "29 23 0:26 /docker/abc /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n",
            "30 23 0:27 /docker/abc /sys/fs/cgroup/cpu,cpuacct rw - cgroup cgroup rw,cpu,cpuacct\n",
        );

        let paths = discover_cgroup_paths_from(cgroup, mountinfo)?;
        assert_eq!(required_controller(&paths.cpu)?.directory, PathBuf::from("/sys/fs/cgroup/cpu,cpuacct/child"));
        assert_eq!(required_controller(&paths.memory)?.directory, PathBuf::from("/sys/fs/cgroup/memory/child"));
        Ok(())
    }

    #[test]
    fn discovers_namespaced_v2_mount() -> io::Result<()> {
        let cgroup = "0::/\n";
        let mountinfo = "29 23 0:26 /docker/abc /sys/fs/cgroup rw - cgroup2 cgroup rw\n";

        let paths = discover_cgroup_paths_from(cgroup, mountinfo)?;
        assert_eq!(required_controller(&paths.memory)?.directory, PathBuf::from("/sys/fs/cgroup"));
        Ok(())
    }

    #[test]
    fn resolves_hybrid_controllers_independently() -> io::Result<()> {
        let cgroup = "5:memory:/legacy/app\n0::/unified/app\n";
        let mountinfo = concat!(
            "29 23 0:26 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n",
            "30 23 0:27 / /sys/fs/cgroup/unified rw - cgroup2 cgroup rw\n",
        );

        let paths = discover_cgroup_paths_from(cgroup, mountinfo)?;
        assert_eq!(required_controller(&paths.memory)?.version, CgroupVersion::V1);
        assert_eq!(required_controller(&paths.cpu)?.version, CgroupVersion::V2);
        Ok(())
    }

    #[test]
    fn parses_v2_limit_and_rejects_invalid_values() -> io::Result<()> {
        assert_eq!(parse_memory_limit_v2("max", "test")?, None);
        assert_eq!(parse_memory_limit_v2("1048576", "test")?, Some(1_048_576));
        assert!(parse_memory_limit_v2("not-a-number", "test").is_err());
        Ok(())
    }

    #[test]
    fn required_key_rejects_missing_and_invalid_values() -> io::Result<()> {
        let path = Path::new("memory.stat");
        assert_eq!(required_key("anon 42\n", "anon", path)?, 42);
        assert!(required_key("file 42\n", "anon", path).is_err());
        assert!(required_key("anon invalid\n", "anon", path).is_err());
        Ok(())
    }

    #[test]
    fn v1_memory_stat_respects_hierarchy_mode() -> io::Result<()> {
        let path = Path::new("memory.stat");
        let content = concat!(
            "rss 10\n",
            "active_file 20\n",
            "inactive_file 30\n",
            "total_rss 100\n",
            "total_active_file 200\n",
            "total_inactive_file 300\n",
        );

        assert_eq!(parse_memory_stat_v1_content(content, path, Some(false))?, (10, 20, 30));
        assert_eq!(parse_memory_stat_v1_content(content, path, Some(true))?, (100, 200, 300));
        assert_eq!(parse_memory_stat_v1_content(content, path, None)?, (100, 200, 300));
        Ok(())
    }

    #[test]
    fn optional_kernel_key_distinguishes_missing_from_invalid() -> io::Result<()> {
        let path = Path::new("memory.stat");
        assert_eq!(optional_key("kernel 42\n", "kernel", path)?, Some(42));
        assert_eq!(optional_key("anon 42\n", "kernel", path)?, None);
        assert!(optional_key("kernel invalid\n", "kernel", path).is_err());
        Ok(())
    }

    #[test]
    fn collects_current_process_memory_independently() {
        let Ok(paths) = discover_cgroup_paths() else {
            return;
        };
        let Ok(stats) = collect_cgroup_memory_stats(&paths) else {
            return;
        };

        assert!(stats.current_bytes > 0);
        assert!(stats.working_set_bytes <= stats.current_bytes);
        if let Some(limit) = stats.limit_bytes {
            assert!(limit > 0);
        }
    }

    #[test]
    fn nonexistent_pid_returns_error() {
        assert!(discover_cgroup_paths_for_pid(9_999_999).is_err());
    }

    fn required_controller(controller: &Option<ControllerPath>) -> io::Result<&ControllerPath> {
        controller
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "expected controller path in test"))
    }
}
