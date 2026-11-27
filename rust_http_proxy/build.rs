use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=APP_RELEASE_TAG");
    println!("cargo:rerun-if-env-changed=APP_GIT_SHA");
    println!("cargo:rerun-if-env-changed=APP_GIT_DIRTY");

    emit_git_rerun_hints();

    let pkg_version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let expected_tag = format!("v{pkg_version}");

    let git_sha = env_non_empty("APP_GIT_SHA").or_else(|| git_output(&["rev-parse", "--short=8", "HEAD"]));
    let is_dirty = env_bool("APP_GIT_DIRTY").unwrap_or_else(detect_git_dirty);
    let exact_release_tag = match env_non_empty("APP_RELEASE_TAG") {
        Some(tag) => tag == expected_tag,
        None => head_has_exact_tag(&expected_tag),
    };

    let commits_since_tag = if exact_release_tag {
        None
    } else {
        commits_since_ancestor_tag(&expected_tag)
    };

    let app_version =
        format_app_version(&pkg_version, git_sha.as_deref(), exact_release_tag, commits_since_tag, is_dirty);
    let features = collect_enabled_features();

    println!("cargo:rustc-env=APP_VERSION={app_version}");
    println!("cargo:rustc-env=APP_GIT_SHA={}", git_sha.as_deref().unwrap_or("unknown"));
    println!("cargo:rustc-env=APP_BUILD_FEATURES={features}");
}

fn env_non_empty(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn env_bool(name: &str) -> Option<bool> {
    let raw = env_non_empty(name)?;
    match raw.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Some(true),
        "0" | "false" | "no" => Some(false),
        _ => None,
    }
}

fn git_output(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn git_success(args: &[&str]) -> bool {
    Command::new("git")
        .args(args)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn detect_git_dirty() -> bool {
    git_output(&["status", "--porcelain", "--untracked-files=no"]).is_some()
}

fn head_has_exact_tag(expected_tag: &str) -> bool {
    git_output(&["tag", "--points-at", "HEAD"])
        .map(|tags| tags.lines().any(|line| line.trim() == expected_tag))
        .unwrap_or(false)
}

fn commits_since_ancestor_tag(tag: &str) -> Option<u64> {
    if !git_success(&["merge-base", "--is-ancestor", tag, "HEAD"]) {
        return None;
    }
    let range = format!("{tag}..HEAD");
    git_output(&["rev-list", "--count", &range])?.parse::<u64>().ok()
}

fn emit_git_rerun_hints() {
    let Some(git_dir_raw) = git_output(&["rev-parse", "--absolute-git-dir"]) else {
        return;
    };
    let git_dir = PathBuf::from(git_dir_raw);
    let common_dir = git_output(&["rev-parse", "--git-common-dir"])
        .map(|raw| {
            let path = PathBuf::from(raw);
            if path.is_absolute() {
                path
            } else {
                env::current_dir().map(|cwd| cwd.join(&path)).unwrap_or(path)
            }
        })
        .unwrap_or_else(|| git_dir.clone());

    let head_path = git_dir.join("HEAD");
    emit_rerun_if_exists(&head_path);
    emit_rerun_if_exists(&git_dir.join("index"));
    emit_rerun_if_exists(&common_dir.join("packed-refs"));
    emit_rerun_if_exists(&common_dir.join("refs").join("tags"));

    if let Ok(head_contents) = fs::read_to_string(&head_path) {
        if let Some(reference) = head_contents.trim().strip_prefix("ref: ") {
            emit_rerun_if_exists(&common_dir.join(reference));
        }
    }
}

fn emit_rerun_if_exists(path: &Path) {
    if path.exists() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn format_app_version(
    pkg_version: &str, git_sha: Option<&str>, exact_release_tag: bool, commits_since_tag: Option<u64>, is_dirty: bool,
) -> String {
    if exact_release_tag {
        if is_dirty {
            return match git_sha {
                Some(sha) => format!("{pkg_version}+dirty.g{sha}"),
                None => format!("{pkg_version}+dirty"),
            };
        }
        return pkg_version.to_string();
    }

    match git_sha {
        Some(sha) => {
            let mut metadata = match commits_since_tag {
                Some(count) if count > 0 => format!("dev.{count}.g{sha}"),
                _ => format!("dev.g{sha}"),
            };
            if is_dirty {
                metadata.push_str(".dirty");
            }
            format!("{pkg_version}+{metadata}")
        }
        None => {
            if is_dirty {
                format!("{pkg_version}+dirty")
            } else {
                pkg_version.to_string()
            }
        }
    }
}

fn collect_enabled_features() -> String {
    let mut features = env::vars()
        .filter_map(|(key, _)| key.strip_prefix("CARGO_FEATURE_").map(str::to_ascii_lowercase))
        .filter(|name| name != "default")
        .collect::<Vec<_>>();
    features.sort();
    if features.is_empty() {
        "none".to_string()
    } else {
        features.join(",")
    }
}
