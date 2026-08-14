mod connect;
mod dump;
mod request;

pub(super) fn host_matches_mitm_suffix(host: &str, suffixes: &[String]) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    suffixes.iter().any(|suffix| {
        host == *suffix
            || host
                .strip_suffix(suffix)
                .map(|prefix| prefix.ends_with('.'))
                .unwrap_or_default()
    })
}
