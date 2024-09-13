use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub(crate) struct LocationConfig {
    #[serde(default = "root")]
    pub(crate) location: String,
    pub(crate) upstream: Upstream,
}

impl std::cmp::PartialOrd for LocationConfig {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for LocationConfig {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.location.cmp(&other.location).reverse() // 越长越优先
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, PartialOrd)]
pub(crate) struct Upstream {
    pub(crate) scheme_and_authority: String, // https://google.com
    #[serde(default = "root")]
    pub(crate) replacement: String, // /
    #[serde(default = "default_version")]
    pub(crate) version: Version,
}

// 定义默认值函数
fn default_version() -> Version {
    Version::Auto
}

fn root() -> String {
    "/".to_owned()
}

#[derive(PartialEq, PartialOrd, Copy, Clone, Eq, Ord, Hash, Serialize, Deserialize)]
pub(crate) enum Version {
    #[serde(rename = "H1")]
    H1,
    #[serde(rename = "H2")]
    H2,
    #[serde(rename = "AUTO")]
    Auto,
}
