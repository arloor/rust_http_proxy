//! Persisted UI rules supplement the immutable file rules. A match selects one whole rule.
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use hyper::body::Bytes;
use serde::{Deserialize, Serialize};

use crate::mitm::{
    MitmDynamicStub, MitmStubAction, MitmStubResponse, MitmStubUpstreamConfig, parse_dynamic_stub_upstream,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeaderEdit {
    pub op: HeaderOperation,
    pub name: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HeaderOperation {
    Add,
    Set,
    Remove,
}

impl HeaderEdit {
    pub(crate) fn validate(&self) -> Result<(), String> {
        let name = self
            .name
            .parse::<HeaderName>()
            .map_err(|_| format!("无效的 Header 名称：{}", self.name))?;
        // Framing and connection negotiation belong to the HTTP transport.
        if matches!(
            name.as_str(),
            "content-length"
                | "transfer-encoding"
                | "connection"
                | "upgrade"
                | "host"
                | "te"
                | "trailer"
                | "proxy-authorization"
                | "proxy-connection"
                | "keep-alive"
        ) {
            return Err(format!("{} 由 HTTP 传输层管理，不能通过规则修改", self.name));
        }
        if self.op != HeaderOperation::Remove {
            self.value
                .parse::<HeaderValue>()
                .map_err(|_| format!("无效的 Header 值：{}", self.name))?;
        }
        Ok(())
    }
}

pub(crate) fn apply_headers(headers: &mut HeaderMap, edits: &[HeaderEdit]) {
    for edit in edits {
        let Ok(name) = edit.name.parse::<HeaderName>() else {
            continue;
        };
        if edit.op == HeaderOperation::Remove {
            headers.remove(name);
        } else if let Ok(value) = edit.value.parse::<HeaderValue>() {
            match edit.op {
                HeaderOperation::Add => {
                    headers.append(name, value);
                }
                HeaderOperation::Set => {
                    headers.insert(name, value);
                }
                HeaderOperation::Remove => {}
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuleMode {
    Response,
    Upstream,
    Headers,
    ModHeader,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UiStubRule {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub authority: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub url_pattern: String,
    #[serde(skip)]
    pub compiled_url_pattern: Option<regex::Regex>,
    pub enabled: bool,
    pub mode: RuleMode,
    #[serde(default)]
    pub body: String,
    pub status: Option<u16>,
    pub upstream: Option<String>,
    #[serde(default)]
    pub request_headers: Vec<HeaderEdit>,
    #[serde(default)]
    pub response_headers: Vec<HeaderEdit>,
}

impl UiStubRule {
    pub(crate) fn validate(&mut self) -> Result<(), String> {
        self.compiled_url_pattern = None;
        if self.mode == RuleMode::ModHeader {
            if self.url_pattern.trim().is_empty() || self.url_pattern.len() > 4096 {
                return Err("URL 正则不能为空，且不能超过 4096 字节".to_owned());
            }
            self.compiled_url_pattern =
                Some(regex::Regex::new(&self.url_pattern).map_err(|error| format!("URL 正则无效：{error}"))?);
            self.authority.clear();
            self.path.clear();
        } else {
            self.authority = self.authority.trim().to_ascii_lowercase();
            let authority = self
                .authority
                .parse::<http::uri::Authority>()
                .map_err(|_| "域名必须是 host:port，不含协议和路径".to_owned())?;
            if authority.host().is_empty() || self.authority.contains('@') || authority.port_u16().is_none() {
                return Err("请填写完整的 host:port，例如 api.example.com:443".to_owned());
            }
            let path = self
                .path
                .parse::<http::uri::PathAndQuery>()
                .map_err(|_| "无效的路径".to_owned())?;
            if !self.path.starts_with('/') || path.query().is_some() || self.path.contains('#') {
                return Err("路径必须以 / 开头，且不包含 query 或 fragment".to_owned());
            }
            self.url_pattern.clear();
        }
        if self.body.len() > 1024 * 1024 {
            return Err("Body 不能超过 1 MiB".to_owned());
        }
        if self.request_headers.len() + self.response_headers.len() > 100 {
            return Err("每条规则最多 100 个 Header 操作".to_owned());
        }
        for edit in self.request_headers.iter_mut().chain(&mut self.response_headers) {
            edit.validate()?;
            if edit.op == HeaderOperation::Remove {
                edit.value.clear();
            }
        }
        match self.mode {
            RuleMode::Response => {
                let code = self.status.unwrap_or(200);
                if !(200..=599).contains(&code) {
                    return Err("响应状态码必须在 200–599 之间".to_owned());
                }
                if matches!(code, 204 | 205 | 304) && !self.body.is_empty() {
                    return Err("204、205、304 响应不能包含 Body".to_owned());
                }
                self.upstream = None;
            }
            RuleMode::Upstream => {
                parse_dynamic_stub_upstream(
                    MitmStubUpstreamConfig::Url(self.upstream.clone().unwrap_or_default()),
                    &self.authority,
                    &self.path,
                )
                .map_err(|e| e.to_string())?;
                self.body.clear();
                self.status = None;
            }
            RuleMode::Headers | RuleMode::ModHeader => {
                if self.request_headers.is_empty() && self.response_headers.is_empty() {
                    return Err("请至少添加一个 Header 操作".to_owned());
                }
                self.body.clear();
                self.status = None;
                self.upstream = None;
            }
        }
        Ok(())
    }

    pub(crate) fn matched(&self) -> MatchedStub {
        let action = match self.mode {
            RuleMode::Response => Some(MitmStubAction::Static(MitmStubResponse {
                status: StatusCode::from_u16(self.status.unwrap_or(200)).unwrap_or(StatusCode::OK),
                body: Bytes::from(self.body.clone()),
                headers: Vec::new(),
            })),
            RuleMode::Upstream => parse_dynamic_stub_upstream(
                MitmStubUpstreamConfig::Url(self.upstream.clone().unwrap_or_default()),
                &self.authority,
                &self.path,
            )
            .ok()
            .map(|upstream| MitmStubAction::Dynamic(MitmDynamicStub { upstream })),
            RuleMode::Headers | RuleMode::ModHeader => None,
        };
        MatchedStub {
            action,
            trace: StubTrace {
                source: "ui".to_owned(),
                mode: self.mode,
                rule_id: self.id.clone(),
                request_headers: self.request_headers.clone(),
                response_headers: self.response_headers.clone(),
                upstream: self.upstream.clone(),
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct StubTrace {
    pub source: String,
    pub mode: RuleMode,
    pub rule_id: String,
    pub request_headers: Vec<HeaderEdit>,
    pub response_headers: Vec<HeaderEdit>,
    pub upstream: Option<String>,
}

pub(crate) struct MatchedStub {
    pub action: Option<MitmStubAction>,
    pub trace: StubTrace,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_operations_preserve_append_and_replace_semantics() -> Result<(), crate::DynError> {
        let mut headers = HeaderMap::new();
        headers.append("x-test", HeaderValue::from_static("original"));
        headers.append("x-delete", HeaderValue::from_static("one"));
        headers.append("x-delete", HeaderValue::from_static("two"));
        let edits = vec![
            HeaderEdit {
                op: HeaderOperation::Add,
                name: "X-Test".into(),
                value: "extra".into(),
            },
            HeaderEdit {
                op: HeaderOperation::Remove,
                name: "X-Delete".into(),
                value: String::new(),
            },
        ];
        for edit in &edits {
            edit.validate()?;
        }
        apply_headers(&mut headers, &edits);
        assert_eq!(headers.get_all("x-test").iter().count(), 2);
        assert!(!headers.contains_key("x-delete"));
        apply_headers(
            &mut headers,
            &[HeaderEdit {
                op: HeaderOperation::Set,
                name: "x-test".into(),
                value: "replacement".into(),
            }],
        );
        assert_eq!(headers.get_all("x-test").iter().count(), 1);
        assert_eq!(headers["x-test"], "replacement");
        for name in [
            "Host",
            "Content-Length",
            "transfer-encoding",
            "connection",
            "invalid name",
        ] {
            assert!(
                HeaderEdit {
                    op: HeaderOperation::Set,
                    name: name.into(),
                    value: "x".into()
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            HeaderEdit {
                op: HeaderOperation::Add,
                name: "x-test".into(),
                value: "a\r\nb".into()
            }
            .validate()
            .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn mod_header_matches_full_url_and_recompiles_after_restart() -> Result<(), crate::DynError> {
        use crate::mitm_manager::MitmManager;
        let dir = crate::e2e_test_support::unique_temp_dir("mod_header_regex")?;
        let db = dir.join("rules.sqlite3");
        let manager = MitmManager::open(db.clone(), true, &[], false, 100, 1024)?;
        let rule: UiStubRule = serde_json::from_value(serde_json::json!({
            "mode":"mod_header", "enabled":true, "url_pattern":r"^https://api\.example\.com/(users|items)/[0-9]+\?debug=1$",
            "body":"discard", "status":201, "upstream":"http://unused",
            "request_headers":[{"op":"set", "name":"x-test", "value":"yes"}]
        }))?;
        let saved = manager.save_stub(None, rule.clone())?;
        assert!(saved.body.is_empty() && saved.status.is_none() && saved.upstream.is_none());
        assert!(manager.save_stub(None, rule.clone()).is_err());
        let mut invalid = rule;
        invalid.url_pattern = "[".into();
        assert!(manager.save_stub(None, invalid).is_err());
        drop(manager);
        let reopened = MitmManager::open(db, true, &[], false, 100, 1024)?;
        for url in [
            "https://api.example.com/users/12?debug=1",
            "https://api.example.com/items/9?debug=1",
        ] {
            let matched = reopened
                .find_ui_stub("unused:443", "/unused", url)
                .ok_or("regex did not match")?;
            assert!(matched.action.is_none());
            assert_eq!(matched.trace.mode, RuleMode::ModHeader);
        }
        for url in [
            "https://api.example.com/users/12?debug=0",
            "https://other.example.com/users/12?debug=1",
            "https://api.example.com/users/name?debug=1",
        ] {
            assert!(reopened.find_ui_stub("api.example.com:443", "/users/12", url).is_none());
        }
        Ok(())
    }

    #[tokio::test]
    async fn ui_rules_persist_and_file_rules_win_without_mutating_ui() -> Result<(), crate::DynError> {
        use crate::mitm_manager::MitmManager;
        let dir = crate::e2e_test_support::unique_temp_dir("ui_stub_rules")?;
        let db = dir.join("rules.sqlite3");
        let manager = MitmManager::open(db.clone(), true, &[], false, 100, 1024)?;
        let rule: UiStubRule = serde_json::from_value(serde_json::json!({
            "authority":"LOCALHOST:443", "path":"/test", "enabled":true, "mode":"response", "body":"UI body", "status":201
        }))?;
        let saved = manager.save_stub(None, rule.clone())?;
        assert!(manager.save_stub(None, rule).is_err());
        std::fs::write(dir.join("body.txt"), "file body")?;
        std::fs::write(dir.join("stubs.yaml"), "localhost:443:\n  - path: /test\n    body_file: body.txt\n")?;
        let file = crate::mitm::parse_mitm_stub_specs(&Some(dir.join("stubs.yaml").to_string_lossy().into_owned()))?;
        manager.set_file_stubs(file.clone());
        let matched = file
            .matched("localhost:443", "/test")
            .or_else(|| manager.find_ui_stub("localhost:443", "/test", "https://localhost/test"))
            .ok_or("no match")?;
        assert_eq!(matched.trace.source, "file");
        assert_eq!(manager.list_stubs()["ui"][0]["body"], "UI body");
        let reopened = MitmManager::open(db, true, &[], false, 100, 1024)?;
        assert_eq!(reopened.list_stubs()["ui"][0]["id"], saved.id);
        let mut disabled = saved.clone();
        disabled.enabled = false;
        reopened.save_stub(Some(saved.id.clone()), disabled)?;
        assert!(
            reopened
                .find_ui_stub("localhost:443", "/test", "https://localhost/test")
                .is_none()
        );
        reopened.delete_stub(&saved.id)?;
        assert_eq!(reopened.list_stubs()["ui"].as_array().map(Vec::len), Some(0));
        assert!(reopened.delete_stub("file:localhost:443:0").is_err());
        Ok(())
    }
}
