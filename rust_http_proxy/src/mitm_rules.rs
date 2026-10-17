//! Persisted UI rules supplement the immutable file rules. Header rules accumulate in order; only one response source is selected.
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use hyper::body::Bytes;
use serde::{Deserialize, Serialize};

use crate::mitm::{
    MitmDynamicStub, MitmStubAction, MitmStubResponse, MitmStubUpstreamConfig, parse_dynamic_stub_upstream,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeaderEdit {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub op: HeaderOperation,
    pub name: String,
    #[serde(default)]
    pub value: String,
}

const fn default_true() -> bool {
    true
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
        if !edit.enabled {
            continue;
        }
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
    /// Legacy input and record traces only: validation rewrites it to `Headers` + `MatchType::Regex`.
    ModHeader,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MatchType {
    /// CONNECT authority plus request path, ignoring the query.
    #[default]
    Exact,
    /// Regex over the full HTTPS URL including the query.
    Regex,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UiStubRule {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub match_type: MatchType,
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
            self.mode = RuleMode::Headers;
            self.match_type = MatchType::Regex;
        }
        if self.match_type == MatchType::Regex {
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
                if self.upstream.as_deref().is_none_or(|url| url.trim().is_empty()) {
                    return Err("请填写替代上游地址，例如 http://127.0.0.1:9010".to_owned());
                }
                self.parse_upstream().map_err(|e| e.to_string())?;
                self.body.clear();
                self.status = None;
            }
            RuleMode::Headers | RuleMode::ModHeader => {
                if self.request_headers.is_empty() && self.response_headers.is_empty() {
                    return Err("转发原始服务时请至少添加一个 Header 修改，否则规则没有效果".to_owned());
                }
                self.body.clear();
                self.status = None;
                self.upstream = None;
            }
        }
        Ok(())
    }

    /// Callers must pass the CONNECT authority, the request path and the full URL of the same request.
    pub(crate) fn matches(&self, authority: &str, path: &str, url: &str) -> bool {
        match self.match_type {
            MatchType::Regex => self
                .compiled_url_pattern
                .as_ref()
                .is_some_and(|pattern| pattern.is_match(url)),
            MatchType::Exact => self.authority.eq_ignore_ascii_case(authority) && self.path == path,
        }
    }

    /// Identical match conditions would make ordering ambiguous, so they share one rule.
    pub(crate) fn same_match(&self, other: &Self) -> bool {
        self.match_type == other.match_type
            && match self.match_type {
                MatchType::Regex => self.url_pattern == other.url_pattern,
                MatchType::Exact => self.authority == other.authority && self.path == other.path,
            }
    }

    fn parse_upstream(&self) -> Result<crate::location::Upstream, crate::DynError> {
        let (label, path) = match self.match_type {
            MatchType::Regex => (self.url_pattern.as_str(), ""),
            MatchType::Exact => (self.authority.as_str(), self.path.as_str()),
        };
        parse_dynamic_stub_upstream(MitmStubUpstreamConfig::Url(self.upstream.clone().unwrap_or_default()), label, path)
    }

    pub(crate) fn matched(&self) -> MatchedStub {
        let action = match self.mode {
            RuleMode::Response => Some(MitmStubAction::Static(MitmStubResponse {
                status: StatusCode::from_u16(self.status.unwrap_or(200)).unwrap_or(StatusCode::OK),
                body: Bytes::from(self.body.clone()),
                headers: Vec::new(),
            })),
            RuleMode::Upstream => self
                .parse_upstream()
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
                rule_ids: vec![self.id.clone()],
                request_headers: self
                    .request_headers
                    .iter()
                    .filter(|edit| edit.enabled)
                    .cloned()
                    .collect(),
                response_headers: self
                    .response_headers
                    .iter()
                    .filter(|edit| edit.enabled)
                    .cloned()
                    .collect(),
                upstream: self.upstream.clone(),
                preapplied_request_headers: 0,
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct StubTrace {
    pub source: String,
    pub mode: RuleMode,
    pub rule_id: String,
    #[serde(default)]
    pub rule_ids: Vec<String>,
    pub request_headers: Vec<HeaderEdit>,
    pub response_headers: Vec<HeaderEdit>,
    pub upstream: Option<String>,
    /// Leading `request_headers` that the action already applied itself (file upstream headers).
    #[serde(skip)]
    pub preapplied_request_headers: usize,
}

pub(crate) struct MatchedStub {
    pub action: Option<MitmStubAction>,
    pub trace: StubTrace,
}

/// Why a rule did or did not take part in handling a request.
#[derive(Clone, Copy, Debug, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Verdict {
    /// Applied and decided the response (static response or alternate upstream).
    Response,
    /// Applied its header edits only.
    Headers,
    /// Matched, but an earlier rule already decided the response, so the whole rule was skipped.
    Shadowed,
    Unmatched,
    Disabled,
}

/// Runs the rule chain: the file match (if any) comes first, then enabled UI rules in list order.
/// Header edits of every applied rule accumulate; only the first response/upstream action wins and any
/// later matching response/upstream rule is skipped entirely. `observe` receives the matched flag and,
/// for shadowed rules, the id of the rule that decided the response.
pub(crate) fn resolve_stubs(
    file: Option<MatchedStub>, rules: &[UiStubRule], authority: &str, path: &str, url: &str,
    mut observe: impl FnMut(&UiStubRule, Verdict, bool, Option<&str>),
) -> Option<MatchedStub> {
    let mut result = file;
    for rule in rules {
        let matched = rule.matches(authority, path, url);
        if !rule.enabled || !matched {
            observe(
                rule,
                if rule.enabled {
                    Verdict::Unmatched
                } else {
                    Verdict::Disabled
                },
                matched,
                None,
            );
            continue;
        }
        let decided_by = result
            .as_ref()
            .filter(|current| current.action.is_some())
            .map(|current| current.trace.rule_id.as_str());
        if let (Some(by), RuleMode::Response | RuleMode::Upstream) = (decided_by, rule.mode) {
            observe(rule, Verdict::Shadowed, true, Some(by));
            continue;
        }
        let next = rule.matched();
        observe(
            rule,
            if next.action.is_some() {
                Verdict::Response
            } else {
                Verdict::Headers
            },
            true,
            None,
        );
        let Some(current) = result.as_mut() else {
            result = Some(next);
            continue;
        };
        if next.action.is_some() {
            current.action = next.action;
            current.trace.mode = next.trace.mode;
            current.trace.rule_id = next.trace.rule_id;
            current.trace.upstream = next.trace.upstream;
        }
        current.trace.rule_ids.extend(next.trace.rule_ids);
        current.trace.request_headers.extend(next.trace.request_headers);
        current.trace.response_headers.extend(next.trace.response_headers);
    }
    result
}

/// A URL entered in the panel, split the same way an intercepted request is matched.
pub(crate) struct StubProbe {
    /// CONNECT-style `host:port`, used by exact rules.
    pub authority: String,
    pub path: String,
    /// Full URL with the default port omitted, used by regex rules.
    pub url: String,
}

impl StubProbe {
    pub(crate) fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim().split('#').next().unwrap_or_default();
        if input.is_empty() {
            return Err("请输入要测试的 URL".to_owned());
        }
        let absolute = if input.contains("://") {
            input.to_owned()
        } else {
            format!("https://{input}")
        };
        let uri = absolute.parse::<http::Uri>().map_err(|_| "无效的 URL".to_owned())?;
        if uri.scheme_str() != Some("https") {
            return Err("MITM 只解密 HTTPS，请输入 https:// 地址".to_owned());
        }
        let authority = uri.authority().ok_or_else(|| "URL 缺少域名".to_owned())?;
        let host = authority.host().to_ascii_lowercase();
        let port = authority.port_u16().unwrap_or(443);
        let path = match uri.path() {
            "" => "/",
            path => path,
        };
        let query = uri.query().map(|query| format!("?{query}")).unwrap_or_default();
        let display_host = if port == 443 {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        Ok(Self {
            authority: format!("{host}:{port}"),
            path: path.to_owned(),
            url: format!("https://{display_host}{path}{query}"),
        })
    }
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
                enabled: true,
                op: HeaderOperation::Add,
                name: "X-Test".into(),
                value: "extra".into(),
            },
            HeaderEdit {
                enabled: false,
                op: HeaderOperation::Set,
                name: "X-Test".into(),
                value: "disabled".into(),
            },
            HeaderEdit {
                enabled: true,
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
                enabled: true,
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
                    enabled: true,
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
                enabled: true,
                op: HeaderOperation::Add,
                name: "x-test".into(),
                value: "a\r\nb".into()
            }
            .validate()
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn legacy_header_edits_default_to_enabled_and_disabled_edits_are_not_traced() -> Result<(), crate::DynError> {
        let edit: HeaderEdit =
            serde_json::from_value(serde_json::json!({"op":"set", "name":"x-legacy", "value":"yes"}))?;
        assert!(edit.enabled);

        let mut rule: UiStubRule = serde_json::from_value(serde_json::json!({
            "mode":"mod_header", "enabled":true, "url_pattern":"example",
            "request_headers":[
                {"op":"set", "name":"x-enabled", "value":"yes"},
                {"enabled":false, "op":"set", "name":"x-disabled", "value":"no"}
            ]
        }))?;
        rule.validate()?;
        let matched = rule.matched();
        assert_eq!(matched.trace.request_headers.len(), 1);
        assert_eq!(matched.trace.request_headers[0].name, "x-enabled");
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
        assert_eq!((saved.mode, saved.match_type), (RuleMode::Headers, MatchType::Regex));
        assert_eq!(serde_json::to_value(&saved)?["mode"], "headers");
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
                .find_stub(None, "unused:443", "/unused", url)
                .ok_or("regex did not match")?;
            assert!(matched.action.is_none());
            assert_eq!(matched.trace.mode, RuleMode::Headers);
        }
        for url in [
            "https://api.example.com/users/12?debug=0",
            "https://other.example.com/users/12?debug=1",
            "https://api.example.com/users/name?debug=1",
        ] {
            assert!(
                reopened
                    .find_stub(None, "api.example.com:443", "/users/12", url)
                    .is_none()
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn match_type_is_independent_of_response_source() -> Result<(), crate::DynError> {
        use crate::mitm_manager::MitmManager;
        let dir = crate::e2e_test_support::unique_temp_dir("match_type_independent")?;
        let manager = MitmManager::open(dir.join("rules.sqlite3"), true, &[], false, 100, 1024)?;
        let regex_response = manager.save_stub(
            None,
            serde_json::from_value(serde_json::json!({
                "match_type":"regex", "mode":"response", "enabled":true,
                "url_pattern":r"^https://api\.example\.com/v[0-9]+/mock", "authority":"stale:443", "path":"/stale",
                "body":"mocked", "status":203
            }))?,
        )?;
        assert!(regex_response.authority.is_empty() && regex_response.path.is_empty());
        let matched = manager
            .find_stub(None, "api.example.com:443", "/v2/mock", "https://api.example.com/v2/mock?x=1")
            .ok_or("regex response rule did not match")?;
        let Some(MitmStubAction::Static(response)) = matched.action else {
            return Err("regex rule should return a static response".into());
        };
        assert_eq!((response.status.as_u16(), response.body.as_ref()), (203, b"mocked".as_slice()));

        let regex_upstream: UiStubRule = serde_json::from_value(serde_json::json!({
            "match_type":"regex", "mode":"upstream", "enabled":true,
            "url_pattern":"^https://other\\.example\\.com/", "upstream":"http://127.0.0.1:9010/base/"
        }))?;
        manager.save_stub(None, regex_upstream)?;
        let matched = manager
            .find_stub(None, "other.example.com:443", "/a", "https://other.example.com/a")
            .ok_or("regex upstream rule did not match")?;
        assert!(matches!(matched.action, Some(MitmStubAction::Dynamic(_))));

        let exact: UiStubRule = serde_json::from_value(serde_json::json!({
            "mode":"response", "enabled":true, "authority":"api.example.com:443", "path":"/same"
        }))?;
        manager.save_stub(None, exact.clone())?;
        let mut same_url_other_mode = exact;
        same_url_other_mode.mode = RuleMode::Headers;
        same_url_other_mode.response_headers = vec![HeaderEdit {
            enabled: true,
            op: HeaderOperation::Set,
            name: "x-test".into(),
            value: "1".into(),
        }];
        assert!(manager.save_stub(None, same_url_other_mode).is_err());

        let missing_upstream: UiStubRule = serde_json::from_value(serde_json::json!({
            "mode":"upstream", "enabled":true, "authority":"api.example.com:443", "path":"/up", "upstream":" "
        }))?;
        assert!(manager.save_stub(None, missing_upstream).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn headers_accumulate_and_reordering_persists() -> Result<(), crate::DynError> {
        use crate::mitm_manager::MitmManager;
        let dir = crate::e2e_test_support::unique_temp_dir("ordered_headers")?;
        let db = dir.join("rules.sqlite3");
        let manager = MitmManager::open(db.clone(), true, &[], false, 100, 1024)?;
        let common = manager.save_stub(
            None,
            serde_json::from_value(serde_json::json!({
                "mode":"mod_header", "enabled":true, "url_pattern":"https://console.example.com/api/",
                "request_headers":[{"enabled":false,"op":"set","name":"x-env","value":"disabled"}],
                "response_headers":[{"op":"set","name":"x-order","value":"common"}]
            }))?,
        )?;
        let response = manager.save_stub(
            None,
            serde_json::from_value(serde_json::json!({
                "mode":"response", "enabled":true, "authority":"console.example.com:443", "path":"/api/region",
                "body":"mock", "status":201,
                "request_headers":[{"op":"set","name":"x-account","value":"mock"}]
            }))?,
        )?;
        let region = manager.save_stub(None, serde_json::from_value(serde_json::json!({
            "mode":"mod_header", "enabled":true, "url_pattern":"https://console.example.com/api/region",
            "request_headers":[{"op":"set","name":"X-Account","value":"region"}],
            "response_headers":[{"op":"set","name":"x-order","value":"region"},{"op":"add","name":"x-order","value":"extra"}]
        }))?)?;
        let matched = manager
            .find_stub(None, "console.example.com:443", "/api/region", "https://console.example.com/api/region?q=1")
            .ok_or("missing match")?;
        assert!(matches!(matched.action, Some(MitmStubAction::Static(_))));
        assert_eq!(matched.trace.rule_id, response.id);
        assert_eq!(matched.trace.rule_ids, vec![common.id.clone(), response.id.clone(), region.id.clone()]);
        let mut headers = HeaderMap::new();
        apply_headers(&mut headers, &matched.trace.request_headers);
        assert_eq!(headers["x-account"], "region");
        assert!(!headers.contains_key("x-env"));
        apply_headers(&mut headers, &matched.trace.response_headers);
        assert_eq!(headers.get_all("x-order").iter().count(), 2);
        assert_eq!(headers["x-order"], "region");
        assert!(manager.reorder_stubs(vec![common.id.clone(); 3]).is_err());
        assert!(
            manager
                .reorder_stubs(vec!["unknown".into(), response.id.clone(), region.id.clone()])
                .is_err()
        );
        assert!(manager.reorder_stubs(vec![]).is_err());
        assert_eq!(manager.list_stubs()["ui"][0]["id"], common.id);
        manager.reorder_stubs(vec![region.id.clone(), response.id.clone(), common.id.clone()])?;
        // Editing a rule must not undo its saved order.
        manager.save_stub(Some(region.id.clone()), region.clone())?;
        drop(manager);
        let reopened = MitmManager::open(db, true, &[], false, 100, 1024)?;
        assert_eq!(reopened.list_stubs()["ui"][0]["id"], region.id);
        let matched = reopened
            .find_stub(None, "console.example.com:443", "/api/region", "https://console.example.com/api/region")
            .ok_or("missing reordered match")?;
        let mut headers = HeaderMap::new();
        apply_headers(&mut headers, &matched.trace.request_headers);
        assert_eq!(headers["x-account"], "mock");
        apply_headers(&mut headers, &matched.trace.response_headers);
        assert_eq!(headers["x-order"], "common");
        assert_eq!(headers.get_all("x-order").iter().count(), 1);
        let mut disabled = region.clone();
        disabled.enabled = false;
        reopened.save_stub(Some(region.id), disabled)?;
        let matched = reopened
            .find_stub(None, "console.example.com:443", "/api/region", "https://console.example.com/api/region")
            .ok_or("missing match")?;
        assert_eq!(matched.trace.rule_ids.len(), 2);
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
        let matched = manager
            .find_stub(file.matched("localhost:443", "/test"), "localhost:443", "/test", "https://localhost/test")
            .ok_or("no match")?;
        assert_eq!(matched.trace.source, "file");
        assert_eq!(matched.trace.rule_ids, vec!["file:localhost:443:0".to_string()]);
        assert_eq!(manager.list_stubs()["ui"][0]["body"], "UI body");
        let reopened = MitmManager::open(db, true, &[], false, 100, 1024)?;
        assert_eq!(reopened.list_stubs()["ui"][0]["id"], saved.id);
        let mut disabled = saved.clone();
        disabled.enabled = false;
        reopened.save_stub(Some(saved.id.clone()), disabled)?;
        assert!(
            reopened
                .find_stub(None, "localhost:443", "/test", "https://localhost/test")
                .is_none()
        );
        reopened.delete_stub(&saved.id)?;
        assert_eq!(reopened.list_stubs()["ui"].as_array().map(Vec::len), Some(0));
        assert!(reopened.delete_stub("file:localhost:443:0").is_err());
        Ok(())
    }

    #[tokio::test]
    async fn file_rule_wins_response_while_ui_header_rules_still_apply() -> Result<(), crate::DynError> {
        use crate::mitm_manager::MitmManager;
        let dir = crate::e2e_test_support::unique_temp_dir("file_and_ui_stub_rules")?;
        let manager = MitmManager::open(dir.join("rules.sqlite3"), true, &[], false, 100, 1024)?;
        let save = |value: serde_json::Value| -> Result<UiStubRule, crate::DynError> {
            Ok(manager.save_stub(None, serde_json::from_value(value)?)?)
        };
        let ui_response = save(serde_json::json!({
            "authority":"api.example.com:443", "path":"/config", "enabled":true, "mode":"response", "body":"ui"
        }))?;
        let ui_headers = save(serde_json::json!({
            "authority":"", "path":"", "match_type":"regex", "url_pattern":"^https://api\\.example\\.com/", "enabled":true,
            "mode":"headers", "response_headers":[{"op":"set","name":"x-ui","value":"1","enabled":true}]
        }))?;
        let ui_disabled = save(serde_json::json!({
            "authority":"api.example.com:443", "path":"/other", "enabled":false, "mode":"headers",
            "request_headers":[{"op":"set","name":"x-off","value":"1","enabled":true}]
        }))?;
        std::fs::write(dir.join("body.json"), "{}")?;
        std::fs::write(dir.join("stubs.yaml"), "api.example.com:443:\n  - path: /config\n    body_file: body.json\n")?;
        let file = crate::mitm::parse_mitm_stub_specs(&Some(dir.join("stubs.yaml").to_string_lossy().into_owned()))?;
        manager.set_file_stubs(file.clone());

        let matched = manager
            .find_stub(
                file.matched("api.example.com:443", "/config"),
                "api.example.com:443",
                "/config",
                "https://api.example.com/config",
            )
            .ok_or("no match")?;
        assert_eq!(matched.trace.source, "file");
        assert_eq!(matched.trace.rule_ids, vec!["file:api.example.com:443:0".to_string(), ui_headers.id.clone()]);
        assert_eq!(matched.trace.response_headers.len(), 1);
        assert!(matches!(matched.action, Some(crate::mitm::MitmStubAction::Static(_))));

        let explained = manager.explain_stubs("api.example.com/config?x=1#frag")?;
        assert_eq!(explained["url"], "https://api.example.com/config?x=1");
        assert_eq!(explained["decided_by"], "file:api.example.com:443:0");
        let verdict = |id: &str| {
            explained["verdicts"]
                .as_array()
                .and_then(|items| items.iter().find(|item| item["id"] == id))
                .cloned()
                .unwrap_or_default()
        };
        assert_eq!(verdict("file:api.example.com:443:0")["verdict"], "response");
        assert_eq!(verdict(&ui_response.id)["verdict"], "shadowed");
        assert_eq!(verdict(&ui_response.id)["by"], "file:api.example.com:443:0");
        assert_eq!(verdict(&ui_headers.id)["verdict"], "headers");
        assert_eq!(verdict(&ui_disabled.id)["verdict"], "disabled");
        assert_eq!(verdict(&ui_disabled.id)["matched"], false);

        let elsewhere = manager.explain_stubs("https://api.example.com/missing")?;
        assert!(elsewhere["decided_by"].is_null());
        assert!(manager.explain_stubs("http://api.example.com/").is_err());
        Ok(())
    }

    #[test]
    fn stub_probe_normalizes_input() {
        let probe = StubProbe::parse(" Example.com/a/b?q=1#x ").expect("probe");
        assert_eq!(probe.authority, "example.com:443");
        assert_eq!(probe.path, "/a/b");
        assert_eq!(probe.url, "https://example.com/a/b?q=1");
        let probe = StubProbe::parse("https://example.com:8443").expect("probe");
        assert_eq!(probe.authority, "example.com:8443");
        assert_eq!(probe.path, "/");
        assert_eq!(probe.url, "https://example.com:8443/");
        assert!(StubProbe::parse("").is_err());
        assert!(StubProbe::parse("ws://example.com/").is_err());
    }
}
