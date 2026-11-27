//! In-process MITM management facade for embedding `rust_http_proxy` (e.g. inside `mitm-desktop`)
//! without routing management requests or event streams over loopback HTTP/SSE.

use std::sync::Arc;

use tokio::sync::broadcast::{Receiver, Sender};

use crate::mitm_manager::MitmManager;

pub use crate::mitm_manager::{
    ManagerError, MitmEvent, MitmSettings, MitmSettingsPatch, MitmTarget, RecentProxyRequest, RecordDetail, RecordPage,
    RecordQuery, RecordSummary, TlsErrorGroup, UrlHostGroup, UrlPathGroup,
};
pub use crate::mitm_rules::{HeaderEdit, HeaderOperation, MatchType, RuleMode, StubTrace, UiStubRule};

#[derive(Clone)]
pub struct EmbeddedMitmHandle {
    mitm_manager: Arc<MitmManager>,
    ca_cert_pem: Option<String>,
    shutdown_tx: Sender<()>,
}

impl std::fmt::Debug for EmbeddedMitmHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddedMitmHandle")
            .field("ca_available", &self.ca_cert_pem.is_some())
            .finish()
    }
}

impl EmbeddedMitmHandle {
    pub(crate) fn new(mitm_manager: Arc<MitmManager>, ca_cert_pem: Option<String>, shutdown_tx: Sender<()>) -> Self {
        Self {
            mitm_manager,
            ca_cert_pem,
            shutdown_tx,
        }
    }

    pub(crate) fn shutdown_sender(&self) -> Sender<()> {
        self.shutdown_tx.clone()
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    pub fn ca_cert_pem(&self) -> Option<&str> {
        self.ca_cert_pem.as_deref()
    }

    pub fn settings(&self) -> MitmSettings {
        self.mitm_manager.settings()
    }

    pub async fn patch_settings(&self, patch: MitmSettingsPatch) -> Result<MitmSettings, ManagerError> {
        self.mitm_manager.patch_settings(patch).await
    }

    pub fn targets(&self) -> Vec<MitmTarget> {
        self.mitm_manager.targets()
    }

    pub async fn add_target(&self, suffix: String) -> Result<MitmTarget, ManagerError> {
        self.mitm_manager.add_target(suffix).await
    }

    pub async fn set_target_enabled(&self, id: i64, enabled: bool) -> Result<Option<MitmTarget>, ManagerError> {
        self.mitm_manager.set_target_enabled(id, enabled).await
    }

    pub async fn delete_target(&self, id: i64) -> Result<bool, ManagerError> {
        self.mitm_manager.delete_target(id).await
    }

    pub fn recent_proxy_requests(&self) -> Vec<RecentProxyRequest> {
        self.mitm_manager.recent_proxy_requests()
    }

    pub async fn list_records(&self, query: RecordQuery) -> Result<RecordPage, ManagerError> {
        self.mitm_manager.list_records(query).await
    }

    pub async fn get_record(&self, id: String) -> Result<Option<RecordDetail>, ManagerError> {
        self.mitm_manager.get_record(id).await
    }

    pub async fn groups(&self) -> Result<Vec<UrlHostGroup>, ManagerError> {
        self.mitm_manager.groups().await
    }

    pub async fn tls_errors(&self) -> Result<Vec<TlsErrorGroup>, ManagerError> {
        self.mitm_manager.tls_errors().await
    }

    pub async fn clear_tls_errors(&self) -> Result<(), ManagerError> {
        self.mitm_manager.clear_tls_errors().await
    }

    pub async fn clear_records(&self) -> Result<(), ManagerError> {
        self.mitm_manager.clear_records().await
    }

    pub fn list_stubs(&self) -> serde_json::Value {
        self.mitm_manager.list_stubs()
    }

    pub fn explain_stubs(&self, url: &str) -> Result<serde_json::Value, ManagerError> {
        self.mitm_manager.explain_stubs(url)
    }

    pub async fn save_stub(&self, id: Option<String>, rule: UiStubRule) -> Result<UiStubRule, ManagerError> {
        let manager = self.mitm_manager.clone();
        tokio::task::spawn_blocking(move || manager.save_stub(id, rule))
            .await
            .map_err(|e| ManagerError::Database(e.to_string()))?
    }

    pub async fn delete_stub(&self, id: String) -> Result<(), ManagerError> {
        let manager = self.mitm_manager.clone();
        tokio::task::spawn_blocking(move || manager.delete_stub(&id))
            .await
            .map_err(|e| ManagerError::Database(e.to_string()))?
    }

    pub async fn reorder_stubs(&self, ids: Vec<String>) -> Result<(), ManagerError> {
        let manager = self.mitm_manager.clone();
        tokio::task::spawn_blocking(move || manager.reorder_stubs(ids))
            .await
            .map_err(|e| ManagerError::Database(e.to_string()))?
    }

    pub fn subscribe(&self) -> Receiver<MitmEvent> {
        self.mitm_manager.subscribe()
    }
}
