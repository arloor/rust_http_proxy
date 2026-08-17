use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use http::{HeaderMap, Version};
use log::{error, warn};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::DynError;

const SCHEMA_VERSION: i64 = 4;
const DEFAULT_PAGE_LIMIT: usize = 100;
const MAX_PAGE_LIMIT: usize = 500;
const MAX_TLS_ERROR_ROWS: i64 = 1000;
const WRITER_FLUSH_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Clone, Debug, Serialize)]
pub(crate) struct MitmSettings {
    pub capture_enabled: bool,
    pub capture_cli_managed: bool,
    pub ca_available: bool,
    pub max_records: usize,
    pub body_limit_bytes: usize,
    pub db_bytes: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MitmSettingsPatch {
    pub capture_enabled: Option<bool>,
    pub max_records: Option<usize>,
    pub body_limit_bytes: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct MitmTarget {
    pub id: i64,
    pub suffix: String,
    pub created_at_ms: i64,
    pub cli_managed: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct RecordStart {
    pub id: String,
    pub started_at_ms: i64,
    pub client_ip: String,
    pub client_port: u16,
    pub proxy_username: String,
    pub authority: String,
    pub host: String,
    pub path: String,
    pub query: Option<String>,
    pub method: String,
    pub request_version: String,
    pub request_headers_json: String,
}

pub(crate) struct RecordMetadata<'a> {
    pub client_ip: String,
    pub client_port: u16,
    pub proxy_username: String,
    pub authority: String,
    pub host: String,
    pub path: String,
    pub query: Option<String>,
    pub method: String,
    pub request_version: Version,
    pub request_headers: &'a HeaderMap,
}

#[derive(Clone, Debug)]
pub(crate) struct ResponseHead {
    pub status: u16,
    pub version: String,
    pub headers_json: String,
    pub body_note: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum BodyDirection {
    Request,
    Response,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RecordSummary {
    pub id: String,
    pub started_at_ms: i64,
    pub completed_at_ms: Option<i64>,
    pub client_ip: String,
    pub client_port: u16,
    pub proxy_username: String,
    pub authority: String,
    pub host: String,
    pub path: String,
    pub query: Option<String>,
    pub method: String,
    pub status: Option<u16>,
    pub duration_ms: Option<i64>,
    pub capture_state: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RecordDetail {
    #[serde(flatten)]
    pub summary: RecordSummary,
    pub request_version: String,
    pub request_headers: serde_json::Value,
    pub request_body: String,
    pub request_body_bytes: i64,
    pub request_body_truncated: bool,
    pub request_body_note: Option<String>,
    pub request_body_image: Option<String>,
    pub response_version: Option<String>,
    pub response_headers: serde_json::Value,
    pub response_body: String,
    pub response_body_bytes: i64,
    pub response_body_truncated: bool,
    pub response_body_note: Option<String>,
    pub response_body_image: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct RecordQuery {
    pub before: Option<i64>,
    pub limit: Option<usize>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub method: Option<String>,
    pub status: Option<u16>,
    pub client_ip: Option<String>,
    pub q: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RecordPage {
    pub records: Vec<RecordSummary>,
    pub next_before: Option<i64>,
    // 数据库中的记录总条数（不受筛选条件影响）
    pub total: i64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct UrlPathGroup {
    pub path: String,
    pub count: i64,
    pub last_seen_ms: i64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct UrlHostGroup {
    pub host: String,
    pub count: i64,
    pub last_seen_ms: i64,
    pub paths: Vec<UrlPathGroup>,
}

// 客户端不信任 MITM CA 导致的 TLS 握手失败，按 authority + 客户端 IP 聚合计数
#[derive(Clone, Debug, Serialize)]
pub(crate) struct TlsErrorGroup {
    pub authority: String,
    pub client_ip: String,
    pub count: i64,
    pub last_seen_ms: i64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct MitmEvent {
    pub kind: &'static str,
    pub record_id: Option<String>,
}

enum StoreCommand {
    Create(RecordStart),
    ResponseHead {
        id: String,
        head: ResponseHead,
    },
    Body {
        id: String,
        direction: BodyDirection,
        chunk: String,
        total_bytes: usize,
        truncated: bool,
    },
    FinishBody {
        id: String,
        direction: BodyDirection,
        note: Option<String>,
        image: Option<String>,
    },
    FinishRecord {
        id: String,
        state: &'static str,
    },
    Error {
        id: String,
        message: String,
    },
    TlsError {
        authority: String,
        client_ip: String,
    },
    StopAllCaptures,
    Clear(mpsc::SyncSender<Result<(), String>>),
}

struct PruneRequest {
    max_records: usize,
    compact: bool,
}

#[derive(Default)]
struct PendingBody {
    request: String,
    response: String,
    request_total: usize,
    response_total: usize,
    request_truncated: bool,
    response_truncated: bool,
    dirty: bool,
}

pub(crate) struct MitmManager {
    db_path: PathBuf,
    ca_available: bool,
    capture_enabled: AtomicBool,
    stored_capture_enabled: AtomicBool,
    capture_cli_managed: bool,
    max_records: AtomicUsize,
    body_limit_bytes: AtomicUsize,
    targets: RwLock<Vec<MitmTarget>>,
    writer_tx: mpsc::Sender<StoreCommand>,
    prune_tx: mpsc::Sender<PruneRequest>,
    events: broadcast::Sender<MitmEvent>,
}

impl MitmManager {
    pub(crate) fn open(
        db_path: PathBuf, ca_available: bool, configured_targets: &[String], cli_capture_enabled: bool,
        seed_max_records: usize, seed_body_limit_bytes: usize,
    ) -> Result<Arc<Self>, DynError> {
        if let Some(parent) = db_path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create MITM database directory {}: {e}", parent.display()))?;
        }
        let connection = open_connection(&db_path)?;
        let cli_suffixes = initialize_schema(
            &connection,
            configured_targets,
            cli_capture_enabled,
            seed_max_records,
            seed_body_limit_bytes,
        )?;
        set_private_permissions(&db_path)?;
        let (stored_capture_enabled, max_records, body_limit_bytes) = load_settings(&connection)?;
        let capture_enabled = cli_capture_enabled || stored_capture_enabled;
        let mut targets = load_targets(&connection)?;
        drop(connection);
        // DB 中没有的 CLI 目标只存在于内存（不落库），负数 id 避免与自增主键冲突
        let mut synthetic_id = 0i64;
        for suffix in &cli_suffixes {
            if !targets.iter().any(|target| &target.suffix == suffix) {
                synthetic_id -= 1;
                targets.push(MitmTarget {
                    id: synthetic_id,
                    suffix: suffix.clone(),
                    created_at_ms: now_ms(),
                    cli_managed: true,
                });
            }
        }
        targets.sort_by(|left, right| left.suffix.cmp(&right.suffix));

        let (writer_tx, writer_rx) = mpsc::channel();
        let (prune_tx, prune_rx) = mpsc::channel();
        let (events, _) = broadcast::channel(1024);
        let manager = Arc::new(Self {
            db_path: db_path.clone(),
            ca_available,
            capture_enabled: AtomicBool::new(capture_enabled),
            stored_capture_enabled: AtomicBool::new(stored_capture_enabled),
            capture_cli_managed: cli_capture_enabled,
            max_records: AtomicUsize::new(max_records),
            body_limit_bytes: AtomicUsize::new(body_limit_bytes),
            targets: RwLock::new(targets),
            writer_tx,
            prune_tx,
            events: events.clone(),
        });

        std::thread::Builder::new()
            .name("mitm-sqlite-writer".to_owned())
            .spawn({
                let db_path = db_path.clone();
                let events = events.clone();
                move || writer_loop(db_path, writer_rx, events)
            })
            .map_err(|e| format!("failed to start MITM SQLite writer: {e}"))?;
        std::thread::Builder::new()
            .name("mitm-sqlite-prune".to_owned())
            .spawn(move || prune_loop(db_path, prune_rx, events))
            .map_err(|e| format!("failed to start MITM SQLite prune worker: {e}"))?;
        Ok(manager)
    }

    pub(crate) fn settings(&self) -> MitmSettings {
        MitmSettings {
            capture_enabled: self.capture_enabled.load(Ordering::Acquire),
            capture_cli_managed: self.capture_cli_managed,
            ca_available: self.ca_available,
            max_records: self.max_records.load(Ordering::Acquire),
            body_limit_bytes: self.body_limit_bytes.load(Ordering::Acquire),
            db_bytes: db_file_bytes(&self.db_path),
        }
    }

    pub(crate) fn capture_enabled(&self) -> bool {
        self.capture_enabled.load(Ordering::Acquire)
    }

    pub(crate) fn body_limit_bytes(&self) -> usize {
        self.body_limit_bytes.load(Ordering::Acquire)
    }

    pub(crate) fn should_mitm(&self, host: &str) -> bool {
        if !self.ca_available {
            return false;
        }
        let host = normalize_host(host);
        self.targets
            .read()
            .map(|targets| targets.iter().any(|target| host_matches_suffix(&host, &target.suffix)))
            .unwrap_or(false)
    }

    pub(crate) fn targets(&self) -> Vec<MitmTarget> {
        self.targets.read().map(|targets| targets.clone()).unwrap_or_default()
    }

    pub(crate) async fn patch_settings(&self, patch: MitmSettingsPatch) -> Result<MitmSettings, ManagerError> {
        if self.capture_cli_managed && patch.capture_enabled.is_some() {
            return Err(ManagerError::Conflict(
                "capture_enabled is managed by --mitm-dump and cannot be changed".to_owned(),
            ));
        }
        if patch.max_records == Some(0) {
            return Err(ManagerError::BadRequest("max_records must be greater than zero".to_owned()));
        }
        if let Some(limit) = patch.body_limit_bytes
            && !(1024..=10 * 1024 * 1024).contains(&limit)
        {
            return Err(ManagerError::BadRequest("body_limit_bytes must be between 1024 and 10485760".to_owned()));
        }

        let current = self.settings();
        let stored_capture = self.stored_capture_enabled.load(Ordering::Acquire);
        let next_stored_capture = patch.capture_enabled.unwrap_or(stored_capture);
        let next_capture = self.capture_cli_managed || next_stored_capture;
        let next_max_records = patch.max_records.unwrap_or(current.max_records);
        let next_body_limit = patch.body_limit_bytes.unwrap_or(current.body_limit_bytes);
        let path = self.db_path.clone();
        run_db(path, move |connection| {
            connection.execute(
                "UPDATE settings SET capture_enabled=?1, max_records=?2, body_limit_bytes=?3 WHERE id=1",
                params![next_stored_capture, next_max_records as i64, next_body_limit as i64],
            )?;
            if current.capture_enabled && !next_capture {
                connection.execute(
                    "UPDATE records SET capture_state='capture_stopped', completed_at_ms=COALESCE(completed_at_ms, ?1) WHERE capture_state='capturing'",
                    [now_ms()],
                )?;
            }
            Ok(())
        })
        .await?;
        self.stored_capture_enabled
            .store(next_stored_capture, Ordering::Release);
        self.capture_enabled.store(next_capture, Ordering::Release);
        self.max_records.store(next_max_records, Ordering::Release);
        self.body_limit_bytes.store(next_body_limit, Ordering::Release);
        if current.capture_enabled && !next_capture {
            self.send(StoreCommand::StopAllCaptures);
        }
        if next_max_records < current.max_records {
            self.request_prune(next_max_records, true);
        }
        self.emit("settings", None);
        Ok(self.settings())
    }

    pub(crate) async fn add_target(&self, suffix: String) -> Result<MitmTarget, ManagerError> {
        let suffix = normalize_suffix(&suffix)
            .ok_or_else(|| ManagerError::BadRequest("target suffix must not be empty".to_owned()))?;
        // 同名 CLI 目标当前仅在内存中时，落库后仍保持 CLI 管理标记
        let keep_cli_managed = self
            .targets
            .read()
            .map(|targets| {
                targets
                    .iter()
                    .any(|target| target.suffix == suffix && target.cli_managed)
            })
            .unwrap_or(false);
        let path = self.db_path.clone();
        let db_suffix = suffix.clone();
        let target = run_db(path, move |connection| {
            let created_at = now_ms();
            connection.execute(
                "INSERT OR IGNORE INTO targets(suffix, created_at_ms, cli_managed) VALUES(?1, ?2, 0)",
                params![db_suffix, created_at],
            )?;
            if keep_cli_managed {
                connection.execute("UPDATE targets SET cli_managed=1 WHERE suffix=?1", [&db_suffix])?;
            }
            connection.query_row(
                "SELECT id, suffix, created_at_ms, cli_managed FROM targets WHERE suffix=?1",
                [&db_suffix],
                |row| {
                    Ok(MitmTarget {
                        id: row.get(0)?,
                        suffix: row.get(1)?,
                        created_at_ms: row.get(2)?,
                        cli_managed: row.get(3)?,
                    })
                },
            )
        })
        .await?;
        if let Ok(mut targets) = self.targets.write() {
            targets.retain(|item| item.suffix != target.suffix);
            targets.push(target.clone());
            targets.sort_by(|left, right| left.suffix.cmp(&right.suffix));
        }
        self.emit("targets", None);
        Ok(target)
    }

    pub(crate) async fn delete_target(&self, id: i64) -> Result<bool, ManagerError> {
        let target = self
            .targets
            .read()
            .ok()
            .and_then(|targets| targets.iter().find(|target| target.id == id).cloned());
        let Some(target) = target else {
            return Ok(false);
        };
        if target.cli_managed {
            return Err(ManagerError::Conflict(
                "target is managed by --mitm-domain-suffix and cannot be deleted".to_owned(),
            ));
        }
        let path = self.db_path.clone();
        let deleted =
            run_db(path, move |connection| Ok(connection.execute("DELETE FROM targets WHERE id=?1", [id])? > 0))
                .await?;
        if deleted {
            if let Ok(mut targets) = self.targets.write() {
                targets.retain(|target| target.id != id);
            }
            self.emit("targets", None);
        }
        Ok(deleted)
    }

    pub(crate) fn begin_record(&self, metadata: RecordMetadata<'_>) -> Option<String> {
        if !self.capture_enabled() {
            return None;
        }
        let id = format!("{:032x}", rand::random::<u128>());
        let record = RecordStart {
            id: id.clone(),
            started_at_ms: now_ms(),
            client_ip: metadata.client_ip,
            client_port: metadata.client_port,
            proxy_username: metadata.proxy_username,
            authority: metadata.authority,
            host: metadata.host,
            path: metadata.path,
            query: metadata.query,
            method: metadata.method,
            request_version: version_label(metadata.request_version).to_owned(),
            request_headers_json: headers_json(metadata.request_headers),
        };
        if self.writer_tx.send(StoreCommand::Create(record)).is_err() {
            error!("MITM SQLite writer stopped; capture record was lost");
            return None;
        }
        Some(id)
    }

    pub(crate) fn response_head(&self, id: &str, head: ResponseHead) {
        self.send(StoreCommand::ResponseHead {
            id: id.to_owned(),
            head,
        });
    }

    pub(crate) fn body_chunk(
        &self, id: &str, direction: BodyDirection, bytes: &[u8], total_bytes: usize, truncated: bool,
    ) {
        if !self.capture_enabled() {
            return;
        }
        self.send(StoreCommand::Body {
            id: id.to_owned(),
            direction,
            chunk: String::from_utf8_lossy(bytes).into_owned(),
            total_bytes,
            truncated,
        });
    }

    pub(crate) fn finish_body(&self, id: &str, direction: BodyDirection, note: Option<String>, image: Option<String>) {
        self.send(StoreCommand::FinishBody {
            id: id.to_owned(),
            direction,
            note,
            image,
        });
    }

    pub(crate) fn finish_record(&self, id: &str, state: &'static str) {
        self.send(StoreCommand::FinishRecord {
            id: id.to_owned(),
            state,
        });
    }

    pub(crate) fn record_error(&self, id: &str, message: impl Into<String>) {
        self.send(StoreCommand::Error {
            id: id.to_owned(),
            message: message.into(),
        });
    }

    // 客户端不信任 MITM CA 的 TLS 握手失败计数，与明文抓取开关无关，始终统计
    pub(crate) fn record_tls_error(&self, authority: &str, client_ip: &str) {
        self.send(StoreCommand::TlsError {
            authority: authority.to_owned(),
            client_ip: client_ip.to_owned(),
        });
    }

    pub(crate) async fn tls_errors(&self) -> Result<Vec<TlsErrorGroup>, ManagerError> {
        let path = self.db_path.clone();
        run_read_db(path, move |connection| {
            let mut statement = connection.prepare(
                "SELECT authority, client_ip, count, last_seen_ms FROM tls_errors ORDER BY last_seen_ms DESC",
            )?;
            let rows = statement.query_map([], |row| {
                Ok(TlsErrorGroup {
                    authority: row.get(0)?,
                    client_ip: row.get(1)?,
                    count: row.get(2)?,
                    last_seen_ms: row.get(3)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()
        })
        .await
    }

    pub(crate) async fn list_records(&self, query: RecordQuery) -> Result<RecordPage, ManagerError> {
        let path = self.db_path.clone();
        run_read_db(path, move |connection| query_records(connection, &query)).await
    }

    pub(crate) async fn get_record(&self, id: String) -> Result<Option<RecordDetail>, ManagerError> {
        let path = self.db_path.clone();
        run_read_db(path, move |connection| get_record(connection, &id)).await
    }

    pub(crate) async fn groups(&self) -> Result<Vec<UrlHostGroup>, ManagerError> {
        let path = self.db_path.clone();
        run_read_db(path, query_groups).await
    }

    pub(crate) async fn clear_records(&self) -> Result<(), ManagerError> {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.writer_tx
            .send(StoreCommand::Clear(sender))
            .map_err(|_| ManagerError::Database("MITM SQLite writer stopped".to_owned()))?;
        tokio::task::spawn_blocking(move || receiver.recv())
            .await
            .map_err(|error| ManagerError::Database(format!("clear records task failed: {error}")))?
            .map_err(|_| ManagerError::Database("MITM SQLite writer stopped".to_owned()))?
            .map_err(ManagerError::Database)
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<MitmEvent> {
        self.events.subscribe()
    }

    fn send(&self, command: StoreCommand) {
        if self.writer_tx.send(command).is_err() {
            error!("MITM SQLite writer stopped; capture update was lost");
        }
    }

    fn request_prune(&self, max_records: usize, compact: bool) {
        if self.prune_tx.send(PruneRequest { max_records, compact }).is_err() {
            error!("MITM SQLite prune worker stopped; retention prune was lost");
        }
    }

    fn emit(&self, kind: &'static str, record_id: Option<String>) {
        let _ = self.events.send(MitmEvent { kind, record_id });
    }
}

#[derive(Debug)]
pub(crate) enum ManagerError {
    BadRequest(String),
    Conflict(String),
    Database(String),
}

impl std::fmt::Display for ManagerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadRequest(message) | Self::Conflict(message) | Self::Database(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl std::error::Error for ManagerError {}

impl From<rusqlite::Error> for ManagerError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error.to_string())
    }
}

fn open_connection(path: &Path) -> Result<Connection, ManagerError> {
    open_connection_with_mode(path, false)
}

fn open_read_connection(path: &Path) -> Result<Connection, ManagerError> {
    open_connection_with_mode(path, true)
}

fn open_connection_with_mode(path: &Path, query_only: bool) -> Result<Connection, ManagerError> {
    let connection = Connection::open(path)?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    if query_only {
        // WAL 已由启动/写连接设置。读连接再执行 journal_mode=WAL 会抢排他锁，
        // 让每次 GET /records/{id} 都堵在正在写入的 capture 后面。
        connection.pragma_update(None, "query_only", "ON")?;
    } else {
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        connection.pragma_update(None, "temp_store", "MEMORY")?;
    }
    Ok(connection)
}

fn initialize_schema(
    connection: &Connection, configured_targets: &[String], seed_capture_enabled: bool, seed_max_records: usize,
    seed_body_limit_bytes: usize,
) -> Result<Vec<String>, ManagerError> {
    let current_version = connection.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))?;
    if current_version > SCHEMA_VERSION {
        return Err(ManagerError::Database(format!(
            "MITM database schema version {current_version} is newer than supported version {SCHEMA_VERSION}"
        )));
    }
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY CHECK(id=1),
            capture_enabled INTEGER NOT NULL,
            max_records INTEGER NOT NULL,
            body_limit_bytes INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            suffix TEXT NOT NULL UNIQUE,
            created_at_ms INTEGER NOT NULL,
            cli_managed INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS records (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            started_at_ms INTEGER NOT NULL,
            completed_at_ms INTEGER,
            client_ip TEXT NOT NULL,
            client_port INTEGER NOT NULL DEFAULT 0,
            proxy_username TEXT NOT NULL,
            authority TEXT NOT NULL,
            host TEXT NOT NULL,
            path TEXT NOT NULL,
            query TEXT,
            method TEXT NOT NULL,
            request_version TEXT NOT NULL,
            request_headers_json TEXT NOT NULL DEFAULT '[]',
            request_body TEXT NOT NULL DEFAULT '',
            request_body_bytes INTEGER NOT NULL DEFAULT 0,
            request_body_truncated INTEGER NOT NULL DEFAULT 0,
            request_body_note TEXT,
            request_body_image TEXT,
            response_status INTEGER,
            response_version TEXT,
            response_headers_json TEXT NOT NULL DEFAULT '[]',
            response_body TEXT NOT NULL DEFAULT '',
            response_body_bytes INTEGER NOT NULL DEFAULT 0,
            response_body_truncated INTEGER NOT NULL DEFAULT 0,
            response_body_note TEXT,
            response_body_image TEXT,
            duration_ms INTEGER,
            capture_state TEXT NOT NULL DEFAULT 'capturing',
            error TEXT
        );
        CREATE INDEX IF NOT EXISTS records_started_idx ON records(started_at_ms DESC, sequence DESC);
        CREATE INDEX IF NOT EXISTS records_host_path_idx ON records(host, path, started_at_ms DESC);
        CREATE TABLE IF NOT EXISTS tls_errors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            authority TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            count INTEGER NOT NULL DEFAULT 1,
            first_seen_ms INTEGER NOT NULL,
            last_seen_ms INTEGER NOT NULL,
            UNIQUE(authority, client_ip)
        );",
    )?;
    let has_cli_managed = {
        let mut statement = connection.prepare("PRAGMA table_info(targets)")?;
        let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
        columns
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .any(|column| column == "cli_managed")
    };
    if !has_cli_managed {
        connection.execute("ALTER TABLE targets ADD COLUMN cli_managed INTEGER NOT NULL DEFAULT 0", [])?;
    }
    let has_legacy_mitm_enabled = {
        let mut statement = connection.prepare("PRAGMA table_info(settings)")?;
        let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
        columns
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .any(|column| column == "mitm_enabled")
    };
    if has_legacy_mitm_enabled {
        connection.execute("ALTER TABLE settings DROP COLUMN mitm_enabled", [])?;
    }
    for column in ["request_body_image", "response_body_image"] {
        if !table_has_column(connection, "records", column)? {
            connection.execute(&format!("ALTER TABLE records ADD COLUMN {column} TEXT"), [])?;
        }
    }
    if !table_has_column(connection, "records", "client_port")? {
        connection.execute("ALTER TABLE records ADD COLUMN client_port INTEGER NOT NULL DEFAULT 0", [])?;
    }
    let normalized_targets: Vec<String> = configured_targets
        .iter()
        .filter_map(|value| normalize_suffix(value))
        .collect();
    connection.execute(
        "INSERT OR IGNORE INTO settings(id, capture_enabled, max_records, body_limit_bytes) VALUES(1, ?1, ?2, ?3)",
        params![
            seed_capture_enabled,
            seed_max_records as i64,
            seed_body_limit_bytes as i64
        ],
    )?;
    let transaction = connection.unchecked_transaction()?;
    // 控制台添加的目标持久保存在 DB 中，跨重启保留，不再整体清空；
    // CLI 目标不落库，仅把 DB 中已存在的同名行标记为 CLI 管理，其余行恢复为控制台目标
    transaction.execute("UPDATE targets SET cli_managed=0", [])?;
    for suffix in &normalized_targets {
        transaction.execute("UPDATE targets SET cli_managed=1 WHERE suffix=?1", [suffix])?;
    }
    transaction.commit()?;
    // 重启后不存在仍在进行的抓取，把历史遗留的 capturing 记录统一收尾为 interrupted
    connection.execute(
        "UPDATE records SET capture_state='interrupted', completed_at_ms=COALESCE(completed_at_ms, ?1),
            duration_ms=COALESCE(duration_ms, ?1-started_at_ms) WHERE capture_state='capturing'",
        [now_ms()],
    )?;
    if current_version < SCHEMA_VERSION {
        connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    }
    Ok(normalized_targets)
}

fn table_has_column(connection: &Connection, table: &str, column: &str) -> Result<bool, ManagerError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    Ok(columns
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .any(|name| name == column))
}

// WAL 模式下真实占用 = 主库 + wal + shm
fn db_file_bytes(path: &Path) -> u64 {
    ["", "-wal", "-shm"]
        .iter()
        .map(|suffix| {
            let mut file = path.as_os_str().to_owned();
            file.push(suffix);
            fs::metadata(&file).map(|metadata| metadata.len()).unwrap_or(0)
        })
        .sum()
}

fn load_settings(connection: &Connection) -> Result<(bool, usize, usize), ManagerError> {
    connection
        .query_row("SELECT capture_enabled, max_records, body_limit_bytes FROM settings WHERE id=1", [], |row| {
            Ok((
                row.get(0)?,
                usize::try_from(row.get::<_, i64>(1)?).unwrap_or(10_000),
                usize::try_from(row.get::<_, i64>(2)?).unwrap_or(64 * 1024),
            ))
        })
        .map_err(ManagerError::from)
}

fn load_targets(connection: &Connection) -> Result<Vec<MitmTarget>, ManagerError> {
    let mut statement =
        connection.prepare("SELECT id, suffix, created_at_ms, cli_managed FROM targets ORDER BY suffix")?;
    let rows = statement.query_map([], |row| {
        Ok(MitmTarget {
            id: row.get(0)?,
            suffix: row.get(1)?,
            created_at_ms: row.get(2)?,
            cli_managed: row.get(3)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(ManagerError::from)
}

fn writer_loop(db_path: PathBuf, receiver: mpsc::Receiver<StoreCommand>, events: broadcast::Sender<MitmEvent>) {
    let connection = match open_connection(&db_path) {
        Ok(connection) => connection,
        Err(error) => {
            error!("failed to open MITM writer database {}: {error}", db_path.display());
            return;
        }
    };
    let mut pending = HashMap::<String, PendingBody>::new();
    let mut next_flush = Instant::now() + WRITER_FLUSH_INTERVAL;
    loop {
        match receiver.recv_timeout(next_flush.saturating_duration_since(Instant::now())) {
            Ok(command) => {
                if let Err(error) = apply_store_command(&connection, command, &mut pending, &events) {
                    error!("failed to persist MITM capture update: {error}");
                }
                // Use a fixed cadence instead of an inactivity timeout. A continuously busy
                // stream (notably text/event-stream) must still become visible in the UI while
                // data keeps arriving.
                if Instant::now() >= next_flush {
                    if let Err(error) = flush_pending(&connection, &mut pending, &events) {
                        error!("failed to flush MITM capture bodies: {error}");
                    }
                    next_flush = Instant::now() + WRITER_FLUSH_INTERVAL;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Err(error) = flush_pending(&connection, &mut pending, &events) {
                    error!("failed to flush MITM capture bodies: {error}");
                }
                next_flush = Instant::now() + WRITER_FLUSH_INTERVAL;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = flush_pending(&connection, &mut pending, &events);
                break;
            }
        }
    }
}

fn apply_store_command(
    connection: &Connection, command: StoreCommand, pending: &mut HashMap<String, PendingBody>,
    events: &broadcast::Sender<MitmEvent>,
) -> Result<(), ManagerError> {
    match command {
        StoreCommand::Create(record) => {
            connection.execute(
                "INSERT INTO records(id, started_at_ms, client_ip, client_port, proxy_username, authority, host, path, query, method, request_version, request_headers_json)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![record.id, record.started_at_ms, record.client_ip, record.client_port, record.proxy_username, record.authority, record.host,
                    record.path, record.query, record.method, record.request_version, record.request_headers_json],
            )?;
            let max_records = connection
                .query_row("SELECT max_records FROM settings WHERE id=1", [], |row| row.get::<_, usize>(0))?;
            prune_records(connection, max_records)?;
            emit(events, "record_created", Some(record.id));
        }
        StoreCommand::ResponseHead { id, head } => {
            connection.execute(
                "UPDATE records SET response_status=?1, response_version=?2, response_headers_json=?3,
                    response_body_note=COALESCE(?4, response_body_note), duration_ms=?5 WHERE id=?6",
                params![
                    head.status,
                    head.version,
                    head.headers_json,
                    head.body_note,
                    elapsed_ms_for(connection, &id),
                    id
                ],
            )?;
            emit(events, "record_updated", Some(id));
        }
        StoreCommand::Body {
            id,
            direction,
            chunk,
            total_bytes,
            truncated,
        } => {
            let body = pending.entry(id).or_default();
            body.dirty = true;
            match direction {
                BodyDirection::Request => {
                    body.request.push_str(&chunk);
                    body.request_total = total_bytes;
                    body.request_truncated = truncated;
                }
                BodyDirection::Response => {
                    body.response.push_str(&chunk);
                    body.response_total = total_bytes;
                    body.response_truncated = truncated;
                }
            }
        }
        StoreCommand::FinishBody {
            id,
            direction,
            note,
            image,
        } => {
            flush_one(connection, pending, &id, events, false)?;
            let (note_column, image_column) = match direction {
                BodyDirection::Request => ("request_body_note", "request_body_image"),
                BodyDirection::Response => ("response_body_note", "response_body_image"),
            };
            let sql = format!(
                "UPDATE records SET {note_column}=COALESCE(?1, {note_column}), {image_column}=COALESCE(?2, {image_column}) WHERE id=?3"
            );
            connection.execute(&sql, params![note, image, id])?;
            emit(events, "record_updated", Some(id));
        }
        StoreCommand::FinishRecord { id, state } => {
            flush_one(connection, pending, &id, events, true)?;
            let completed = now_ms();
            connection.execute(
                "UPDATE records SET completed_at_ms=?1, duration_ms=?1-started_at_ms, capture_state=?2 WHERE id=?3 AND capture_state='capturing'",
                params![completed, state, id],
            )?;
            emit(events, "record_updated", Some(id));
        }
        StoreCommand::Error { id, message } => {
            flush_one(connection, pending, &id, events, true)?;
            let completed = now_ms();
            connection.execute(
                "UPDATE records SET completed_at_ms=?1, duration_ms=?1-started_at_ms, capture_state='error', error=?2 WHERE id=?3",
                params![completed, message, id],
            )?;
            emit(events, "record_updated", Some(id));
        }
        StoreCommand::TlsError { authority, client_ip } => {
            let now = now_ms();
            connection.execute(
                "INSERT INTO tls_errors(authority, client_ip, count, first_seen_ms, last_seen_ms) VALUES(?1, ?2, 1, ?3, ?3)
                 ON CONFLICT(authority, client_ip) DO UPDATE SET count=count+1, last_seen_ms=excluded.last_seen_ms",
                params![authority, client_ip, now],
            )?;
            connection.execute(
                "DELETE FROM tls_errors WHERE id NOT IN (SELECT id FROM tls_errors ORDER BY last_seen_ms DESC LIMIT ?1)",
                [MAX_TLS_ERROR_ROWS],
            )?;
            emit(events, "tls_errors", None);
        }
        StoreCommand::StopAllCaptures => {
            flush_pending(connection, pending, events)?;
            connection.execute(
                "UPDATE records SET capture_state='capture_stopped', completed_at_ms=COALESCE(completed_at_ms, ?1),
                    duration_ms=COALESCE(duration_ms, ?1-started_at_ms) WHERE capture_state='capturing'",
                [now_ms()],
            )?;
            emit(events, "resync", None);
        }
        StoreCommand::Clear(sender) => {
            pending.clear();
            let result = connection
                .execute("DELETE FROM records", [])
                .and_then(|_| compact_database(connection))
                .map_err(|error| error.to_string());
            let succeeded = result.is_ok();
            let _ = sender.send(result);
            if succeeded {
                emit(events, "records_cleared", None);
            }
        }
    }
    Ok(())
}

fn flush_pending(
    connection: &Connection, pending: &mut HashMap<String, PendingBody>, events: &broadcast::Sender<MitmEvent>,
) -> Result<(), ManagerError> {
    let ids: Vec<String> = pending.keys().cloned().collect();
    for id in ids {
        flush_one(connection, pending, &id, events, false)?;
    }
    Ok(())
}

fn flush_one(
    connection: &Connection, pending: &mut HashMap<String, PendingBody>, id: &str,
    events: &broadcast::Sender<MitmEvent>, remove: bool,
) -> Result<(), ManagerError> {
    let dirty = pending.get(id).is_some_and(|body| body.dirty);
    if dirty {
        if let Some(body) = pending.get(id) {
            persist_body(connection, id, body)?;
        }
        if let Some(body) = pending.get_mut(id) {
            body.dirty = false;
        }
        emit(events, "record_updated", Some(id.to_owned()));
    }
    if remove {
        pending.remove(id);
    }
    Ok(())
}

fn persist_body(connection: &Connection, id: &str, body: &PendingBody) -> Result<(), rusqlite::Error> {
    // 内存里累积完整 body 后一次性 SET，避免 request_body||chunk 每次都复制整列。
    let mut statement = connection.prepare_cached(
        "UPDATE records SET request_body=?1, response_body=?2,
            request_body_bytes=MAX(request_body_bytes, ?3), response_body_bytes=MAX(response_body_bytes, ?4),
            request_body_truncated=request_body_truncated OR ?5,
            response_body_truncated=response_body_truncated OR ?6 WHERE id=?7 AND capture_state='capturing'",
    )?;
    statement.execute(params![
        body.request,
        body.response,
        body.request_total as i64,
        body.response_total as i64,
        body.request_truncated,
        body.response_truncated,
        id
    ])?;
    Ok(())
}

fn elapsed_ms_for(connection: &Connection, id: &str) -> i64 {
    connection
        .query_row("SELECT started_at_ms FROM records WHERE id=?1", [id], |row| row.get::<_, i64>(0))
        .map(|started| now_ms().saturating_sub(started))
        .unwrap_or_default()
}

fn prune_records(connection: &Connection, max_records: usize) -> Result<usize, rusqlite::Error> {
    connection.execute(
        "DELETE FROM records WHERE sequence IN (
            SELECT sequence FROM records ORDER BY sequence DESC LIMIT -1 OFFSET ?1
        )",
        [max_records as i64],
    )
}

fn compact_database(connection: &Connection) -> Result<(), rusqlite::Error> {
    connection.execute_batch("VACUUM")?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    Ok(())
}

// 单独线程串行执行批量 prune / VACUUM，避免堵住设置接口和抓包写入
fn prune_loop(path: PathBuf, rx: mpsc::Receiver<PruneRequest>, events: broadcast::Sender<MitmEvent>) {
    while let Ok(mut request) = rx.recv() {
        while let Ok(next) = rx.try_recv() {
            request.max_records = next.max_records;
            request.compact |= next.compact;
        }
        match open_connection(&path) {
            Ok(connection) => {
                if let Err(error) = connection.busy_timeout(Duration::from_secs(60)) {
                    warn!("failed to extend MITM prune busy timeout: {error}");
                }
                match prune_records(&connection, request.max_records) {
                    Ok(deleted) => {
                        if request.compact
                            && deleted > 0
                            && let Err(error) = compact_database(&connection)
                        {
                            warn!("failed to compact MITM database after prune: {error}");
                        }
                        if deleted > 0 {
                            let _ = events.send(MitmEvent {
                                kind: "resync",
                                record_id: None,
                            });
                        }
                    }
                    Err(error) => warn!("failed to prune MITM records: {error}"),
                }
            }
            Err(error) => warn!("failed to open MITM database for prune: {error}"),
        }
    }
}

thread_local! {
    static READ_CONNECTION: RefCell<Option<(PathBuf, Connection)>> = const { RefCell::new(None) };
}

async fn run_db<T, F>(path: PathBuf, operation: F) -> Result<T, ManagerError>
where
    T: Send + 'static,
    F: FnOnce(&Connection) -> Result<T, rusqlite::Error> + Send + 'static,
{
    spawn_db(path, false, operation).await
}

async fn run_read_db<T, F>(path: PathBuf, operation: F) -> Result<T, ManagerError>
where
    T: Send + 'static,
    F: FnOnce(&Connection) -> Result<T, rusqlite::Error> + Send + 'static,
{
    spawn_db(path, true, operation).await
}

async fn spawn_db<T, F>(path: PathBuf, query_only: bool, operation: F) -> Result<T, ManagerError>
where
    T: Send + 'static,
    F: FnOnce(&Connection) -> Result<T, rusqlite::Error> + Send + 'static,
{
    tokio::task::spawn_blocking(move || -> Result<T, ManagerError> {
        if query_only {
            READ_CONNECTION.with(|slot| {
                let mut slot = slot.borrow_mut();
                let needs_open = !matches!(slot.as_ref(), Some((cached_path, _)) if cached_path == &path);
                if needs_open {
                    *slot = Some((path.clone(), open_read_connection(&path)?));
                }
                match slot.as_ref() {
                    Some((_, connection)) => operation(connection).map_err(ManagerError::from),
                    None => Err(ManagerError::Database("failed to open MITM read connection".to_owned())),
                }
            })
        } else {
            let connection = open_connection(&path)?;
            operation(&connection).map_err(ManagerError::from)
        }
    })
    .await
    .map_err(|error| ManagerError::Database(format!("SQLite task failed: {error}")))?
}

fn query_records(connection: &Connection, query: &RecordQuery) -> Result<RecordPage, rusqlite::Error> {
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_LIMIT).clamp(1, MAX_PAGE_LIMIT);
    let mut sql = String::from(
        "SELECT id, started_at_ms, completed_at_ms, client_ip, client_port, proxy_username, authority, host, path, query,
            method, response_status, duration_ms, capture_state, sequence FROM records WHERE 1=1",
    );
    let mut values: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(before) = query.before {
        sql.push_str(" AND sequence < ?");
        values.push(Box::new(before));
    }
    if let Some(host) = query.host.as_ref().filter(|value| !value.is_empty()) {
        sql.push_str(" AND host = ?");
        values.push(Box::new(host.to_ascii_lowercase()));
    }
    if let Some(path) = query.path.as_ref().filter(|value| !value.is_empty()) {
        sql.push_str(" AND path = ?");
        values.push(Box::new(path.clone()));
    }
    if let Some(method) = query.method.as_ref().filter(|value| !value.is_empty()) {
        sql.push_str(" AND method = ?");
        values.push(Box::new(method.to_ascii_uppercase()));
    }
    if let Some(status) = query.status {
        sql.push_str(" AND response_status = ?");
        values.push(Box::new(status));
    }
    if let Some(client_ip) = query
        .client_ip
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        let normalized = client_ip
            .parse::<IpAddr>()
            .map(|address| address.to_canonical().to_string())
            .unwrap_or_else(|_| client_ip.to_owned());
        sql.push_str(" AND client_ip = ?");
        values.push(Box::new(normalized));
    }
    if let Some(search) = query.q.as_ref().filter(|value| !value.is_empty()) {
        sql.push_str(" AND (authority LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\' OR query LIKE ? ESCAPE '\\')");
        let pattern = format!("%{}%", search.replace('%', "\\%").replace('_', "\\_"));
        values.push(Box::new(pattern.clone()));
        values.push(Box::new(pattern.clone()));
        values.push(Box::new(pattern));
    }
    sql.push_str(" ORDER BY sequence DESC LIMIT ?");
    values.push(Box::new((limit + 1) as i64));
    let refs: Vec<&dyn rusqlite::ToSql> = values.iter().map(|value| value.as_ref()).collect();
    let mut statement = connection.prepare(&sql)?;
    let mut rows = statement.query(refs.as_slice())?;
    let mut records = Vec::new();
    let mut sequences = Vec::new();
    while let Some(row) = rows.next()? {
        records.push(summary_from_row(row)?);
        sequences.push(row.get::<_, i64>(14)?);
    }
    let has_more = records.len() > limit;
    if has_more {
        records.truncate(limit);
        sequences.truncate(limit);
    }
    let total = connection.query_row("SELECT COUNT(*) FROM records", [], |row| row.get(0))?;
    Ok(RecordPage {
        next_before: has_more.then(|| sequences.last().copied()).flatten(),
        records,
        total,
    })
}

fn get_record(connection: &Connection, id: &str) -> Result<Option<RecordDetail>, rusqlite::Error> {
    let mut statement = connection.prepare_cached(
        "SELECT id, started_at_ms, completed_at_ms, client_ip, client_port, proxy_username, authority, host, path, query,
            method, response_status, duration_ms, capture_state, request_version, request_headers_json,
            request_body, request_body_bytes, request_body_truncated, request_body_note, request_body_image,
            response_version, response_headers_json, response_body, response_body_bytes, response_body_truncated,
            response_body_note, response_body_image, error FROM records WHERE id=?1",
    )?;
    statement
        .query_row([id], |row| {
            let request_headers_json: String = row.get(15)?;
            let response_headers_json: String = row.get(22)?;
            Ok(RecordDetail {
                summary: RecordSummary {
                    id: row.get(0)?,
                    started_at_ms: row.get(1)?,
                    completed_at_ms: row.get(2)?,
                    client_ip: row.get(3)?,
                    client_port: row.get(4)?,
                    proxy_username: row.get(5)?,
                    authority: row.get(6)?,
                    host: row.get(7)?,
                    path: row.get(8)?,
                    query: row.get(9)?,
                    method: row.get(10)?,
                    status: row.get(11)?,
                    duration_ms: row.get(12)?,
                    capture_state: row.get(13)?,
                },
                request_version: row.get(14)?,
                request_headers: serde_json::from_str(&request_headers_json)
                    .unwrap_or(serde_json::Value::Array(Vec::new())),
                request_body: row.get(16)?,
                request_body_bytes: row.get(17)?,
                request_body_truncated: row.get(18)?,
                request_body_note: row.get(19)?,
                request_body_image: row.get(20)?,
                response_version: row.get(21)?,
                response_headers: serde_json::from_str(&response_headers_json)
                    .unwrap_or(serde_json::Value::Array(Vec::new())),
                response_body: row.get(23)?,
                response_body_bytes: row.get(24)?,
                response_body_truncated: row.get(25)?,
                response_body_note: row.get(26)?,
                response_body_image: row.get(27)?,
                error: row.get(28)?,
            })
        })
        .optional()
}

fn summary_from_row(row: &rusqlite::Row<'_>) -> Result<RecordSummary, rusqlite::Error> {
    Ok(RecordSummary {
        id: row.get(0)?,
        started_at_ms: row.get(1)?,
        completed_at_ms: row.get(2)?,
        client_ip: row.get(3)?,
        client_port: row.get(4)?,
        proxy_username: row.get(5)?,
        authority: row.get(6)?,
        host: row.get(7)?,
        path: row.get(8)?,
        query: row.get(9)?,
        method: row.get(10)?,
        status: row.get(11)?,
        duration_ms: row.get(12)?,
        capture_state: row.get(13)?,
    })
}

fn query_groups(connection: &Connection) -> Result<Vec<UrlHostGroup>, rusqlite::Error> {
    let mut statement = connection.prepare(
        "SELECT host, path, COUNT(*), MAX(started_at_ms) FROM records
         GROUP BY host, path ORDER BY MAX(started_at_ms) DESC",
    )?;
    let mut rows = statement.query([])?;
    let mut groups = Vec::<UrlHostGroup>::new();
    while let Some(row) = rows.next()? {
        let host: String = row.get(0)?;
        let path: String = row.get(1)?;
        let count: i64 = row.get(2)?;
        let last_seen_ms: i64 = row.get(3)?;
        if let Some(group) = groups.iter_mut().find(|group| group.host == host) {
            group.count += count;
            group.last_seen_ms = group.last_seen_ms.max(last_seen_ms);
            group.paths.push(UrlPathGroup {
                path,
                count,
                last_seen_ms,
            });
        } else {
            groups.push(UrlHostGroup {
                host,
                count,
                last_seen_ms,
                paths: vec![UrlPathGroup {
                    path,
                    count,
                    last_seen_ms,
                }],
            });
        }
    }
    groups.sort_by_key(|group| std::cmp::Reverse(group.last_seen_ms));
    Ok(groups)
}

pub(crate) fn headers_json(headers: &HeaderMap) -> String {
    let pairs: Vec<[String; 2]> = headers
        .iter()
        .map(|(name, value)| {
            [
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            ]
        })
        .collect();
    serde_json::to_string(&pairs).unwrap_or_else(|_| "[]".to_owned())
}

pub(crate) fn version_label(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP/unknown",
    }
}

pub(crate) fn normalize_suffix(raw: &str) -> Option<String> {
    let suffix = raw.trim().trim_matches('.').to_ascii_lowercase();
    (!suffix.is_empty()).then_some(suffix)
}

pub(crate) fn normalize_host(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub(crate) fn host_matches_suffix(host: &str, suffix: &str) -> bool {
    host == suffix
        || host
            .strip_suffix(suffix)
            .map(|prefix| prefix.ends_with('.'))
            .unwrap_or(false)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

fn emit(events: &broadcast::Sender<MitmEvent>, kind: &'static str, record_id: Option<String>) {
    let _ = events.send(MitmEvent { kind, record_id });
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<(), ManagerError> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)
        .map_err(|error| ManagerError::Database(format!("failed to inspect {}: {error}", path.display())))?
        .permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)
        .map_err(|error| ManagerError::Database(format!("failed to protect {}: {error}", path.display())))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<(), ManagerError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "rust_http_proxy_mitm_manager_{name}_{}_{:x}.sqlite3",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    async fn wait_for_event(rx: &mut broadcast::Receiver<MitmEvent>, kind: &str) -> Result<(), DynError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(format!("timed out waiting for MITM event {kind}").into());
            }
            let event = tokio::time::timeout(remaining, rx.recv())
                .await
                .map_err(|_| format!("timed out waiting for MITM event {kind}"))?
                .map_err(|error| error.to_string())?;
            if event.kind == kind {
                return Ok(());
            }
        }
    }

    #[test]
    fn suffix_matching_respects_label_boundaries() {
        assert!(host_matches_suffix("example.com", "example.com"));
        assert!(host_matches_suffix("api.example.com", "example.com"));
        assert!(!host_matches_suffix("badexample.com", "example.com"));
    }

    #[test]
    fn normalizes_suffixes() {
        assert_eq!(normalize_suffix(" .Example.COM. "), Some("example.com".to_owned()));
        assert_eq!(normalize_suffix("..."), None);
    }

    #[test]
    fn filters_records_by_normalized_client_ip() -> Result<(), DynError> {
        let path = test_db("client_ip_filter");
        let connection = Connection::open(&path)?;
        initialize_schema(&connection, &[], true, 10_000, 65_536)?;
        for (id, client_ip, sequence) in [("ipv4", "127.0.0.1", 1), ("ipv6", "2001:db8::1", 2)] {
            connection.execute(
                "INSERT INTO records(id, started_at_ms, client_ip, proxy_username, authority, host, path,
                    method, request_version, capture_state) VALUES(?1, ?2, ?3, '', 'example.com:443',
                    'example.com', '/', 'GET', 'HTTP/1.1', 'complete')",
                params![id, sequence, client_ip],
            )?;
        }

        let page = query_records(
            &connection,
            &RecordQuery {
                client_ip: Some(" 2001:0DB8:0:0:0:0:0:1 ".to_owned()),
                ..RecordQuery::default()
            },
        )?;
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].id, "ipv6");
        drop(connection);
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn rejects_newer_database_schema() -> Result<(), DynError> {
        let path = test_db("future_schema");
        let connection = Connection::open(&path)?;
        connection.pragma_update(None, "user_version", SCHEMA_VERSION + 1)?;
        drop(connection);

        let error = MitmManager::open(path.clone(), false, &[], false, 10_000, 65_536)
            .err()
            .ok_or("newer schema was unexpectedly accepted")?;
        assert!(error.to_string().contains("newer than supported"));
        fs::remove_file(path)?;
        Ok(())
    }

    #[test]
    fn migrates_cli_target_marker_from_schema_v1() -> Result<(), DynError> {
        let path = test_db("schema_v1");
        let connection = Connection::open(&path)?;
        connection.execute_batch(
            "CREATE TABLE settings (
                id INTEGER PRIMARY KEY CHECK(id=1),
                mitm_enabled INTEGER NOT NULL,
                capture_enabled INTEGER NOT NULL,
                max_records INTEGER NOT NULL,
                body_limit_bytes INTEGER NOT NULL
            );
            INSERT INTO settings VALUES(1, 0, 1, 123, 4096);
            CREATE TABLE targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                suffix TEXT NOT NULL UNIQUE,
                created_at_ms INTEGER NOT NULL
            );
            PRAGMA user_version=1;",
        )?;
        drop(connection);

        let manager = MitmManager::open(path.clone(), true, &["cli.example".to_owned()], false, 10_000, 65_536)?;
        assert_eq!(manager.targets().len(), 1);
        assert!(manager.targets()[0].cli_managed);
        assert!(manager.settings().capture_enabled);
        assert_eq!(manager.settings().max_records, 123);
        assert_eq!(manager.settings().body_limit_bytes, 4096);
        drop(manager);
        std::thread::sleep(Duration::from_millis(300));
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[tokio::test]
    async fn persists_settings_and_console_targets_but_not_cli_ones() -> Result<(), DynError> {
        let path = test_db("settings");
        let manager = MitmManager::open(path.clone(), true, &["Example.COM".to_owned()], false, 10_000, 65_536)?;
        assert!(manager.should_mitm("api.example.com"));
        assert!(manager.settings().db_bytes > 0);
        assert!(manager.targets()[0].cli_managed);
        let protected_id = manager.targets()[0].id;
        let error = manager
            .delete_target(protected_id)
            .await
            .err()
            .ok_or("CLI target was unexpectedly deleted")?;
        assert!(error.to_string().contains("--mitm-domain-suffix"));
        manager
            .patch_settings(MitmSettingsPatch {
                capture_enabled: Some(true),
                max_records: Some(321),
                body_limit_bytes: Some(16_384),
            })
            .await?;
        let target = manager.add_target(".Second.Example.".to_owned()).await?;
        assert_eq!(target.suffix, "second.example");
        assert!(!target.cli_managed);
        assert!(manager.delete_target(target.id).await?);
        let target = manager.add_target(".Second.Example.".to_owned()).await?;
        assert!(!target.cli_managed);
        drop(manager);
        tokio::time::sleep(Duration::from_millis(300)).await;

        let reopened = MitmManager::open(path.clone(), true, &["Override.Example".to_owned()], false, 1, 1024)?;
        let settings = reopened.settings();
        assert!(settings.capture_enabled);
        assert_eq!(settings.max_records, 321);
        assert_eq!(settings.body_limit_bytes, 16_384);
        // 控制台添加的目标跨重启保留；上一轮的 CLI 目标（example.com）不落库，随之消失
        assert_eq!(reopened.targets().len(), 2);
        let targets = reopened.targets();
        let cli_target = targets
            .iter()
            .find(|target| target.suffix == "override.example")
            .ok_or("CLI target missing")?;
        assert!(cli_target.cli_managed);
        let cli_target_id = cli_target.id;
        let console_target = targets
            .iter()
            .find(|target| target.suffix == "second.example")
            .ok_or("console target was not persisted")?;
        assert!(!console_target.cli_managed);
        let error = reopened
            .delete_target(cli_target_id)
            .await
            .err()
            .ok_or("CLI target was unexpectedly deleted")?;
        assert!(error.to_string().contains("--mitm-domain-suffix"));
        assert!(reopened.should_mitm("www.override.example"));
        assert!(reopened.should_mitm("www.second.example"));
        assert!(!reopened.should_mitm("api.example.com"));
        drop(reopened);
        tokio::time::sleep(Duration::from_millis(300)).await;

        let reopened_without_targets = MitmManager::open(path.clone(), true, &[], false, 1, 1024)?;
        // CLI 目标不落库已消失，控制台目标仍在
        let targets = reopened_without_targets.targets();
        let suffixes: Vec<&str> = targets.iter().map(|target| target.suffix.as_str()).collect();
        assert_eq!(suffixes, ["second.example"]);
        assert!(!reopened_without_targets.should_mitm("www.override.example"));
        assert!(reopened_without_targets.should_mitm("www.second.example"));
        drop(reopened_without_targets);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[tokio::test]
    async fn cli_capture_override_is_locked_and_does_not_replace_stored_setting() -> Result<(), DynError> {
        let path = test_db("capture_cli_override");
        let manager = MitmManager::open(path.clone(), true, &[], false, 10_000, 65_536)?;
        assert!(!manager.settings().capture_enabled);
        assert!(!manager.settings().capture_cli_managed);
        drop(manager);
        tokio::time::sleep(Duration::from_millis(300)).await;

        let manager = MitmManager::open(path.clone(), true, &[], true, 10_000, 65_536)?;
        let settings = manager.settings();
        assert!(settings.capture_enabled);
        assert!(settings.capture_cli_managed);
        let error = manager
            .patch_settings(MitmSettingsPatch {
                capture_enabled: Some(false),
                max_records: None,
                body_limit_bytes: None,
            })
            .await
            .err()
            .ok_or("CLI-managed capture setting was unexpectedly changed")?;
        assert!(matches!(error, ManagerError::Conflict(_)));
        assert!(error.to_string().contains("--mitm-dump"));

        let settings = manager
            .patch_settings(MitmSettingsPatch {
                capture_enabled: None,
                max_records: Some(321),
                body_limit_bytes: None,
            })
            .await?;
        assert!(settings.capture_enabled);
        assert_eq!(settings.max_records, 321);
        drop(manager);
        tokio::time::sleep(Duration::from_millis(300)).await;

        let manager = MitmManager::open(path.clone(), true, &[], false, 10_000, 65_536)?;
        let settings = manager.settings();
        assert!(!settings.capture_enabled);
        assert!(!settings.capture_cli_managed);
        assert_eq!(settings.max_records, 321);
        drop(manager);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = fs::remove_file(path);
        Ok(())
    }

    // CLI 目标若已在 DB 中（之前由控制台添加），行保留并标记为 CLI 管理
    #[tokio::test]
    async fn cli_target_matching_db_row_keeps_row_and_mark() -> Result<(), DynError> {
        let path = test_db("cli_db_overlap");
        let manager = MitmManager::open(path.clone(), true, &[], false, 10_000, 65_536)?;
        manager.add_target("shared.example".to_owned()).await?;
        drop(manager);
        tokio::time::sleep(Duration::from_millis(300)).await;

        let manager = MitmManager::open(path.clone(), true, &["shared.example".to_owned()], false, 10_000, 65_536)?;
        assert_eq!(manager.targets().len(), 1);
        assert!(manager.targets()[0].cli_managed);
        assert!(manager.targets()[0].id > 0);
        let error = manager
            .delete_target(manager.targets()[0].id)
            .await
            .err()
            .ok_or("CLI target was unexpectedly deleted")?;
        assert!(error.to_string().contains("--mitm-domain-suffix"));
        drop(manager);
        tokio::time::sleep(Duration::from_millis(300)).await;

        // 再次重启且不带 CLI：行仍在，恢复为可删除的控制台目标
        let manager = MitmManager::open(path.clone(), true, &[], false, 10_000, 65_536)?;
        assert_eq!(manager.targets().len(), 1);
        assert!(!manager.targets()[0].cli_managed);
        drop(manager);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = fs::remove_file(path);
        Ok(())
    }

    // 控制台添加一个当前由 CLI 提供的同名后缀：落库、去重、仍按 CLI 管理
    #[tokio::test]
    async fn console_add_of_cli_suffix_persists_single_managed_row() -> Result<(), DynError> {
        let path = test_db("console_add_cli_suffix");
        let manager = MitmManager::open(path.clone(), true, &["dup.example".to_owned()], false, 10_000, 65_536)?;
        let added = manager.add_target("dup.example".to_owned()).await?;
        assert!(added.cli_managed);
        assert_eq!(
            manager
                .targets()
                .iter()
                .filter(|target| target.suffix == "dup.example")
                .count(),
            1
        );
        drop(manager);
        tokio::time::sleep(Duration::from_millis(300)).await;

        let manager = MitmManager::open(path.clone(), true, &[], false, 10_000, 65_536)?;
        assert_eq!(manager.targets().len(), 1);
        assert_eq!(manager.targets()[0].suffix, "dup.example");
        assert!(!manager.targets()[0].cli_managed);
        drop(manager);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[tokio::test]
    async fn aggregates_tls_errors_by_authority_and_client_ip() -> Result<(), DynError> {
        let path = test_db("tls_errors");
        let manager = MitmManager::open(path.clone(), true, &[], false, 10_000, 65_536)?;
        manager.record_tls_error("example.com:443", "127.0.0.1");
        manager.record_tls_error("example.com:443", "127.0.0.1");
        manager.record_tls_error("example.com:443", "10.0.0.2");
        manager.record_tls_error("api.example.com:443", "127.0.0.1");
        tokio::time::sleep(Duration::from_millis(400)).await;

        let groups = manager.tls_errors().await?;
        assert_eq!(groups.len(), 3);
        let pair = groups
            .iter()
            .find(|group| group.authority == "example.com:443" && group.client_ip == "127.0.0.1")
            .ok_or("tls error group missing")?;
        assert_eq!(pair.count, 2);
        assert!(groups.iter().all(|group| group.last_seen_ms > 0));
        drop(manager);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[tokio::test]
    async fn stores_correlated_request_and_response() -> Result<(), DynError> {
        let path = test_db("capture");
        let manager = MitmManager::open(path.clone(), true, &["example.com".to_owned()], true, 10_000, 65_536)?;
        let request_headers = HeaderMap::new();
        let id = manager
            .begin_record(RecordMetadata {
                client_ip: "127.0.0.1".to_owned(),
                client_port: 54321,
                proxy_username: "tester".to_owned(),
                authority: "api.example.com:443".to_owned(),
                host: "api.example.com".to_owned(),
                path: "/v1/value".to_owned(),
                query: Some("verbose=1".to_owned()),
                method: "POST".to_owned(),
                request_version: Version::HTTP_2,
                request_headers: &request_headers,
            })
            .ok_or("capture unexpectedly disabled")?;
        manager.body_chunk(&id, BodyDirection::Request, br#"{"request":true}"#, 16, false);
        manager.finish_body(&id, BodyDirection::Request, None, None);
        manager.response_head(
            &id,
            ResponseHead {
                status: 201,
                version: "HTTP/2".to_owned(),
                headers_json: "[]".to_owned(),
                body_note: None,
            },
        );
        manager.body_chunk(&id, BodyDirection::Response, br#"{"ok":true}"#, 11, false);
        manager.finish_body(&id, BodyDirection::Response, None, None);
        manager.finish_record(&id, "complete");
        tokio::time::sleep(Duration::from_millis(400)).await;

        let detail = manager.get_record(id).await?.ok_or("record not found")?;
        assert_eq!(detail.summary.status, Some(201));
        assert_eq!(detail.summary.capture_state, "complete");
        assert_eq!(detail.request_body, r#"{"request":true}"#);
        assert_eq!(detail.response_body, r#"{"ok":true}"#);
        drop(manager);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[tokio::test]
    async fn lowering_max_records_prunes_old_rows_and_shrinks_db() -> Result<(), DynError> {
        let path = test_db("prune_compact");
        let manager = MitmManager::open(path.clone(), true, &["example.com".to_owned()], true, 10_000, 65_536)?;
        let request_headers = HeaderMap::new();
        let payload = "x".repeat(48 * 1024);
        for index in 0..6 {
            let id = manager
                .begin_record(RecordMetadata {
                    client_ip: "127.0.0.1".to_owned(),
                    client_port: 54321,
                    proxy_username: "tester".to_owned(),
                    authority: "api.example.com:443".to_owned(),
                    host: "api.example.com".to_owned(),
                    path: format!("/item/{index}"),
                    query: None,
                    method: "POST".to_owned(),
                    request_version: Version::HTTP_11,
                    request_headers: &request_headers,
                })
                .ok_or("capture unexpectedly disabled")?;
            manager.body_chunk(&id, BodyDirection::Request, payload.as_bytes(), payload.len(), false);
            manager.finish_body(&id, BodyDirection::Request, None, None);
            manager.finish_record(&id, "complete");
        }
        tokio::time::sleep(Duration::from_millis(400)).await;

        let mut events = manager.subscribe();
        let before = manager.settings().db_bytes;
        let settings = manager
            .patch_settings(MitmSettingsPatch {
                capture_enabled: None,
                max_records: Some(2),
                body_limit_bytes: None,
            })
            .await?;
        assert_eq!(settings.max_records, 2);
        wait_for_event(&mut events, "resync").await?;
        let page = manager
            .list_records(RecordQuery {
                limit: Some(20),
                ..RecordQuery::default()
            })
            .await?;
        assert_eq!(page.total, 2);
        assert_eq!(page.records.len(), 2);
        let after = manager.settings().db_bytes;
        assert!(after < before, "expected VACUUM to shrink {after} bytes to less than the pre-prune size {before}");
        drop(manager);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[tokio::test]
    async fn incremental_body_flushes_replace_full_snapshot() -> Result<(), DynError> {
        let path = test_db("incremental_body");
        let manager = MitmManager::open(path.clone(), true, &["example.com".to_owned()], true, 10_000, 65_536)?;
        let request_headers = HeaderMap::new();
        let id = manager
            .begin_record(RecordMetadata {
                client_ip: "127.0.0.1".to_owned(),
                client_port: 54321,
                proxy_username: "tester".to_owned(),
                authority: "api.example.com:443".to_owned(),
                host: "api.example.com".to_owned(),
                path: "/v1/stream".to_owned(),
                query: None,
                method: "POST".to_owned(),
                request_version: Version::HTTP_11,
                request_headers: &request_headers,
            })
            .ok_or("capture unexpectedly disabled")?;
        manager.body_chunk(&id, BodyDirection::Request, b"hello", 5, false);
        tokio::time::sleep(Duration::from_millis(400)).await;
        manager.body_chunk(&id, BodyDirection::Request, b" world", 11, false);
        manager.finish_body(&id, BodyDirection::Request, None, None);
        manager.finish_record(&id, "complete");
        tokio::time::sleep(Duration::from_millis(400)).await;

        let detail = manager.get_record(id).await?.ok_or("record not found")?;
        assert_eq!(detail.request_body, "hello world");
        assert_eq!(detail.request_body_bytes, 11);
        drop(manager);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[tokio::test]
    async fn continuously_arriving_response_body_flushes_while_stream_is_open() -> Result<(), DynError> {
        let path = test_db("continuous_response_body");
        let manager = MitmManager::open(path.clone(), true, &["example.com".to_owned()], true, 10_000, 65_536)?;
        let request_headers = HeaderMap::new();
        let id = manager
            .begin_record(RecordMetadata {
                client_ip: "127.0.0.1".to_owned(),
                client_port: 54321,
                proxy_username: "tester".to_owned(),
                authority: "api.example.com:443".to_owned(),
                host: "api.example.com".to_owned(),
                path: "/v1/events".to_owned(),
                query: None,
                method: "GET".to_owned(),
                request_version: Version::HTTP_11,
                request_headers: &request_headers,
            })
            .ok_or("capture unexpectedly disabled")?;
        manager.response_head(
            &id,
            ResponseHead {
                status: 200,
                version: "HTTP/1.1".to_owned(),
                headers_json: r#"[["content-type","text/event-stream"]]"#.to_owned(),
                body_note: None,
            },
        );

        let producer_manager = manager.clone();
        let producer_id = id.clone();
        let producer = tokio::spawn(async move {
            let chunk = b"data: tick\n\n";
            for index in 0..20 {
                producer_manager.body_chunk(
                    &producer_id,
                    BodyDirection::Response,
                    chunk,
                    (index + 1) * chunk.len(),
                    false,
                );
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
            producer_manager.finish_body(&producer_id, BodyDirection::Response, None, None);
            producer_manager.finish_record(&producer_id, "complete");
        });

        // The producer is still sending often enough that an inactivity-based flush never fires.
        tokio::time::sleep(Duration::from_millis(450)).await;
        let streaming_detail = manager.get_record(id.clone()).await?.ok_or("record not found")?;
        assert_eq!(streaming_detail.summary.capture_state, "capturing");
        assert!(streaming_detail.response_body.starts_with("data: tick\n\n"));
        assert!(streaming_detail.response_body_bytes > 0);

        producer.await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let complete_detail = manager.get_record(id).await?.ok_or("record not found")?;
        assert_eq!(complete_detail.summary.capture_state, "complete");
        assert_eq!(complete_detail.response_body.matches("data: tick\n\n").count(), 20);
        drop(manager);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = fs::remove_file(path);
        Ok(())
    }
}
