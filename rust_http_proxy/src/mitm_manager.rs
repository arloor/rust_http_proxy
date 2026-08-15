use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::{HeaderMap, Version};
use log::error;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::DynError;

const SCHEMA_VERSION: i64 = 1;
const DEFAULT_PAGE_LIMIT: usize = 100;
const MAX_PAGE_LIMIT: usize = 500;
const WRITER_FLUSH_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Clone, Debug, Serialize)]
pub(crate) struct MitmSettings {
    pub mitm_enabled: bool,
    pub effective_mitm_enabled: bool,
    pub capture_enabled: bool,
    pub ca_available: bool,
    pub max_records: usize,
    pub body_limit_bytes: usize,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct MitmSettingsPatch {
    pub mitm_enabled: Option<bool>,
    pub capture_enabled: Option<bool>,
    pub max_records: Option<usize>,
    pub body_limit_bytes: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct MitmTarget {
    pub id: i64,
    pub suffix: String,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct RecordStart {
    pub id: String,
    pub started_at_ms: i64,
    pub client_ip: String,
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
    pub response_version: Option<String>,
    pub response_headers: serde_json::Value,
    pub response_body: String,
    pub response_body_bytes: i64,
    pub response_body_truncated: bool,
    pub response_body_note: Option<String>,
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
    pub q: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RecordPage {
    pub records: Vec<RecordSummary>,
    pub next_before: Option<i64>,
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
    },
    FinishRecord {
        id: String,
        state: &'static str,
    },
    Error {
        id: String,
        message: String,
    },
    StopAllCaptures,
    Clear(mpsc::SyncSender<Result<(), String>>),
}

#[derive(Default)]
struct PendingBody {
    request: String,
    response: String,
    request_total: usize,
    response_total: usize,
    request_truncated: bool,
    response_truncated: bool,
}

pub(crate) struct MitmManager {
    db_path: PathBuf,
    ca_available: bool,
    mitm_enabled: AtomicBool,
    capture_enabled: AtomicBool,
    max_records: AtomicUsize,
    body_limit_bytes: AtomicUsize,
    targets: RwLock<Vec<MitmTarget>>,
    writer_tx: mpsc::Sender<StoreCommand>,
    events: broadcast::Sender<MitmEvent>,
}

impl MitmManager {
    pub(crate) fn open(
        db_path: PathBuf, ca_available: bool, configured_targets: &[String], seed_capture_enabled: bool,
        seed_max_records: usize, seed_body_limit_bytes: usize,
    ) -> Result<Arc<Self>, DynError> {
        if let Some(parent) = db_path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create MITM database directory {}: {e}", parent.display()))?;
        }
        let connection = open_connection(&db_path)?;
        initialize_schema(
            &connection,
            configured_targets,
            seed_capture_enabled,
            seed_max_records,
            seed_body_limit_bytes,
        )?;
        set_private_permissions(&db_path)?;
        let (mitm_enabled, capture_enabled, max_records, body_limit_bytes) = load_settings(&connection)?;
        let targets = load_targets(&connection)?;
        drop(connection);

        let (writer_tx, writer_rx) = mpsc::channel();
        let (events, _) = broadcast::channel(1024);
        let manager = Arc::new(Self {
            db_path: db_path.clone(),
            ca_available,
            mitm_enabled: AtomicBool::new(mitm_enabled),
            capture_enabled: AtomicBool::new(capture_enabled),
            max_records: AtomicUsize::new(max_records),
            body_limit_bytes: AtomicUsize::new(body_limit_bytes),
            targets: RwLock::new(targets),
            writer_tx,
            events: events.clone(),
        });

        std::thread::Builder::new()
            .name("mitm-sqlite-writer".to_owned())
            .spawn(move || writer_loop(db_path, writer_rx, events))
            .map_err(|e| format!("failed to start MITM SQLite writer: {e}"))?;
        Ok(manager)
    }

    pub(crate) fn settings(&self) -> MitmSettings {
        let enabled = self.mitm_enabled.load(Ordering::Acquire);
        MitmSettings {
            mitm_enabled: enabled,
            effective_mitm_enabled: enabled && self.ca_available,
            capture_enabled: self.capture_enabled.load(Ordering::Acquire),
            ca_available: self.ca_available,
            max_records: self.max_records.load(Ordering::Acquire),
            body_limit_bytes: self.body_limit_bytes.load(Ordering::Acquire),
        }
    }

    pub(crate) fn capture_enabled(&self) -> bool {
        self.capture_enabled.load(Ordering::Acquire)
    }

    pub(crate) fn body_limit_bytes(&self) -> usize {
        self.body_limit_bytes.load(Ordering::Acquire)
    }

    pub(crate) fn should_mitm(&self, host: &str) -> bool {
        if !self.ca_available || !self.mitm_enabled.load(Ordering::Acquire) {
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
        if patch.mitm_enabled == Some(true) && !self.ca_available {
            return Err(ManagerError::Conflict("MITM CA certificate and key are not configured".to_owned()));
        }
        if patch.max_records == Some(0) {
            return Err(ManagerError::BadRequest("max_records must be greater than zero".to_owned()));
        }
        if let Some(limit) = patch.body_limit_bytes
            && !(1024..=1024 * 1024).contains(&limit)
        {
            return Err(ManagerError::BadRequest("body_limit_bytes must be between 1024 and 1048576".to_owned()));
        }

        let current = self.settings();
        let next_mitm = patch.mitm_enabled.unwrap_or(current.mitm_enabled);
        let next_capture = patch.capture_enabled.unwrap_or(current.capture_enabled);
        let next_max_records = patch.max_records.unwrap_or(current.max_records);
        let next_body_limit = patch.body_limit_bytes.unwrap_or(current.body_limit_bytes);
        let path = self.db_path.clone();
        run_db(path, move |connection| {
            connection.execute(
                "UPDATE settings SET mitm_enabled=?1, capture_enabled=?2, max_records=?3, body_limit_bytes=?4 WHERE id=1",
                params![next_mitm, next_capture, next_max_records as i64, next_body_limit as i64],
            )?;
            if current.capture_enabled && !next_capture {
                connection.execute(
                    "UPDATE records SET capture_state='capture_stopped', completed_at_ms=COALESCE(completed_at_ms, ?1) WHERE capture_state='capturing'",
                    [now_ms()],
                )?;
            }
            prune_records(connection, next_max_records)?;
            Ok(())
        })
        .await?;
        self.mitm_enabled.store(next_mitm, Ordering::Release);
        self.capture_enabled.store(next_capture, Ordering::Release);
        self.max_records.store(next_max_records, Ordering::Release);
        self.body_limit_bytes.store(next_body_limit, Ordering::Release);
        if current.capture_enabled && !next_capture {
            self.send(StoreCommand::StopAllCaptures);
        }
        self.emit("settings", None);
        Ok(self.settings())
    }

    pub(crate) async fn add_target(&self, suffix: String) -> Result<MitmTarget, ManagerError> {
        let suffix = normalize_suffix(&suffix)
            .ok_or_else(|| ManagerError::BadRequest("target suffix must not be empty".to_owned()))?;
        let path = self.db_path.clone();
        let db_suffix = suffix.clone();
        let target = run_db(path, move |connection| {
            let created_at = now_ms();
            connection.execute(
                "INSERT OR IGNORE INTO targets(suffix, created_at_ms) VALUES(?1, ?2)",
                params![db_suffix, created_at],
            )?;
            connection.query_row("SELECT id, suffix, created_at_ms FROM targets WHERE suffix=?1", [db_suffix], |row| {
                Ok(MitmTarget {
                    id: row.get(0)?,
                    suffix: row.get(1)?,
                    created_at_ms: row.get(2)?,
                })
            })
        })
        .await?;
        if let Ok(mut targets) = self.targets.write()
            && !targets.iter().any(|item| item.id == target.id)
        {
            targets.push(target.clone());
            targets.sort_by(|left, right| left.suffix.cmp(&right.suffix));
        }
        self.emit("targets", None);
        Ok(target)
    }

    pub(crate) async fn delete_target(&self, id: i64) -> Result<bool, ManagerError> {
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

    pub(crate) fn finish_body(&self, id: &str, direction: BodyDirection, note: Option<String>) {
        self.send(StoreCommand::FinishBody {
            id: id.to_owned(),
            direction,
            note,
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

    pub(crate) async fn list_records(&self, query: RecordQuery) -> Result<RecordPage, ManagerError> {
        let path = self.db_path.clone();
        run_db(path, move |connection| query_records(connection, &query)).await
    }

    pub(crate) async fn get_record(&self, id: String) -> Result<Option<RecordDetail>, ManagerError> {
        let path = self.db_path.clone();
        run_db(path, move |connection| get_record(connection, &id)).await
    }

    pub(crate) async fn groups(&self) -> Result<Vec<UrlHostGroup>, ManagerError> {
        let path = self.db_path.clone();
        run_db(path, query_groups).await
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
    let connection = Connection::open(path)?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    Ok(connection)
}

fn initialize_schema(
    connection: &Connection, configured_targets: &[String], seed_capture_enabled: bool, seed_max_records: usize,
    seed_body_limit_bytes: usize,
) -> Result<(), ManagerError> {
    let current_version = connection.pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))?;
    if current_version > SCHEMA_VERSION {
        return Err(ManagerError::Database(format!(
            "MITM database schema version {current_version} is newer than supported version {SCHEMA_VERSION}"
        )));
    }
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY CHECK(id=1),
            mitm_enabled INTEGER NOT NULL,
            capture_enabled INTEGER NOT NULL,
            max_records INTEGER NOT NULL,
            body_limit_bytes INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            suffix TEXT NOT NULL UNIQUE,
            created_at_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS records (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            started_at_ms INTEGER NOT NULL,
            completed_at_ms INTEGER,
            client_ip TEXT NOT NULL,
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
            response_status INTEGER,
            response_version TEXT,
            response_headers_json TEXT NOT NULL DEFAULT '[]',
            response_body TEXT NOT NULL DEFAULT '',
            response_body_bytes INTEGER NOT NULL DEFAULT 0,
            response_body_truncated INTEGER NOT NULL DEFAULT 0,
            response_body_note TEXT,
            duration_ms INTEGER,
            capture_state TEXT NOT NULL DEFAULT 'capturing',
            error TEXT
        );
        CREATE INDEX IF NOT EXISTS records_started_idx ON records(started_at_ms DESC, sequence DESC);
        CREATE INDEX IF NOT EXISTS records_host_path_idx ON records(host, path, started_at_ms DESC);",
    )?;
    let normalized_targets: Vec<String> = configured_targets
        .iter()
        .filter_map(|value| normalize_suffix(value))
        .collect();
    connection.execute(
        "INSERT OR IGNORE INTO settings(id, mitm_enabled, capture_enabled, max_records, body_limit_bytes) VALUES(1, ?1, ?2, ?3, ?4)",
        params![!normalized_targets.is_empty(), seed_capture_enabled, seed_max_records as i64, seed_body_limit_bytes as i64],
    )?;
    let transaction = connection.unchecked_transaction()?;
    transaction.execute("DELETE FROM targets", [])?;
    for suffix in normalized_targets {
        transaction.execute(
            "INSERT OR IGNORE INTO targets(suffix, created_at_ms) VALUES(?1, ?2)",
            params![suffix, now_ms()],
        )?;
    }
    transaction.commit()?;
    if current_version < SCHEMA_VERSION {
        connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    }
    Ok(())
}

fn load_settings(connection: &Connection) -> Result<(bool, bool, usize, usize), ManagerError> {
    connection
        .query_row(
            "SELECT mitm_enabled, capture_enabled, max_records, body_limit_bytes FROM settings WHERE id=1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    usize::try_from(row.get::<_, i64>(2)?).unwrap_or(10_000),
                    usize::try_from(row.get::<_, i64>(3)?).unwrap_or(64 * 1024),
                ))
            },
        )
        .map_err(ManagerError::from)
}

fn load_targets(connection: &Connection) -> Result<Vec<MitmTarget>, ManagerError> {
    let mut statement = connection.prepare("SELECT id, suffix, created_at_ms FROM targets ORDER BY suffix")?;
    let rows = statement.query_map([], |row| {
        Ok(MitmTarget {
            id: row.get(0)?,
            suffix: row.get(1)?,
            created_at_ms: row.get(2)?,
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
    loop {
        match receiver.recv_timeout(WRITER_FLUSH_INTERVAL) {
            Ok(command) => {
                if let Err(error) = apply_store_command(&connection, command, &mut pending, &events) {
                    error!("failed to persist MITM capture update: {error}");
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Err(error) = flush_pending(&connection, &mut pending, &events) {
                    error!("failed to flush MITM capture bodies: {error}");
                }
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
                "INSERT INTO records(id, started_at_ms, client_ip, proxy_username, authority, host, path, query, method, request_version, request_headers_json)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![record.id, record.started_at_ms, record.client_ip, record.proxy_username, record.authority, record.host,
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
        StoreCommand::FinishBody { id, direction, note } => {
            flush_one(connection, pending, &id, events)?;
            let (column, note_column) = match direction {
                BodyDirection::Request => ("request_body_note", "request_body_note"),
                BodyDirection::Response => ("response_body_note", "response_body_note"),
            };
            let sql = format!("UPDATE records SET {column}=COALESCE(?1, {note_column}) WHERE id=?2");
            connection.execute(&sql, params![note, id])?;
            emit(events, "record_updated", Some(id));
        }
        StoreCommand::FinishRecord { id, state } => {
            flush_one(connection, pending, &id, events)?;
            let completed = now_ms();
            connection.execute(
                "UPDATE records SET completed_at_ms=?1, duration_ms=?1-started_at_ms, capture_state=?2 WHERE id=?3 AND capture_state='capturing'",
                params![completed, state, id],
            )?;
            emit(events, "record_updated", Some(id));
        }
        StoreCommand::Error { id, message } => {
            flush_one(connection, pending, &id, events)?;
            let completed = now_ms();
            connection.execute(
                "UPDATE records SET completed_at_ms=?1, duration_ms=?1-started_at_ms, capture_state='error', error=?2 WHERE id=?3",
                params![completed, message, id],
            )?;
            emit(events, "record_updated", Some(id));
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
                .map(|_| ())
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
        flush_one(connection, pending, &id, events)?;
    }
    Ok(())
}

fn flush_one(
    connection: &Connection, pending: &mut HashMap<String, PendingBody>, id: &str,
    events: &broadcast::Sender<MitmEvent>,
) -> Result<(), ManagerError> {
    let Some(body) = pending.remove(id) else {
        return Ok(());
    };
    connection.execute(
        "UPDATE records SET request_body=request_body||?1, response_body=response_body||?2,
            request_body_bytes=MAX(request_body_bytes, ?3), response_body_bytes=MAX(response_body_bytes, ?4),
            request_body_truncated=request_body_truncated OR ?5,
            response_body_truncated=response_body_truncated OR ?6 WHERE id=?7 AND capture_state='capturing'",
        params![
            body.request,
            body.response,
            body.request_total as i64,
            body.response_total as i64,
            body.request_truncated,
            body.response_truncated,
            id
        ],
    )?;
    emit(events, "record_updated", Some(id.to_owned()));
    Ok(())
}

fn elapsed_ms_for(connection: &Connection, id: &str) -> i64 {
    connection
        .query_row("SELECT started_at_ms FROM records WHERE id=?1", [id], |row| row.get::<_, i64>(0))
        .map(|started| now_ms().saturating_sub(started))
        .unwrap_or_default()
}

fn prune_records(connection: &Connection, max_records: usize) -> Result<(), rusqlite::Error> {
    connection.execute(
        "DELETE FROM records WHERE sequence IN (
            SELECT sequence FROM records ORDER BY sequence DESC LIMIT -1 OFFSET ?1
        )",
        [max_records as i64],
    )?;
    Ok(())
}

async fn run_db<T, F>(path: PathBuf, operation: F) -> Result<T, ManagerError>
where
    T: Send + 'static,
    F: FnOnce(&Connection) -> Result<T, rusqlite::Error> + Send + 'static,
{
    tokio::task::spawn_blocking(move || -> Result<T, ManagerError> {
        let connection = open_connection(&path)?;
        operation(&connection).map_err(ManagerError::from)
    })
    .await
    .map_err(|error| ManagerError::Database(format!("SQLite task failed: {error}")))?
}

fn query_records(connection: &Connection, query: &RecordQuery) -> Result<RecordPage, rusqlite::Error> {
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_LIMIT).clamp(1, MAX_PAGE_LIMIT);
    let mut sql = String::from(
        "SELECT id, started_at_ms, completed_at_ms, client_ip, proxy_username, authority, host, path, query,
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
        sequences.push(row.get::<_, i64>(13)?);
    }
    let has_more = records.len() > limit;
    if has_more {
        records.truncate(limit);
        sequences.truncate(limit);
    }
    Ok(RecordPage {
        next_before: has_more.then(|| sequences.last().copied()).flatten(),
        records,
    })
}

fn get_record(connection: &Connection, id: &str) -> Result<Option<RecordDetail>, rusqlite::Error> {
    connection
        .query_row(
            "SELECT id, started_at_ms, completed_at_ms, client_ip, proxy_username, authority, host, path, query,
                method, response_status, duration_ms, capture_state, request_version, request_headers_json,
                request_body, request_body_bytes, request_body_truncated, request_body_note, response_version,
                response_headers_json, response_body, response_body_bytes, response_body_truncated,
                response_body_note, error FROM records WHERE id=?1",
            [id],
            |row| {
                let request_headers_json: String = row.get(14)?;
                let response_headers_json: String = row.get(20)?;
                Ok(RecordDetail {
                    summary: RecordSummary {
                        id: row.get(0)?,
                        started_at_ms: row.get(1)?,
                        completed_at_ms: row.get(2)?,
                        client_ip: row.get(3)?,
                        proxy_username: row.get(4)?,
                        authority: row.get(5)?,
                        host: row.get(6)?,
                        path: row.get(7)?,
                        query: row.get(8)?,
                        method: row.get(9)?,
                        status: row.get(10)?,
                        duration_ms: row.get(11)?,
                        capture_state: row.get(12)?,
                    },
                    request_version: row.get(13)?,
                    request_headers: serde_json::from_str(&request_headers_json)
                        .unwrap_or(serde_json::Value::Array(Vec::new())),
                    request_body: row.get(15)?,
                    request_body_bytes: row.get(16)?,
                    request_body_truncated: row.get(17)?,
                    request_body_note: row.get(18)?,
                    response_version: row.get(19)?,
                    response_headers: serde_json::from_str(&response_headers_json)
                        .unwrap_or(serde_json::Value::Array(Vec::new())),
                    response_body: row.get(21)?,
                    response_body_bytes: row.get(22)?,
                    response_body_truncated: row.get(23)?,
                    response_body_note: row.get(24)?,
                    error: row.get(25)?,
                })
            },
        )
        .optional()
}

fn summary_from_row(row: &rusqlite::Row<'_>) -> Result<RecordSummary, rusqlite::Error> {
    Ok(RecordSummary {
        id: row.get(0)?,
        started_at_ms: row.get(1)?,
        completed_at_ms: row.get(2)?,
        client_ip: row.get(3)?,
        proxy_username: row.get(4)?,
        authority: row.get(5)?,
        host: row.get(6)?,
        path: row.get(7)?,
        query: row.get(8)?,
        method: row.get(9)?,
        status: row.get(10)?,
        duration_ms: row.get(11)?,
        capture_state: row.get(12)?,
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

    #[tokio::test]
    async fn persists_settings_and_replaces_targets_from_cli() -> Result<(), DynError> {
        let path = test_db("settings");
        let manager = MitmManager::open(path.clone(), true, &["Example.COM".to_owned()], false, 10_000, 65_536)?;
        assert!(manager.should_mitm("api.example.com"));
        manager
            .patch_settings(MitmSettingsPatch {
                mitm_enabled: None,
                capture_enabled: Some(true),
                max_records: Some(321),
                body_limit_bytes: Some(16_384),
            })
            .await?;
        let target = manager.add_target(".Second.Example.".to_owned()).await?;
        assert_eq!(target.suffix, "second.example");
        drop(manager);
        tokio::time::sleep(Duration::from_millis(300)).await;

        let reopened = MitmManager::open(path.clone(), true, &["Override.Example".to_owned()], false, 1, 1024)?;
        let settings = reopened.settings();
        assert!(settings.capture_enabled);
        assert_eq!(settings.max_records, 321);
        assert_eq!(settings.body_limit_bytes, 16_384);
        assert_eq!(reopened.targets().len(), 1);
        assert_eq!(reopened.targets()[0].suffix, "override.example");
        assert!(reopened.should_mitm("www.override.example"));
        assert!(!reopened.should_mitm("www.second.example"));
        drop(reopened);
        tokio::time::sleep(Duration::from_millis(300)).await;

        let reopened_without_targets = MitmManager::open(path.clone(), true, &[], false, 1, 1024)?;
        assert!(reopened_without_targets.targets().is_empty());
        assert!(!reopened_without_targets.should_mitm("www.override.example"));
        drop(reopened_without_targets);
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
        manager.finish_body(&id, BodyDirection::Request, None);
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
        manager.finish_body(&id, BodyDirection::Response, None);
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
}
