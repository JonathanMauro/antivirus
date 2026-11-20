//! Comandos expostos à interface (chamados via `invoke` no JavaScript).
//!
//! Nesta fase o aplicativo executa as operações no próprio processo, com as
//! permissões do usuário. Na Fase 3 elas migram para um serviço Windows e
//! estes comandos passam a ser apenas clientes IPC desse serviço.

use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde::Serialize;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
use tauri::{AppHandle, Emitter, State};
use tkv_core::storage::{ScanSummary, StoredDetection};
use tkv_core::{
    Database, Detection, Quarantine, QuarantineItem, ScanConfig, Scanner, SignatureDb, Verdict,
    YaraRules,
};

const KEY_AUTO_QUARANTINE: &str = "auto_quarantine";
const KEY_MAX_FILE_SIZE_MB: &str = "max_file_size_mb";
const DEFAULT_MAX_FILE_SIZE_MB: u64 = 512;
const PROGRESS_INTERVAL: Duration = Duration::from_millis(120);

pub struct AppState {
    pub data_dir: PathBuf,
    pub db: Mutex<Database>,
    pub quarantine: Quarantine,
    pub signatures: SignatureDb,
    pub yara: Option<Arc<YaraRules>>,
    /// Erro de compilação das regras YARA, exibido no painel.
    pub yara_error: Option<String>,
    pub scanning: AtomicBool,
    pub cancel: Arc<AtomicBool>,
    pub sys: Mutex<System>,
}

impl AppState {
    fn db(&self) -> Result<MutexGuard<'_, Database>, String> {
        self.db
            .lock()
            .map_err(|_| "banco de dados indisponível".to_string())
    }

    /// Scanner com assinaturas e regras YARA carregadas.
    fn scanner(&self, config: ScanConfig) -> Scanner {
        let scanner = Scanner::new(self.signatures.clone(), config);
        match &self.yara {
            Some(rules) => scanner.with_yara(rules.clone()),
            None => scanner,
        }
    }
}

fn err(e: impl ToString) -> String {
    e.to_string()
}

// ------------------------------------------------------------------ status

#[derive(Serialize)]
pub struct Status {
    version: &'static str,
    signatures: usize,
    yara_rules: usize,
    yara_error: Option<String>,
    quarantined: usize,
    last_scan: Option<ScanSummary>,
    data_dir: String,
    scanning: bool,
}

#[tauri::command]
pub fn get_status(state: State<'_, AppState>) -> Result<Status, String> {
    let db = state.db()?;
    Ok(Status {
        version: env!("CARGO_PKG_VERSION"),
        signatures: state.signatures.len(),
        yara_rules: state.yara.as_ref().map_or(0, |r| r.len()),
        yara_error: state.yara_error.clone(),
        quarantined: db.quarantine_items(false).map_err(err)?.len(),
        last_scan: db.recent_scans(1).map_err(err)?.into_iter().next(),
        data_dir: state.data_dir.display().to_string(),
        scanning: state.scanning.load(Ordering::SeqCst),
    })
}

// -------------------------------------------------------------------- scan

#[derive(Serialize, Clone)]
struct Progress {
    files: u64,
    current: String,
}

#[derive(Serialize)]
pub struct ScanOutcome {
    scan_id: i64,
    label: String,
    files_scanned: u64,
    bytes_scanned: u64,
    skipped_too_large: u64,
    elapsed_ms: u128,
    cancelled: bool,
    errors: usize,
    detections: Vec<Detection>,
    quarantined: Vec<QuarantineItem>,
    quarantine_errors: Vec<String>,
}

/// Libera a flag de "verificação em andamento" mesmo se houver erro.
struct ScanGuard<'a>(&'a AtomicBool);
impl Drop for ScanGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Locais mais visados por malware em uma máquina de usuário.
fn quick_scan_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(home) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
        for sub in ["Desktop", "Downloads", "Documents"] {
            roots.push(home.join(sub));
        }
    }
    if let Some(tmp) = std::env::var_os("TEMP") {
        roots.push(PathBuf::from(tmp));
    }
    if let Some(appdata) = std::env::var_os("APPDATA").map(PathBuf::from) {
        roots.push(appdata.join(r"Microsoft\Windows\Start Menu\Programs\Startup"));
    }
    roots.retain(|p| p.exists());
    roots
}

/// Todas as unidades existentes (C:\, D:\ ...).
fn all_drives() -> Vec<PathBuf> {
    (b'C'..=b'Z')
        .map(|c| PathBuf::from(format!("{}:\\", c as char)))
        .filter(|p| p.exists())
        .collect()
}

#[tauri::command]
pub async fn start_scan(
    app: AppHandle,
    state: State<'_, AppState>,
    kind: String,
    path: Option<String>,
) -> Result<ScanOutcome, String> {
    let (roots, label) = match kind.as_str() {
        "quick" => (quick_scan_roots(), "Verificação rápida".to_string()),
        "full" => (all_drives(), "Verificação completa".to_string()),
        "custom" => {
            let p = path.ok_or("nenhuma pasta selecionada")?;
            if !Path::new(&p).exists() {
                return Err(format!("'{p}' não existe"));
            }
            (vec![PathBuf::from(&p)], p)
        }
        other => return Err(format!("tipo de verificação desconhecido: {other}")),
    };

    if state.scanning.swap(true, Ordering::SeqCst) {
        return Err("já existe uma verificação em andamento".into());
    }
    let _guard = ScanGuard(&state.scanning);
    state.cancel.store(false, Ordering::SeqCst);

    let (auto_quarantine, max_mb) = {
        let db = state.db()?;
        read_settings(&db)?
    };
    let scanner = state.scanner(ScanConfig {
        max_file_size: max_mb.saturating_mul(1024 * 1024),
        ..ScanConfig::default()
    });

    let cancel = state.cancel.clone();
    let emitter = app.clone();
    let report = tauri::async_runtime::spawn_blocking(move || {
        let mut files = 0u64;
        let mut last: Option<Instant> = None;
        scanner.scan_paths(&roots, |p| {
            files += 1;
            if last.is_none_or(|t| t.elapsed() >= PROGRESS_INTERVAL) {
                last = Some(Instant::now());
                let _ = emitter.emit(
                    "scan-progress",
                    Progress {
                        files,
                        current: p.display().to_string(),
                    },
                );
            }
            if cancel.load(Ordering::Relaxed) {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
    })
    .await
    .map_err(err)?;

    let db = state.db()?;
    let scan_id = db.record_scan(&label, &report).map_err(err)?;

    // Isolamento automático somente para veredito MALICIOSO.
    let mut quarantined = Vec::new();
    let mut quarantine_errors = Vec::new();
    if auto_quarantine {
        for d in report
            .detections
            .iter()
            .filter(|d| d.verdict == Verdict::Malicious)
        {
            match state
                .quarantine
                .add(&db, &d.path, d.threat_name.as_deref(), d.risk_score)
            {
                Ok(item) => quarantined.push(item),
                Err(e) => quarantine_errors.push(format!("{}: {e}", d.path.display())),
            }
        }
    }

    Ok(ScanOutcome {
        scan_id,
        label,
        files_scanned: report.files_scanned,
        bytes_scanned: report.bytes_scanned,
        skipped_too_large: report.skipped_too_large,
        elapsed_ms: report.elapsed.as_millis(),
        cancelled: report.cancelled,
        errors: report.errors.len(),
        detections: report.detections,
        quarantined,
        quarantine_errors,
    })
}

#[tauri::command]
pub fn cancel_scan(state: State<'_, AppState>) {
    state.cancel.store(true, Ordering::SeqCst);
}

// ----------------------------------------------------------------- history

#[tauri::command]
pub fn history(state: State<'_, AppState>, limit: Option<usize>) -> Result<Vec<ScanSummary>, String> {
    state.db()?.recent_scans(limit.unwrap_or(50)).map_err(err)
}

#[tauri::command]
pub fn scan_details(state: State<'_, AppState>, scan_id: i64) -> Result<Vec<StoredDetection>, String> {
    state.db()?.scan_detections(scan_id).map_err(err)
}

// -------------------------------------------------------------- quarantine

#[tauri::command]
pub fn quarantine_list(
    state: State<'_, AppState>,
    all: Option<bool>,
) -> Result<Vec<QuarantineItem>, String> {
    state
        .db()?
        .quarantine_items(all.unwrap_or(false))
        .map_err(err)
}

#[tauri::command]
pub fn quarantine_add(state: State<'_, AppState>, path: String) -> Result<QuarantineItem, String> {
    let scanner = state.scanner(ScanConfig::default());
    let det = scanner.scan_file(Path::new(&path)).map_err(err)?;
    let db = state.db()?;
    state
        .quarantine
        .add(&db, Path::new(&path), det.threat_name.as_deref(), det.risk_score)
        .map_err(err)
}

#[tauri::command]
pub fn quarantine_restore(
    state: State<'_, AppState>,
    id: String,
    overwrite: Option<bool>,
) -> Result<QuarantineItem, String> {
    let db = state.db()?;
    state
        .quarantine
        .restore(&db, &id, overwrite.unwrap_or(false))
        .map_err(err)
}

#[tauri::command]
pub fn quarantine_delete(state: State<'_, AppState>, id: String) -> Result<QuarantineItem, String> {
    let db = state.db()?;
    state.quarantine.delete(&db, &id).map_err(err)
}

// ---------------------------------------------------------------- settings

#[derive(Serialize)]
pub struct Settings {
    auto_quarantine: bool,
    max_file_size_mb: u64,
    data_dir: String,
}

fn read_settings(db: &Database) -> Result<(bool, u64), String> {
    let auto = db
        .get_setting(KEY_AUTO_QUARANTINE)
        .map_err(err)?
        .map(|v| v != "false")
        .unwrap_or(true);
    let max = db
        .get_setting(KEY_MAX_FILE_SIZE_MB)
        .map_err(err)?
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_FILE_SIZE_MB);
    Ok((auto, max))
}

#[tauri::command]
pub fn get_settings(state: State<'_, AppState>) -> Result<Settings, String> {
    let (auto_quarantine, max_file_size_mb) = read_settings(&*state.db()?)?;
    Ok(Settings {
        auto_quarantine,
        max_file_size_mb,
        data_dir: state.data_dir.display().to_string(),
    })
}

#[tauri::command]
pub fn save_settings(
    state: State<'_, AppState>,
    auto_quarantine: bool,
    max_file_size_mb: u64,
) -> Result<(), String> {
    if max_file_size_mb > 100_000 {
        return Err("tamanho máximo inválido".into());
    }
    let db = state.db()?;
    db.set_setting(KEY_AUTO_QUARANTINE, if auto_quarantine { "true" } else { "false" })
        .map_err(err)?;
    db.set_setting(KEY_MAX_FILE_SIZE_MB, &max_file_size_mb.to_string())
        .map_err(err)?;
    Ok(())
}

// ----------------------------------------------------------------- metrics

#[derive(Serialize)]
pub struct Metrics {
    /// CPU do processo principal, em % do total da máquina.
    app_cpu: f32,
    app_memory_mb: f64,
    system_cpu: f32,
    system_memory_used_mb: f64,
    system_memory_total_mb: f64,
}

#[tauri::command]
pub fn metrics(state: State<'_, AppState>) -> Result<Metrics, String> {
    let mut sys = state
        .sys
        .lock()
        .map_err(|_| "métricas indisponíveis".to_string())?;
    let pid = sysinfo::get_current_pid().map_err(err)?;

    sys.refresh_cpu_usage();
    sys.refresh_memory();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing().with_cpu().with_memory(),
    );

    let cpus = sys.cpus().len().max(1) as f32;
    let (app_cpu, app_mem) = sys
        .process(pid)
        .map(|p| (p.cpu_usage() / cpus, p.memory()))
        .unwrap_or((0.0, 0));
    const MB: f64 = 1024.0 * 1024.0;
    Ok(Metrics {
        app_cpu,
        app_memory_mb: app_mem as f64 / MB,
        system_cpu: sys.global_cpu_usage(),
        system_memory_used_mb: sys.used_memory() as f64 / MB,
        system_memory_total_mb: sys.total_memory() as f64 / MB,
    })
}
