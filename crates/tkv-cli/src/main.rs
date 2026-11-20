//! `tkv` — linha de comando do THUGAS KILL VIRUS.
//!
//! Exemplos:
//!   tkv scan C:\Users\voce\Downloads
//!   tkv scan . --quarantine
//!   tkv history
//!   tkv history 3
//!   tkv quarantine list
//!   tkv quarantine add arquivo.exe
//!   tkv quarantine restore <id>
//!   tkv quarantine delete <id>
//!   tkv hash arquivo.exe
//!
//! Dados (banco e quarentena) ficam em %LOCALAPPDATA%\ThugasKillVirus,
//! ou no diretório indicado por --data-dir.
//!
//! Códigos de saída: 0 = nada encontrado, 1 = ameaças/suspeitos, 2 = erro.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tkv_core::analysis::analyze_file;
use tkv_core::{Database, Quarantine, ScanConfig, Scanner, SignatureDb, Verdict};

#[derive(Parser)]
#[command(name = "tkv", version, about = "THUGAS KILL VIRUS — linha de comando")]
struct Cli {
    /// Diretório de dados (banco e quarentena)
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Varre um arquivo ou pasta e grava no histórico
    Scan {
        /// Arquivo ou pasta a verificar
        path: PathBuf,
        /// Arquivo de assinaturas adicional (formato '<sha256>;<nome>')
        #[arg(short, long)]
        signatures: Option<PathBuf>,
        /// Tamanho máximo de arquivo em MB (0 = sem limite)
        #[arg(long, default_value_t = 512)]
        max_size_mb: u64,
        /// Move para a quarentena os arquivos MALICIOSOS (suspeitos só são relatados)
        #[arg(short, long)]
        quarantine: bool,
        /// Saída em JSON (para integração com a interface)
        #[arg(long)]
        json: bool,
    },
    /// Lista as últimas varreduras, ou as detecções de uma varredura
    History {
        /// Id da varredura para ver os detalhes
        scan_id: Option<i64>,
        /// Quantidade de varreduras listadas
        #[arg(short, long, default_value_t = 10)]
        limit: usize,
    },
    /// Gerencia a quarentena
    Quarantine {
        #[command(subcommand)]
        action: QuarantineAction,
    },
    /// Mostra SHA-256, tamanho e entropia de um arquivo
    Hash { file: PathBuf },
}

#[derive(Subcommand)]
enum QuarantineAction {
    /// Lista os itens em quarentena
    List {
        /// Inclui itens já restaurados ou excluídos
        #[arg(short, long)]
        all: bool,
    },
    /// Coloca um arquivo em quarentena manualmente
    Add { file: PathBuf },
    /// Restaura um item para o local original
    Restore {
        id: String,
        /// Substitui o arquivo se já existir outro no local original
        #[arg(long)]
        overwrite: bool,
    },
    /// Exclui definitivamente um item da quarentena
    Delete { id: String },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("erro: {msg}");
            ExitCode::from(2)
        }
    }
}

fn data_dir(cli_value: Option<PathBuf>) -> PathBuf {
    cli_value.unwrap_or_else(|| {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("ThugasKillVirus")
    })
}

struct Store {
    db: Database,
    quarantine: Quarantine,
}

fn open_store(dir: &Path) -> Result<Store, String> {
    let db = Database::open(&dir.join("tkv.db")).map_err(|e| e.to_string())?;
    let quarantine = Quarantine::open(dir.join("quarantine")).map_err(|e| e.to_string())?;
    Ok(Store { db, quarantine })
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    let dir = data_dir(cli.data_dir);
    match cli.command {
        Command::Hash { file } => cmd_hash(&file),
        Command::Scan {
            path,
            signatures,
            max_size_mb,
            quarantine,
            json,
        } => cmd_scan(&dir, &path, signatures.as_deref(), max_size_mb, quarantine, json),
        Command::History { scan_id, limit } => cmd_history(&dir, scan_id, limit),
        Command::Quarantine { action } => cmd_quarantine(&dir, action),
    }
}

fn cmd_hash(file: &Path) -> Result<ExitCode, String> {
    let facts = analyze_file(file).map_err(|e| e.to_string())?;
    println!("arquivo : {}", file.display());
    println!("sha256  : {}", facts.sha256);
    println!("tamanho : {} bytes", facts.size);
    println!("entropia: {:.4} bits/byte", facts.entropy);
    println!("PE      : {}", if facts.is_pe() { "sim" } else { "não" });
    Ok(ExitCode::SUCCESS)
}

fn verdict_label(v: Verdict) -> &'static str {
    match v {
        Verdict::Malicious => "MALICIOSO",
        Verdict::Suspicious => "SUSPEITO ",
        Verdict::Clean => "LIMPO    ",
    }
}

fn cmd_scan(
    dir: &Path,
    path: &Path,
    signatures: Option<&Path>,
    max_size_mb: u64,
    quarantine: bool,
    json: bool,
) -> Result<ExitCode, String> {
    let store = open_store(dir)?;
    let mut db = SignatureDb::with_builtin();
    if let Some(sig) = signatures {
        db.load_file(sig).map_err(|e| e.to_string())?;
    }
    let config = ScanConfig {
        max_file_size: max_size_mb.saturating_mul(1024 * 1024),
        ..ScanConfig::default()
    };
    let scanner = Scanner::new(db, config);
    let target = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());

    if !json {
        println!(
            "THUGAS KILL VIRUS — verificando '{}' ({} assinaturas)\n",
            target.display(),
            scanner.signatures().len()
        );
    }

    let report = scanner.scan_path(&target, |_| {});
    let scan_id = store
        .db
        .record_scan(&target.to_string_lossy(), &report)
        .map_err(|e| e.to_string())?;

    // Quarentena automática apenas para veredito MALICIOSO (assinatura confirmada).
    let mut quarantined = Vec::new();
    let mut quarantine_errors = Vec::new();
    if quarantine {
        for d in report
            .detections
            .iter()
            .filter(|d| d.verdict == Verdict::Malicious)
        {
            match store
                .quarantine
                .add(&store.db, &d.path, d.threat_name.as_deref(), d.risk_score)
            {
                Ok(item) => quarantined.push(item),
                Err(e) => quarantine_errors.push(format!("{}: {e}", d.path.display())),
            }
        }
    }

    if json {
        let out = serde_json::json!({
            "scan_id": scan_id,
            "report": report,
            "quarantined": quarantined,
            "quarantine_errors": quarantine_errors,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?
        );
    } else {
        for d in &report.detections {
            println!(
                "[{}] risco {:>3}  {}",
                verdict_label(d.verdict),
                d.risk_score,
                d.path.display()
            );
            for ind in &d.indicators {
                println!("             - {}", ind.description);
            }
        }
        for e in &report.errors {
            println!("[ERRO     ] {}: {}", e.path.display(), e.message);
        }
        for item in &quarantined {
            println!(
                "[QUARENTENA] {}  (id {})",
                item.original_path.display(),
                item.id
            );
        }
        for e in &quarantine_errors {
            println!("[FALHA QUARENTENA] {e}");
        }
        println!(
            "\nVarredura #{scan_id}: {} arquivo(s), {:.1} MB em {:.2}s | {} detecção(ões) | \
             {} em quarentena | {} erro(s) | {} ignorado(s) por tamanho",
            report.files_scanned,
            report.bytes_scanned as f64 / (1024.0 * 1024.0),
            report.elapsed.as_secs_f64(),
            report.detections.len(),
            quarantined.len(),
            report.errors.len(),
            report.skipped_too_large,
        );
        let pending = report
            .detections
            .iter()
            .any(|d| d.verdict == Verdict::Malicious)
            && !quarantine;
        if pending {
            println!("Dica: use --quarantine para isolar os arquivos maliciosos.");
        }
    }

    Ok(if report.has_threats() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn cmd_history(dir: &Path, scan_id: Option<i64>, limit: usize) -> Result<ExitCode, String> {
    let store = open_store(dir)?;
    match scan_id {
        None => {
            let scans = store.db.recent_scans(limit).map_err(|e| e.to_string())?;
            if scans.is_empty() {
                println!("Nenhuma varredura registrada.");
            }
            for s in scans {
                println!(
                    "#{:<4} {}  {:>6} arq.  {:>3} det.  {:>3} erros  {:>7.2}s  {}",
                    s.id,
                    s.finished_at,
                    s.files_scanned,
                    s.detections,
                    s.errors,
                    s.duration_ms as f64 / 1000.0,
                    s.target
                );
            }
        }
        Some(id) => {
            let dets = store.db.scan_detections(id).map_err(|e| e.to_string())?;
            if dets.is_empty() {
                println!("Varredura #{id}: nenhuma detecção (ou varredura inexistente).");
            }
            for d in dets {
                let label = match d.verdict.as_str() {
                    "malicious" => verdict_label(Verdict::Malicious),
                    "suspicious" => verdict_label(Verdict::Suspicious),
                    _ => verdict_label(Verdict::Clean),
                };
                println!("[{label}] risco {:>3}  {}", d.risk_score, d.path);
                if let Some(name) = &d.threat_name {
                    println!("              ameaça: {name}");
                }
                println!("              sha256: {}", d.sha256);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_quarantine(dir: &Path, action: QuarantineAction) -> Result<ExitCode, String> {
    let store = open_store(dir)?;
    match action {
        QuarantineAction::List { all } => {
            let items = store
                .db
                .quarantine_items(all)
                .map_err(|e| e.to_string())?;
            if items.is_empty() {
                println!("Quarentena vazia.");
            }
            for i in items {
                println!(
                    "{}  {}  {:<11}  risco {:>3}  {}  {}",
                    i.id,
                    i.quarantined_at,
                    i.status.as_str(),
                    i.risk_score,
                    i.threat_name.as_deref().unwrap_or("-"),
                    i.original_path.display()
                );
            }
        }
        QuarantineAction::Add { file } => {
            // Analisa antes para registrar nome da ameaça e risco.
            let scanner = Scanner::new(SignatureDb::with_builtin(), ScanConfig::default());
            let det = scanner.scan_file(&file).map_err(|e| e.to_string())?;
            let item = store
                .quarantine
                .add(&store.db, &file, det.threat_name.as_deref(), det.risk_score)
                .map_err(|e| e.to_string())?;
            println!(
                "Arquivo isolado: {} (id {})",
                item.original_path.display(),
                item.id
            );
        }
        QuarantineAction::Restore { id, overwrite } => {
            let item = store
                .quarantine
                .restore(&store.db, &id, overwrite)
                .map_err(|e| e.to_string())?;
            println!("Restaurado em {}", item.original_path.display());
        }
        QuarantineAction::Delete { id } => {
            let item = store
                .quarantine
                .delete(&store.db, &id)
                .map_err(|e| e.to_string())?;
            println!(
                "Excluído definitivamente: {}",
                item.original_path.display()
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}
