//! `tkv` — linha de comando do THUGAS KILL VIRUS.
//!
//! Exemplos:
//!   tkv scan C:\Users\voce\Downloads
//!   tkv scan . --signatures signatures\hashes.txt --json
//!   tkv hash arquivo.exe
//!
//! Códigos de saída: 0 = nada encontrado, 1 = ameaças/suspeitos, 2 = erro.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tkv_core::analysis::analyze_file;
use tkv_core::{ScanConfig, Scanner, SignatureDb, Verdict};

#[derive(Parser)]
#[command(name = "tkv", version, about = "THUGAS KILL VIRUS — scanner de linha de comando")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Varre um arquivo ou pasta
    Scan {
        /// Arquivo ou pasta a verificar
        path: PathBuf,
        /// Arquivo de assinaturas adicional (formato '<sha256>;<nome>')
        #[arg(short, long)]
        signatures: Option<PathBuf>,
        /// Tamanho máximo de arquivo em MB (0 = sem limite)
        #[arg(long, default_value_t = 512)]
        max_size_mb: u64,
        /// Saída em JSON (para integração com a interface)
        #[arg(long)]
        json: bool,
    },
    /// Mostra SHA-256, tamanho e entropia de um arquivo
    Hash { file: PathBuf },
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

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.command {
        Command::Hash { file } => {
            let facts = analyze_file(&file).map_err(|e| e.to_string())?;
            println!("arquivo : {}", file.display());
            println!("sha256  : {}", facts.sha256);
            println!("tamanho : {} bytes", facts.size);
            println!("entropia: {:.4} bits/byte", facts.entropy);
            println!("PE      : {}", if facts.is_pe() { "sim" } else { "não" });
            Ok(ExitCode::SUCCESS)
        }
        Command::Scan {
            path,
            signatures,
            max_size_mb,
            json,
        } => {
            let mut db = SignatureDb::with_builtin();
            if let Some(sig) = &signatures {
                db.load_file(sig).map_err(|e| e.to_string())?;
            }
            let config = ScanConfig {
                max_file_size: max_size_mb.saturating_mul(1024 * 1024),
                ..ScanConfig::default()
            };
            let scanner = Scanner::new(db, config);
            if !json {
                println!(
                    "THUGAS KILL VIRUS — verificando '{}' ({} assinaturas)\n",
                    path.display(),
                    scanner.signatures().len()
                );
            }

            let report = scanner.scan_path(&path, |_| {});

            if json {
                let out = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
                println!("{out}");
            } else {
                for d in &report.detections {
                    let label = match d.verdict {
                        Verdict::Malicious => "MALICIOSO",
                        Verdict::Suspicious => "SUSPEITO ",
                        Verdict::Clean => "LIMPO    ",
                    };
                    println!("[{label}] risco {:>3}  {}", d.risk_score, d.path.display());
                    for ind in &d.indicators {
                        println!("             - {}", ind.description);
                    }
                }
                for e in &report.errors {
                    println!("[ERRO     ] {}: {}", e.path.display(), e.message);
                }
                println!(
                    "\n{} arquivo(s), {:.1} MB em {:.2}s | {} detecção(ões) | {} erro(s) | {} ignorado(s) por tamanho",
                    report.files_scanned,
                    report.bytes_scanned as f64 / (1024.0 * 1024.0),
                    report.elapsed.as_secs_f64(),
                    report.detections.len(),
                    report.errors.len(),
                    report.skipped_too_large,
                );
            }

            Ok(if report.has_threats() {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
    }
}
