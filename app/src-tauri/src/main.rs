// Em release, não abre uma janela de console junto com o aplicativo.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use tauri::Manager;
use tkv_core::{Database, Quarantine, SignatureDb};

use commands::AppState;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let data_dir = tkv_core::default_data_dir();
            let db = Database::open(&data_dir.join("tkv.db"))?;
            let quarantine = Quarantine::open(data_dir.join("quarantine"))?;

            let mut signatures = SignatureDb::with_builtin();
            // Assinaturas extras opcionais em <dados>\signatures.txt
            let extra = data_dir.join("signatures.txt");
            if extra.is_file() {
                signatures.load_file(&extra)?;
            }

            app.manage(AppState {
                data_dir,
                db: Mutex::new(db),
                quarantine,
                signatures,
                scanning: AtomicBool::new(false),
                cancel: Arc::new(AtomicBool::new(false)),
                sys: Mutex::new(sysinfo::System::new()),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::start_scan,
            commands::cancel_scan,
            commands::history,
            commands::scan_details,
            commands::quarantine_list,
            commands::quarantine_add,
            commands::quarantine_restore,
            commands::quarantine_delete,
            commands::get_settings,
            commands::save_settings,
            commands::metrics,
        ])
        .run(tauri::generate_context!())
        .expect("falha ao iniciar o THUGAS KILL VIRUS");
}
