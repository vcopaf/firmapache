mod commands;

use mini_firmador::{
    config::AppConfig,
    init_tracing,
    server::{self, AppState},
};
use tauri::Manager;

fn main() {
    init_tracing();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let config = AppConfig::load()?;
            let state = AppState::new(config);
            let server_state = state.clone();
            app.manage(state);

            tauri::async_runtime::spawn(async move {
                if let Err(error) = server::serve(server_state).await {
                    tracing::error!(%error, "embedded local service stopped");
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::get_config,
            commands::save_config,
            commands::select_pkcs11_library,
            commands::list_tokens,
            commands::list_certificates,
            commands::list_signing_sessions,
            commands::approve_signing_session,
            commands::reject_signing_session,
        ])
        .run(tauri::generate_context!())
        .expect("could not run MiniFirmador desktop application");
}
