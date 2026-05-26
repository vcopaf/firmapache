use mini_firmador::{
    config::AppConfig,
    core::pkcs11::provider,
    models::{
        pkcs11::{CertificateInfo, TokenInfo},
        signing::SigningSession,
    },
    server::AppState,
};
use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

#[derive(Serialize)]
pub struct ServiceStatus {
    service: &'static str,
    version: &'static str,
    active: bool,
    https: bool,
    port: u16,
    pkcs11_library_path: Option<String>,
}

#[tauri::command]
pub fn get_status(state: State<'_, AppState>) -> Result<ServiceStatus, String> {
    let config = current_config(&state)?;
    let pkcs11_library_path = provider::detect_pkcs11_library(&config)
        .ok()
        .and_then(|library| library.path);

    Ok(ServiceStatus {
        service: "mini-firmador",
        version: env!("CARGO_PKG_VERSION"),
        active: true,
        https: config.server.https,
        port: config.server.port,
        pkcs11_library_path,
    })
}

#[tauri::command]
pub fn get_config(state: State<'_, AppState>) -> Result<AppConfig, String> {
    current_config(&state)
}

#[tauri::command]
pub fn save_config(state: State<'_, AppState>, config: AppConfig) -> Result<AppConfig, String> {
    config.save().map_err(|error| error.to_string())?;
    state
        .replace_config(config.clone())
        .map_err(|error| error.to_string())?;
    Ok(config)
}

#[tauri::command]
pub async fn select_pkcs11_library(app: AppHandle) -> Result<Option<String>, String> {
    let selection = app.dialog().file().blocking_pick_file();
    let Some(selection) = selection else {
        return Ok(None);
    };
    let path = selection
        .into_path()
        .map_err(|error| format!("No se pudo obtener la ruta seleccionada: {error}"))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if !(file_name.ends_with(".so") || file_name.contains(".so.")) {
        return Err("Seleccione una biblioteca compartida .so o .so.*".to_owned());
    }

    Ok(Some(path.to_string_lossy().into_owned()))
}

#[tauri::command]
pub async fn list_tokens(state: State<'_, AppState>) -> Result<Vec<TokenInfo>, String> {
    let config = current_config(&state)?;
    tauri::async_runtime::spawn_blocking(move || provider::list_tokens(&config))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn list_certificates(state: State<'_, AppState>) -> Result<Vec<CertificateInfo>, String> {
    let config = current_config(&state)?;
    tauri::async_runtime::spawn_blocking(move || provider::list_certificates(&config))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn list_signing_sessions(state: State<'_, AppState>) -> Result<Vec<SigningSession>, String> {
    state
        .signing_sessions()
        .list()
        .map_err(|error| error.to_string())
}

fn current_config(state: &State<'_, AppState>) -> Result<AppConfig, String> {
    state.config().map_err(|error| error.to_string())
}
