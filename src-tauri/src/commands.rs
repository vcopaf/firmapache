use mini_firmador::{
    config::AppConfig,
    core::pkcs11::provider,
    models::{
        compatible::CompatibleSignResponse,
        pkcs11::{CertificateInfo, TokenInfo},
        signing::{ApproveSigningSessionInput, SigningSession, SigningSessionStatus},
    },
    server::{self, AppState},
};
use serde::Serialize;
use std::sync::Mutex;
use tauri::{AppHandle, Manager, State, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;

const SIGNING_WINDOW_LABEL: &str = "signing";

pub struct DesktopState {
    server_task: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
}

impl DesktopState {
    pub fn new() -> Self {
        Self {
            server_task: Mutex::new(None),
        }
    }
}

#[derive(Serialize)]
pub struct ServiceStatus {
    service: &'static str,
    version: &'static str,
    active: bool,
    https: bool,
    port: u16,
    pkcs11_library_path: Option<String>,
}

#[derive(Serialize)]
pub struct SigningSessionView {
    id: String,
    files: Vec<SigningSessionFileView>,
    format: String,
    language: Option<String>,
    status: &'static str,
    created_at: String,
}

#[derive(Serialize)]
pub struct SigningSessionFileView {
    name: String,
    approximate_size_bytes: usize,
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
pub fn list_signing_sessions(
    state: State<'_, AppState>,
) -> Result<Vec<SigningSessionView>, String> {
    state
        .signing_sessions()
        .list()
        .map(|sessions| sessions.into_iter().map(session_view).collect())
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn approve_signing_session(
    state: State<'_, AppState>,
    session_id: String,
    slot_id: u64,
    certificate_id: String,
    pin: String,
) -> Result<CompatibleSignResponse, String> {
    if certificate_id.trim().is_empty() {
        return Err("Missing certificate selection".to_owned());
    }
    if pin.is_empty() {
        return Err("Missing PIN".to_owned());
    }

    let id = parse_session_id(&session_id)?;
    let config = current_config(&state)?;
    let manager = state.signing_sessions().clone();
    tauri::async_runtime::spawn_blocking(move || {
        manager.approve_with_jws(
            id,
            &config,
            ApproveSigningSessionInput {
                slot_id,
                certificate_id,
                pin,
            },
        )
    })
    .await
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn show_main_window(app: AppHandle) -> Result<(), String> {
    show_main_window_for_app(&app)
}

#[tauri::command]
pub fn show_signing_window(app: AppHandle) -> Result<(), String> {
    show_signing_window_for_app(&app)
}

#[tauri::command]
pub fn hide_signing_window(app: AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window(SIGNING_WINDOW_LABEL) {
        window.hide().map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub fn restart_server(
    state: State<'_, AppState>,
    desktop: State<'_, DesktopState>,
) -> Result<(), String> {
    start_embedded_server(&desktop, state.inner().clone())
}

#[tauri::command]
pub fn reject_signing_session(
    state: State<'_, AppState>,
    session_id: String,
) -> Result<SigningSessionView, String> {
    state
        .signing_sessions()
        .reject(parse_session_id(&session_id)?)
        .map(session_view)
        .map_err(|error| error.to_string())
}

fn current_config(state: &State<'_, AppState>) -> Result<AppConfig, String> {
    state.config().map_err(|error| error.to_string())
}

pub fn start_embedded_server(desktop: &DesktopState, state: AppState) -> Result<(), String> {
    let mut server_task = desktop
        .server_task
        .lock()
        .map_err(|_| "server runtime lock is unavailable".to_owned())?;
    if let Some(task) = server_task.take() {
        task.abort();
    }

    *server_task = Some(tauri::async_runtime::spawn(async move {
        if let Err(error) = server::serve(state).await {
            tracing::error!(%error, "embedded local service stopped");
        }
    }));
    Ok(())
}

pub fn show_main_window_for_app(app: &AppHandle) -> Result<(), String> {
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| "main window not found".to_owned())?;
    window.show().map_err(|error| error.to_string())?;
    window.unminimize().map_err(|error| error.to_string())?;
    window.set_focus().map_err(|error| error.to_string())
}

pub fn show_signing_window_for_app(app: &AppHandle) -> Result<(), String> {
    let window = match app.get_webview_window(SIGNING_WINDOW_LABEL) {
        Some(window) => window,
        None => {
            let window = WebviewWindowBuilder::new(
                app,
                SIGNING_WINDOW_LABEL,
                WebviewUrl::App("index.html?window=signing".into()),
            )
            .title("Solicitud de firma - MiniFirmador")
            .inner_size(620.0, 720.0)
            .min_inner_size(520.0, 560.0)
            .resizable(false)
            .always_on_top(true)
            .focused(true)
            .center()
            .build()
            .map_err(|error| error.to_string())?;
            let close_window = window.clone();
            window.on_window_event(move |event| {
                if let WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = close_window.hide();
                }
            });
            window
        }
    };

    window.show().map_err(|error| error.to_string())?;
    window.unminimize().map_err(|error| error.to_string())?;
    window.center().map_err(|error| error.to_string())?;
    window
        .set_always_on_top(true)
        .map_err(|error| error.to_string())?;
    window.set_focus().map_err(|error| error.to_string())
}

fn parse_session_id(session_id: &str) -> Result<Uuid, String> {
    Uuid::parse_str(session_id).map_err(|_| "Invalid signing session id".to_owned())
}

fn session_view(session: SigningSession) -> SigningSessionView {
    SigningSessionView {
        id: session.id.to_string(),
        files: session
            .files
            .into_iter()
            .map(|file| SigningSessionFileView {
                name: file.name,
                approximate_size_bytes: approximate_decoded_size(&file.content_base64),
            })
            .collect(),
        format: session.format,
        language: session.language,
        status: status_name(session.status),
        created_at: session.created_at.to_rfc3339(),
    }
}

fn approximate_decoded_size(content_base64: &str) -> usize {
    let padding = content_base64
        .as_bytes()
        .iter()
        .rev()
        .take_while(|byte| **byte == b'=')
        .count();
    content_base64
        .len()
        .saturating_mul(3)
        .saturating_div(4)
        .saturating_sub(padding)
}

fn status_name(status: SigningSessionStatus) -> &'static str {
    match status {
        SigningSessionStatus::Pending => "pending",
        SigningSessionStatus::Approved => "approved",
        SigningSessionStatus::Rejected => "rejected",
        SigningSessionStatus::Expired => "expired",
    }
}
