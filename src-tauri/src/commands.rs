use base64::{Engine as _, engine::general_purpose::STANDARD};
use mini_firmador::{
    config::AppConfig,
    core::{
        pdf::{self, PdfDocumentInfo},
        pkcs11::provider,
        signing::jws,
        validation::{
            diagnostics::{self, DiagnosticsReport},
            jws::{self as jws_validation, JwsValidationReport},
            pdf::{self as pdf_validation, PdfValidationReport},
        },
    },
    models::{
        compatible::CompatibleSignResponse,
        pkcs11::{CertificateInfo, TokenInfo},
        signing::{ApproveSigningSessionInput, SigningSession, SigningSessionStatus},
    },
    server::{self, AppState},
};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Instant,
};
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

#[derive(Serialize)]
pub struct SelectedFileToSign {
    path: String,
    name: String,
    size_bytes: u64,
    detected_format: String,
}

#[derive(Serialize)]
pub struct SelectedPdfFile {
    path: String,
    name: String,
    size_bytes: u64,
}

#[derive(Serialize)]
pub struct SelectedManualFile {
    path: String,
    name: String,
    size_bytes: u64,
    detected_type: String,
    output_format: String,
    suggested_file_name: Option<String>,
    supported: bool,
    pdf_info: Option<PdfDocumentInfo>,
}

#[derive(Serialize)]
pub struct SelectedValidationFile {
    path: String,
    name: String,
    size_bytes: u64,
    detected_type: String,
}

#[derive(Serialize)]
pub struct ManualSignResponse {
    jws_base64: String,
    suggested_file_name: String,
}

#[derive(Serialize)]
pub struct PdfSignResponse {
    pdf_base64: String,
    suggested_file_name: String,
}

#[derive(Serialize)]
pub struct SaveSignedFileResponse {
    saved: bool,
    path: Option<String>,
}

#[derive(Serialize)]
pub struct ExportDiagnosticsResponse {
    saved: bool,
    path: Option<String>,
}

#[derive(Serialize)]
pub struct TokenCertificateCacheView {
    tokens: Vec<TokenInfo>,
    certificates: Vec<CertificateInfo>,
    loaded_at: Option<String>,
    pkcs11_library_path: Option<String>,
    token_count: usize,
    certificate_count: usize,
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
pub async fn select_file_to_sign(app: AppHandle) -> Result<Option<SelectedFileToSign>, String> {
    let selection = app
        .dialog()
        .file()
        .add_filter("JSON", &["json"])
        .add_filter("Todos los archivos", &["*"])
        .blocking_pick_file();
    let Some(selection) = selection else {
        return Ok(None);
    };
    let path = selection
        .into_path()
        .map_err(|error| format!("No se pudo obtener la ruta seleccionada: {error}"))?;
    let metadata = fs::metadata(&path)
        .map_err(|error| format!("No se pudo leer informacion del archivo: {error}"))?;
    if !metadata.is_file() {
        return Err("Seleccione un archivo valido".to_owned());
    }

    Ok(Some(SelectedFileToSign {
        name: file_name(&path),
        detected_format: detected_format(&path),
        path: path.to_string_lossy().into_owned(),
        size_bytes: metadata.len(),
    }))
}

#[tauri::command]
pub async fn select_pdf_file(app: AppHandle) -> Result<Option<SelectedPdfFile>, String> {
    let selection = app
        .dialog()
        .file()
        .add_filter("PDF", &["pdf"])
        .add_filter("Todos los archivos", &["*"])
        .blocking_pick_file();
    let Some(selection) = selection else {
        return Ok(None);
    };
    let path = selection
        .into_path()
        .map_err(|error| format!("No se pudo obtener la ruta seleccionada: {error}"))?;
    let metadata = fs::metadata(&path)
        .map_err(|error| format!("No se pudo leer informacion del PDF: {error}"))?;
    if !metadata.is_file() {
        return Err("Seleccione un archivo PDF valido".to_owned());
    }

    Ok(Some(SelectedPdfFile {
        name: file_name(&path),
        path: path.to_string_lossy().into_owned(),
        size_bytes: metadata.len(),
    }))
}

#[tauri::command]
pub async fn select_manual_file(app: AppHandle) -> Result<Option<SelectedManualFile>, String> {
    let selection = app
        .dialog()
        .file()
        .add_filter("JSON y PDF", &["json", "pdf"])
        .add_filter("Todos los archivos", &["*"])
        .blocking_pick_file();
    let Some(selection) = selection else {
        return Ok(None);
    };
    let path = selection
        .into_path()
        .map_err(|error| format!("No se pudo obtener la ruta seleccionada: {error}"))?;
    let metadata = fs::metadata(&path)
        .map_err(|error| format!("No se pudo leer informacion del archivo: {error}"))?;
    if !metadata.is_file() {
        return Err("Seleccione un archivo valido".to_owned());
    }

    Ok(Some(selected_manual_file(path, metadata.len())))
}

#[tauri::command]
pub async fn select_file_to_validate(
    app: AppHandle,
) -> Result<Option<SelectedValidationFile>, String> {
    let selection = app
        .dialog()
        .file()
        .add_filter("Firmados", &["jws", "json", "pdf"])
        .add_filter("Todos los archivos", &["*"])
        .blocking_pick_file();
    let Some(selection) = selection else {
        return Ok(None);
    };
    let path = selection
        .into_path()
        .map_err(|error| format!("No se pudo obtener la ruta seleccionada: {error}"))?;
    let metadata = fs::metadata(&path)
        .map_err(|error| format!("No se pudo leer informacion del archivo: {error}"))?;
    if !metadata.is_file() {
        return Err("Seleccione un archivo valido".to_owned());
    }

    Ok(Some(SelectedValidationFile {
        name: file_name(&path),
        detected_type: validation_file_type(&path),
        path: path.to_string_lossy().into_owned(),
        size_bytes: metadata.len(),
    }))
}

#[tauri::command]
pub async fn inspect_pdf_file(path: String) -> Result<PdfDocumentInfo, String> {
    if path.trim().is_empty() {
        return Err("archivo PDF no seleccionado".to_owned());
    }
    let path = PathBuf::from(path);
    tauri::async_runtime::spawn_blocking(move || mini_firmador::core::pdf::inspect_pdf_file(&path))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn validate_jws_file(path: String) -> Result<JwsValidationReport, String> {
    if path.trim().is_empty() {
        return Err("archivo JWS no seleccionado".to_owned());
    }
    let path = PathBuf::from(path);
    tauri::async_runtime::spawn_blocking(move || {
        let bytes = fs::read(&path).map_err(|error| format!("error leyendo JWS: {error}"))?;
        jws_validation::validate_jws_bytes(&bytes).map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn validate_pdf_file(path: String) -> Result<PdfValidationReport, String> {
    if path.trim().is_empty() {
        return Err("archivo PDF no seleccionado".to_owned());
    }
    let path = PathBuf::from(path);
    tauri::async_runtime::spawn_blocking(move || {
        let bytes = fs::read(&path).map_err(|error| format!("error leyendo PDF: {error}"))?;
        pdf_validation::validate_pdf_bytes(&bytes).map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn sign_file_as_jws(
    state: State<'_, AppState>,
    path: String,
    slot_id: u64,
    certificate_id: String,
    pin: String,
) -> Result<ManualSignResponse, String> {
    if path.trim().is_empty() {
        return Err("archivo no seleccionado".to_owned());
    }
    if certificate_id.trim().is_empty() {
        return Err("certificado no seleccionado".to_owned());
    }
    if pin.is_empty() {
        return Err("PIN vacio".to_owned());
    }

    let config = current_config(&state)?;
    let cache = state.token_certificate_cache().clone();
    let path = PathBuf::from(path);
    tauri::async_runtime::spawn_blocking(move || {
        let payload = fs::read(&path).map_err(|error| format!("error leyendo archivo: {error}"))?;
        let jws_base64 = jws::sign_payload_base64_with_cache(
            &config,
            &payload,
            ApproveSigningSessionInput {
                slot_id,
                certificate_id,
                pin,
            },
            &cache,
        )
        .map_err(|error| format!("error firmando: {error}"))?;

        Ok(ManualSignResponse {
            jws_base64,
            suggested_file_name: suggested_jws_file_name(&path),
        })
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn sign_pdf(
    state: State<'_, AppState>,
    path: String,
    slot_id: u64,
    certificate_id: String,
    pin: String,
) -> Result<PdfSignResponse, String> {
    if path.trim().is_empty() {
        return Err("archivo PDF no seleccionado".to_owned());
    }
    if certificate_id.trim().is_empty() {
        return Err("certificado no seleccionado".to_owned());
    }
    if pin.is_empty() {
        return Err("PIN vacio".to_owned());
    }

    let config = current_config(&state)?;
    let cache = state.token_certificate_cache().clone();
    let path = PathBuf::from(path);
    tauri::async_runtime::spawn_blocking(move || {
        let signed_pdf = pdf::signing::sign_pdf_file(
            &config,
            &cache,
            &path,
            ApproveSigningSessionInput {
                slot_id,
                certificate_id,
                pin,
            },
        )
        .map_err(|error| format!("error firmando PDF: {error}"))?;

        Ok(PdfSignResponse {
            pdf_base64: STANDARD.encode(signed_pdf),
            suggested_file_name: suggested_signed_pdf_file_name(&path),
        })
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn save_signed_file(
    app: AppHandle,
    jws_base64: String,
    suggested_file_name: String,
) -> Result<SaveSignedFileResponse, String> {
    if jws_base64.trim().is_empty() {
        return Err("resultado JWS vacio".to_owned());
    }
    let decoded = STANDARD
        .decode(jws_base64.as_bytes())
        .map_err(|_| "resultado JWS no es Base64 valido".to_owned())?;

    let destination = app
        .dialog()
        .file()
        .add_filter("JWS", &["jws"])
        .add_filter("JSON firmado", &["json"])
        .set_file_name(suggested_file_name)
        .blocking_save_file();
    let Some(destination) = destination else {
        return Ok(SaveSignedFileResponse {
            saved: false,
            path: None,
        });
    };
    let path = destination
        .into_path()
        .map_err(|error| format!("No se pudo obtener la ruta de guardado: {error}"))?;
    fs::write(&path, decoded).map_err(|error| format!("error guardando archivo: {error}"))?;

    Ok(SaveSignedFileResponse {
        saved: true,
        path: Some(path.to_string_lossy().into_owned()),
    })
}

#[tauri::command]
pub async fn save_pdf_file(
    app: AppHandle,
    pdf_base64: String,
    suggested_file_name: String,
) -> Result<SaveSignedFileResponse, String> {
    if pdf_base64.trim().is_empty() {
        return Err("PDF firmado vacio".to_owned());
    }
    let decoded = STANDARD
        .decode(pdf_base64.as_bytes())
        .map_err(|_| "PDF firmado no es Base64 valido".to_owned())?;

    let destination = app
        .dialog()
        .file()
        .add_filter("PDF firmado", &["pdf"])
        .set_file_name(suggested_file_name)
        .blocking_save_file();
    let Some(destination) = destination else {
        return Ok(SaveSignedFileResponse {
            saved: false,
            path: None,
        });
    };
    let path = destination
        .into_path()
        .map_err(|error| format!("No se pudo obtener la ruta de guardado: {error}"))?;
    fs::write(&path, decoded).map_err(|error| format!("error guardando PDF: {error}"))?;

    Ok(SaveSignedFileResponse {
        saved: true,
        path: Some(path.to_string_lossy().into_owned()),
    })
}

#[tauri::command]
pub async fn list_tokens(state: State<'_, AppState>) -> Result<Vec<TokenInfo>, String> {
    let cache = state.token_certificate_cache().clone();
    if cache
        .snapshot()
        .map_err(|error| error.to_string())?
        .loaded_at
        .is_some()
    {
        return cache.get_cached_tokens().map_err(|error| error.to_string());
    }

    let config = current_config(&state)?;
    tauri::async_runtime::spawn_blocking(move || cache.refresh_tokens_and_certificates(&config))
        .await
        .map_err(|error| error.to_string())?
        .map(|state| state.tokens)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn list_certificates(state: State<'_, AppState>) -> Result<Vec<CertificateInfo>, String> {
    let cache = state.token_certificate_cache().clone();
    if cache
        .snapshot()
        .map_err(|error| error.to_string())?
        .loaded_at
        .is_some()
    {
        return cache
            .get_cached_certificates()
            .map_err(|error| error.to_string());
    }

    let config = current_config(&state)?;
    tauri::async_runtime::spawn_blocking(move || cache.refresh_tokens_and_certificates(&config))
        .await
        .map_err(|error| error.to_string())?
        .map(|state| state.certificates)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn get_cached_tokens(state: State<'_, AppState>) -> Result<Vec<TokenInfo>, String> {
    state
        .token_certificate_cache()
        .get_cached_tokens()
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn get_cached_certificates(state: State<'_, AppState>) -> Result<Vec<CertificateInfo>, String> {
    state
        .token_certificate_cache()
        .get_cached_certificates()
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn get_token_certificate_cache(
    state: State<'_, AppState>,
) -> Result<TokenCertificateCacheView, String> {
    token_certificate_cache_view(
        state
            .token_certificate_cache()
            .snapshot()
            .map_err(|error| error.to_string())?,
    )
}

#[tauri::command]
pub fn run_diagnostics(state: State<'_, AppState>) -> Result<DiagnosticsReport, String> {
    let config = current_config(&state)?;
    Ok(diagnostics::run_diagnostics(
        &config,
        state.token_certificate_cache(),
        env!("CARGO_PKG_VERSION"),
    ))
}

#[tauri::command]
pub async fn export_diagnostics(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ExportDiagnosticsResponse, String> {
    let config = current_config(&state)?;
    let report = diagnostics::run_diagnostics(
        &config,
        state.token_certificate_cache(),
        env!("CARGO_PKG_VERSION"),
    );
    let json = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("error serializando diagnostico: {error}"))?;

    let destination = app
        .dialog()
        .file()
        .add_filter("Diagnostico JSON", &["json"])
        .add_filter("Texto", &["txt"])
        .set_file_name("mini-firmador-diagnostico.json")
        .blocking_save_file();
    let Some(destination) = destination else {
        return Ok(ExportDiagnosticsResponse {
            saved: false,
            path: None,
        });
    };
    let path = destination
        .into_path()
        .map_err(|error| format!("No se pudo obtener la ruta de guardado: {error}"))?;
    fs::write(&path, json).map_err(|error| format!("error guardando diagnostico: {error}"))?;

    Ok(ExportDiagnosticsResponse {
        saved: true,
        path: Some(path.to_string_lossy().into_owned()),
    })
}

#[tauri::command]
pub async fn refresh_tokens_and_certificates(
    state: State<'_, AppState>,
) -> Result<TokenCertificateCacheView, String> {
    let config = current_config(&state)?;
    let cache = state.token_certificate_cache().clone();
    tauri::async_runtime::spawn_blocking(move || cache.refresh_tokens_and_certificates(&config))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())
        .and_then(token_certificate_cache_view)
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
    let cache = state.token_certificate_cache().clone();
    let started = Instant::now();
    tauri::async_runtime::spawn_blocking(move || {
        manager.approve_with_signature(
            id,
            &config,
            ApproveSigningSessionInput {
                slot_id,
                certificate_id,
                pin,
            },
            &cache,
        )
    })
    .await
    .map_err(|error| error.to_string())?
    .map(|response| {
        tracing::info!(
            session_id = %id,
            signing_step = "approve_signing_session",
            elapsed_ms = started.elapsed().as_millis() as u64,
            "Tauri approve_signing_session completed"
        );
        response
    })
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

fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("archivo")
        .to_owned()
}

fn detected_format(path: &Path) -> String {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.to_ascii_lowercase())
        .unwrap_or_else(|| "desconocido".to_owned())
}

fn validation_file_type(path: &Path) -> String {
    match detected_format(path).as_str() {
        "pdf" => "PDF".to_owned(),
        "jws" => "JWS".to_owned(),
        "json" => "JWS/JSON".to_owned(),
        _ => "Desconocido".to_owned(),
    }
}

fn suggested_jws_file_name(path: &Path) -> String {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("firmado");
    format!("{stem}.jws")
}

fn suggested_signed_pdf_file_name(path: &Path) -> String {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("firmado");
    format!("{stem}-firmado.pdf")
}

fn selected_manual_file(path: PathBuf, size_bytes: u64) -> SelectedManualFile {
    let detected_format = detected_format(&path);
    let pdf_info = mini_firmador::core::pdf::inspect_pdf_file(&path).ok();
    let is_pdf = detected_format == "pdf"
        || pdf_info
            .as_ref()
            .is_some_and(|info| info.valid_header || info.has_eof_marker);
    let is_json = detected_format == "json" && !is_pdf;

    if is_json {
        return SelectedManualFile {
            name: file_name(&path),
            path: path.to_string_lossy().into_owned(),
            size_bytes,
            detected_type: "JSON".to_owned(),
            output_format: "JWS".to_owned(),
            suggested_file_name: Some(suggested_jws_file_name(&path)),
            supported: true,
            pdf_info: None,
        };
    }

    if is_pdf {
        return SelectedManualFile {
            name: file_name(&path),
            path: path.to_string_lossy().into_owned(),
            size_bytes,
            detected_type: "PDF".to_owned(),
            output_format: "PDF/PAdES".to_owned(),
            suggested_file_name: Some(suggested_signed_pdf_file_name(&path)),
            supported: true,
            pdf_info,
        };
    }

    SelectedManualFile {
        name: file_name(&path),
        path: path.to_string_lossy().into_owned(),
        size_bytes,
        detected_type: "No soportado".to_owned(),
        output_format: "No disponible".to_owned(),
        suggested_file_name: None,
        supported: false,
        pdf_info: None,
    }
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

pub fn warm_token_certificate_cache(state: AppState) {
    tauri::async_runtime::spawn(async move {
        let config = match state.config() {
            Ok(config) => config,
            Err(error) => {
                tracing::warn!(%error, "could not read configuration for token cache warmup");
                return;
            }
        };
        let cache = state.token_certificate_cache().clone();
        match tauri::async_runtime::spawn_blocking(move || {
            cache.refresh_tokens_and_certificates(&config)
        })
        .await
        {
            Ok(Ok(snapshot)) => {
                tracing::info!(
                    token_count = snapshot.tokens.len(),
                    certificate_count = snapshot.certificates.len(),
                    "token/certificate cache warmup completed"
                );
            }
            Ok(Err(error)) => {
                tracing::warn!(%error, "token/certificate cache warmup failed");
            }
            Err(error) => {
                tracing::warn!(%error, "token/certificate cache warmup task failed");
            }
        }
    });
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

fn token_certificate_cache_view(
    state: mini_firmador::core::cache::TokenCertificateCacheState,
) -> Result<TokenCertificateCacheView, String> {
    Ok(TokenCertificateCacheView {
        token_count: state.tokens.len(),
        certificate_count: state.certificates.len(),
        loaded_at: state.loaded_at.map(|loaded_at| loaded_at.to_rfc3339()),
        pkcs11_library_path: state.pkcs11_library_path,
        tokens: state.tokens,
        certificates: state.certificates,
    })
}
