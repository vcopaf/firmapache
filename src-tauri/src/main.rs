mod commands;

use firmapache::{config::AppConfig, init_tracing, server::AppState};
use tauri::{
    Manager, WindowEvent,
    menu::{MenuBuilder, MenuItemBuilder, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
};

fn main() {
    init_tracing();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let config = AppConfig::load()?;
            let state = AppState::new(config);
            let desktop_state = commands::DesktopState::new();
            commands::start_embedded_server(&desktop_state, state.clone())?;
            commands::warm_token_certificate_cache(state.clone());
            app.manage(state);
            app.manage(desktop_state);

            if let Some(window) = app.get_webview_window("main") {
                let window_to_hide = window.clone();
                window.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        api.prevent_close();
                        let _ = window_to_hide.hide();
                    }
                });
            }

            setup_tray(app)?;
            Ok(())
        })
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => {
                let _ = commands::show_main_window_for_app(app);
            }
            "sign_file" => {
                let _ = commands::show_main_window_for_app(app);
            }
            "sessions" => {
                let _ = commands::show_signing_window_for_app(app);
            }
            "refresh_tokens" => {
                let state = app.state::<AppState>().inner().clone();
                commands::warm_token_certificate_cache(state);
            }
            "restart_server" => {
                let state = app.state::<AppState>().inner().clone();
                let desktop = app.state::<commands::DesktopState>();
                match commands::start_embedded_server(&desktop, state) {
                    Ok(()) => desktop.set_last_restart_error(None),
                    Err(error) => {
                        desktop.set_last_restart_error(Some(error.clone()));
                        tracing::error!(%error, "could not restart embedded local service");
                    }
                }
            }
            "quit" => {
                app.exit(0);
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::get_brand_logo_data_url,
            commands::get_config,
            commands::get_server_config,
            commands::update_server_config,
            commands::test_server_status,
            commands::get_development_config,
            commands::update_development_config,
            commands::test_development_config,
            commands::select_pkcs12_file,
            commands::select_p12_output_path,
            commands::generate_virtual_token_p12,
            commands::list_pkcs12_tokens,
            commands::add_pkcs12_token,
            commands::remove_pkcs12_token,
            commands::test_pkcs12_token,
            commands::save_config,
            commands::select_pkcs11_library,
            commands::select_file_to_sign,
            commands::select_manual_file,
            commands::select_manual_files,
            commands::select_manual_output_directory,
            commands::select_file_to_validate,
            commands::select_pdf_file,
            commands::inspect_pdf_file,
            commands::validate_jws_file,
            commands::validate_pdf_file,
            commands::sign_file_as_jws,
            commands::sign_pdf,
            commands::save_signed_file,
            commands::save_pdf_file,
            commands::save_manual_output_file,
            commands::save_manual_output_zip,
            commands::list_tokens,
            commands::list_certificates,
            commands::get_cached_tokens,
            commands::get_cached_certificates,
            commands::list_signing_identities,
            commands::refresh_signing_identities,
            commands::set_default_signing_identity,
            commands::clear_default_signing_identity,
            commands::get_token_certificate_cache,
            commands::run_diagnostics,
            commands::export_diagnostics,
            commands::refresh_tokens_and_certificates,
            commands::list_signing_sessions,
            commands::approve_signing_session,
            commands::reject_signing_session,
            commands::show_main_window,
            commands::show_signing_window,
            commands::hide_signing_window,
            commands::restart_server,
        ])
        .run(tauri::generate_context!())
        .expect("could not run FirMapache desktop application");
}

fn setup_tray(app: &mut tauri::App) -> tauri::Result<()> {
    let state = app.state::<AppState>();
    let config = state.config().ok();
    let pending_sessions = state
        .signing_sessions()
        .list()
        .map(|sessions| {
            sessions
                .into_iter()
                .filter(|session| {
                    matches!(
                        session.status,
                        firmapache::models::signing::SigningSessionStatus::Pending
                    )
                })
                .count()
        })
        .unwrap_or(0);
    let mode_label = config
        .as_ref()
        .map(tray_mode_label)
        .unwrap_or_else(|| "Estado: Confirmación manual".to_owned());
    let identity_label = config.as_ref().and_then(tray_identity_label);
    let pending_label = format!("Solicitudes: {pending_sessions} pendientes");

    let title = MenuItemBuilder::with_id("tray_title", "FirMapache").build(app)?;
    let mode = MenuItemBuilder::with_id("tray_mode", mode_label).build(app)?;
    let identity = identity_label
        .as_ref()
        .map(|label| MenuItemBuilder::with_id("tray_identity", label).build(app))
        .transpose()?;
    let status = MenuItemBuilder::with_id("tray_status", "Estado: Activo").build(app)?;
    let pending = MenuItemBuilder::with_id("tray_pending", pending_label).build(app)?;
    let open = MenuItemBuilder::with_id("open", "Abrir panel principal").build(app)?;
    let sign_file = MenuItemBuilder::with_id("sign_file", "Firmar archivo...").build(app)?;
    let sessions = MenuItemBuilder::with_id("sessions", "Solicitudes pendientes").build(app)?;
    let refresh =
        MenuItemBuilder::with_id("refresh_tokens", "Actualizar tokens/certificados").build(app)?;
    let restart =
        MenuItemBuilder::with_id("restart_server", "Reiniciar servidor local").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Salir").build(app)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let menu = if let Some(identity) = &identity {
        MenuBuilder::new(app)
            .items(&[
                &title,
                &mode,
                &status,
                identity,
                &pending,
                &separator,
                &sign_file,
                &separator,
                &open,
                &sessions,
                &separator,
                &refresh,
                &restart,
                &separator,
                &quit,
            ])
            .build()?
    } else {
        MenuBuilder::new(app)
            .items(&[
                &title, &mode, &status, &pending, &separator, &sign_file, &separator, &open,
                &sessions, &separator, &refresh, &restart, &separator, &quit,
            ])
            .build()?
    };

    let mut tray = TrayIconBuilder::with_id("firmapache")
        .menu(&menu)
        .tooltip("FirMapache activo")
        .show_menu_on_left_click(true)
        .on_tray_icon_event(|tray, event| match event {
            TrayIconEvent::DoubleClick {
                button: MouseButton::Left,
                ..
            }
            | TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } => {
                let _ = commands::show_main_window_for_app(tray.app_handle());
            }
            _ => {}
        });

    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }

    tray.build(app)?;
    Ok(())
}

fn tray_mode_label(config: &AppConfig) -> String {
    if !config.development.enabled || !config.development.auto_sign {
        return "Estado: Confirmación manual".to_owned();
    }
    let has_identity = !config.development.default_identity_id.trim().is_empty();
    let has_pin = config
        .development
        .local_pin
        .as_deref()
        .is_some_and(|pin| !pin.is_empty())
        || std::env::var(&config.development.pin_env).is_ok();
    if !has_identity || !has_pin {
        "Estado: Confirmación manual (autofirma incompleta)".to_owned()
    } else {
        "Estado: Autofirma".to_owned()
    }
}

fn tray_identity_label(config: &AppConfig) -> Option<String> {
    if !config.development.enabled || !config.development.auto_sign {
        return None;
    }
    let identity_id = config.development.default_identity_id.trim();
    (!identity_id.is_empty()).then(|| format!("Identidad: {identity_id}"))
}
