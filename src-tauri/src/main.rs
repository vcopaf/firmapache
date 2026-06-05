mod commands;

use mini_firmador::{config::AppConfig, init_tracing, server::AppState};
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
            commands::select_file_to_validate,
            commands::select_pdf_file,
            commands::inspect_pdf_file,
            commands::validate_jws_file,
            commands::validate_pdf_file,
            commands::sign_file_as_jws,
            commands::sign_pdf,
            commands::save_signed_file,
            commands::save_pdf_file,
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
        .expect("could not run MiniFirmador desktop application");
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
                        mini_firmador::models::signing::SigningSessionStatus::Pending
                    )
                })
                .count()
        })
        .unwrap_or(0);
    let development_label = if config
        .as_ref()
        .map(|config| config.development.enabled)
        .unwrap_or(false)
    {
        "Modo desarrollo: Activado"
    } else {
        "Modo desarrollo: Desactivado"
    };
    let pending_label = format!("Solicitudes: {pending_sessions} pendientes");

    let title = MenuItemBuilder::with_id("tray_title", "MiniFirmador activo").build(app)?;
    let status = MenuItemBuilder::with_id("tray_status", "Estado: Activo").build(app)?;
    let pending = MenuItemBuilder::with_id("tray_pending", pending_label).build(app)?;
    let open = MenuItemBuilder::with_id("open", "Abrir panel principal").build(app)?;
    let sign_file = MenuItemBuilder::with_id("sign_file", "Firmar archivo...").build(app)?;
    let sessions = MenuItemBuilder::with_id("sessions", "Solicitudes pendientes").build(app)?;
    let development = MenuItemBuilder::with_id("development", development_label).build(app)?;
    let refresh =
        MenuItemBuilder::with_id("refresh_tokens", "Actualizar tokens/certificados").build(app)?;
    let restart =
        MenuItemBuilder::with_id("restart_server", "Reiniciar servidor local").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Salir").build(app)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let menu = MenuBuilder::new(app)
        .items(&[
            &title,
            &status,
            &pending,
            &separator,
            &sign_file,
            &separator,
            &open,
            &sessions,
            &development,
            &separator,
            &refresh,
            &restart,
            &separator,
            &quit,
        ])
        .build()?;

    let mut tray = TrayIconBuilder::with_id("mini-firmador")
        .menu(&menu)
        .tooltip("MiniFirmador activo")
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
