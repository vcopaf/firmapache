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
            "sessions" => {
                let _ = commands::show_signing_window_for_app(app);
            }
            "restart_server" => {
                let state = app.state::<AppState>().inner().clone();
                let desktop = app.state::<commands::DesktopState>();
                if let Err(error) = commands::start_embedded_server(&desktop, state) {
                    tracing::error!(%error, "could not restart embedded local service");
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
            commands::save_config,
            commands::select_pkcs11_library,
            commands::list_tokens,
            commands::list_certificates,
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
    let open = MenuItemBuilder::with_id("open", "Abrir MiniFirmador").build(app)?;
    let sessions =
        MenuItemBuilder::with_id("sessions", "Mostrar sesiones pendientes").build(app)?;
    let restart = MenuItemBuilder::with_id("restart_server", "Reiniciar servidor").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Salir").build(app)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let menu = MenuBuilder::new(app)
        .items(&[&open, &sessions, &separator, &restart, &separator, &quit])
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
