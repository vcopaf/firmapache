use axum::{extract::State, response::Html};
use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::{config::AppConfig, server::AppState};

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const LOGO_PNG: &[u8] = include_bytes!("../../../src-tauri/icons/icon.png");

pub async fn home(State(state): State<AppState>) -> Html<String> {
    let logo = STANDARD.encode(LOGO_PNG);
    let config = state.config().unwrap_or_else(|_| AppConfig::default());
    let url = service_url(&config);
    Html(format!(
        r#"<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FirMapache activo</title>
  <style>
    :root {{
      --bg-primary: #f4f5f7;
      --surface: #ffffff;
      --surface-hover: #f0f3f6;
      --text-primary: #1f252b;
      --text-secondary: #63707d;
      --border: #d8dee5;
      --primary: #2f3a44;
      --success: #2f8f62;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      background: radial-gradient(circle at top right, #d8dee5 0, transparent 28%), var(--bg-primary);
      color: var(--text-primary);
      font-family: Inter, "Segoe UI", sans-serif;
      margin: 0;
      min-height: 100vh;
      padding: 32px;
    }}
    main {{ margin: 0 auto; max-width: 1060px; }}
    .hero {{
      align-items: center;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 24px;
      box-shadow: 0 18px 44px rgba(31, 37, 43, .08);
      display: grid;
      gap: 24px;
      grid-template-columns: auto 1fr;
      padding: 28px;
    }}
    .logo {{
      border: 1px solid var(--border);
      border-radius: 20px;
      height: 96px;
      object-fit: contain;
      padding: 8px;
      width: 96px;
    }}
    h1 {{ font-size: clamp(32px, 6vw, 54px); line-height: 1; margin: 0 0 8px; }}
    p {{ color: var(--text-secondary); margin: 0; }}
    .status {{
      align-items: center;
      background: #dff3e8;
      border-radius: 999px;
      color: #256b49;
      display: inline-flex;
      font-weight: 800;
      gap: 8px;
      margin-top: 18px;
      padding: 9px 13px;
    }}
    .dot {{ background: var(--success); border-radius: 999px; height: 10px; width: 10px; }}
    .grid {{
      display: grid;
      gap: 16px;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      margin-top: 18px;
    }}
    .card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 20px;
    }}
    h2 {{ font-size: 18px; margin: 0 0 12px; }}
    ul {{ color: var(--text-secondary); margin: 0; padding-left: 20px; }}
    li {{ margin: 7px 0; }}
    code {{
      background: var(--surface-hover);
      border-radius: 7px;
      color: var(--primary);
      display: inline-block;
      margin: 4px 4px 0 0;
      padding: 5px 8px;
    }}
    .wide {{ grid-column: span 2; }}
    @media (max-width: 760px) {{
      body {{ padding: 18px; }}
      .hero {{ grid-template-columns: 1fr; }}
      .grid {{ grid-template-columns: 1fr; }}
      .wide {{ grid-column: span 1; }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <img class="logo" src="data:image/png;base64,{logo}" alt="Logo FirMapache">
      <div>
        <h1>FirMapache</h1>
        <p>Firma digital local para JSON/JWS y PDF/PAdES.</p>
        <span class="status"><span class="dot"></span> Servicio activo</span>
      </div>
    </section>
    <section class="grid">
      <article class="card">
        <h2>Estado</h2>
        <p>Version {APP_VERSION}</p>
        <p>URL actual: <strong>{url}</strong></p>
      </article>
      <article class="card">
        <h2>Formatos soportados</h2>
        <ul>
          <li>JSON/JWS RS256</li>
          <li>PDF/PAdES ETSI.CAdES.detached</li>
        </ul>
      </article>
      <article class="card">
        <h2>Endpoints</h2>
        <code>GET /</code><code>GET /status</code><code>GET /tokens</code>
        <code>GET /certificates</code><code>POST /sign</code>
      </article>
      <article class="card wide">
        <h2>Seguridad</h2>
        <ul>
          <li>El PIN nunca se envia por <code>POST /sign</code>.</li>
          <li>La aprobacion ocurre localmente en la aplicacion de escritorio.</li>
          <li>No se muestran rutas sensibles ni contenido privado en esta pagina.</li>
        </ul>
      </article>
      <article class="card">
        <h2>Proyecto</h2>
        <p>FirMapache</p>
        <p>Responsable: Vladimir Copa Fabian</p>
        <p>Correo: vcopafabian@gmail.com</p>
      </article>
    </section>
  </main>
</body>
</html>"#
    ))
}

fn service_url(config: &AppConfig) -> String {
    let scheme = if config.server.https { "https" } else { "http" };
    let host = if config.server.host == "127.0.0.1" {
        "localhost"
    } else {
        config.server.host.as_str()
    };
    format!("{scheme}://{host}:{}/", config.server.port)
}
