use axum::response::Html;

pub async fn home() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>MiniFirmador activo</title>
</head>
<body>
  <main>
    <h1>MiniFirmador activo</h1>
    <p>Servicio local de firma digital</p>
    <p>Version 0.1.0</p>
    <p>Estado operativo</p>
    <p>Estado JSON disponible en <a href="/status">/status</a>.</p>
  </main>
</body>
</html>
"#,
    )
}
