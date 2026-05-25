# mini-firmador

Servicio REST local en Rust que servira como bridge entre un navegador y un token
PKCS#11 para firma digital.

Esta primera fase expone solamente endpoints de salud y version. No implementa
firma, integracion con tokens, procesamiento PDF/XML ni interfaz de escritorio.

## Requisitos

- Rust estable con Cargo

## Ejecutar

```bash
cargo run
```

El servidor escucha en `http://127.0.0.1:4856`.

## Verificar

```bash
cargo check
curl http://127.0.0.1:4856/status
curl http://127.0.0.1:4856/version
```

Respuestas esperadas:

```json
{"status":"ok","service":"mini-firmador"}
```

```json
{"name":"mini-firmador","version":"0.1.0"}
```

## Estructura

- `src/api`: rutas y handlers HTTP.
- `src/config`: configuracion del servicio local.
- `src/error`: errores convertibles a respuestas HTTP.
- `src/models`: modelos JSON de la API.
- `src/pkcs11`: espacio reservado para proveedor, token y firma PKCS#11.
- `src/utils`: utilidades compartidas futuras.
