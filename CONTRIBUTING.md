# Contribuir a FirMapache

Gracias por querer contribuir. FirMapache combina Rust, Axum, Tauri, PKCS#11,
PKCS#12, JWS y PDF, asi que los cambios deben ser pequeños, verificables y
cuidadosos con los contratos publicos.

## Clonar

```bash
git clone https://github.com/<owner>/firmapache.git
cd firmapache
```

## Requisitos

- Rust estable con Cargo.
- Dependencias de sistema para OpenSSL.
- `pcscd` si se probaran tokens fisicos.
- Driver PKCS#11 del token fisico, por ejemplo Feitian `libcastle.so` u OpenSC.
- Tauri CLI para desarrollo de escritorio:

```bash
cargo install tauri-cli --version "^2" --locked
```

## Compilar y ejecutar

Servicio local:

```bash
cargo run
```

Aplicacion de escritorio:

```bash
cargo tauri dev
```

No ejecute ambos al mismo tiempo si usan el mismo puerto.

## Verificacion antes de enviar cambios

```bash
cargo fmt --all
cargo check
cargo test
cargo check --manifest-path src-tauri/Cargo.toml
node --check ui/app.js
```

## Reportar bugs

Al reportar un bug, incluya:

- version o commit;
- sistema operativo;
- si usa PKCS#11 fisico o PKCS#12 virtual;
- driver PKCS#11 usado, si aplica;
- pasos para reproducir;
- resultado esperado y resultado obtenido.

No incluya PIN, claves privadas, certificados privados ni contenido sensible de
documentos.

## Proponer cambios

- Mantenga intacto el contrato publico de `POST /sign` salvo que el cambio sea
  explicitamente de API y este documentado.
- Evite mover logica criptografica al frontend.
- Reutilice el core Rust para firma, validacion y acceso a tokens.
- Agregue pruebas cuando el cambio afecte core, PDF, JWS o PKCS#12.
- Actualice README/CHANGELOG cuando cambie comportamiento visible.

## Estilo

- Rust: usar `cargo fmt --all`.
- JavaScript: mantener `ui/app.js` valido con `node --check`.
- Documentacion: preferir claridad y ejemplos reproducibles.
