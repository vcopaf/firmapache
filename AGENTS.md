# FirMapache Agent Notes

## Layout

- The root Cargo package (`firmapache`) is the reusable signing core plus Axum service; `src/main.rs` loads `AppConfig` and serves it.
- `src-tauri/` is a separate Cargo package, not a workspace member. It depends on the root package and starts the same `AppState` and embedded HTTP service; keep signing, validation, and token access in `src/core/`, not in `ui/`.
- The Tauri frontend is static `ui/` files (`tauri.conf.json` sets `frontendDist` to `../ui`); it invokes Rust commands through `window.__TAURI__`, so it is not a standalone web app.

## Development And Checks

- Run only one service instance: `cargo run` starts the standalone local service, while `cargo tauri dev` starts the desktop app and its embedded service on the same configured port.
- CI and release verification order is `cargo fmt --all -- --check`, `cargo check`, `cargo test`, `cargo check --manifest-path src-tauri/Cargo.toml`, then `node --check ui/app.js`. Run `./scripts/check-release.sh` for that exact sequence.
- Run a focused Rust test with `cargo test <test_name>`; root tests are inline unit tests, with no separate `tests/` integration-test suite.
- Building the desktop package requires Tauri CLI v2. Use `./scripts/build-linux.sh` for Debian and AppImage bundles; use `./scripts/build-arch-package.sh` for the Arch package.

## Service And Security Constraints

- Runtime configuration is persisted outside the repo at `~/.config/firmapache/config.toml`; default service is HTTPS on `127.0.0.1:4637`, using a generated self-signed certificate under `~/.config/firmapache/certs/`. Local HTTPS checks need `curl -k` unless that certificate is trusted.
- PKCS#11 driver selection prioritizes `FIRMAPACHE_PKCS11` over persisted configuration. Physical-token work needs the system driver and may need `pcscd`; do not make these prerequisites part of ordinary unit tests.
- Preserve the public `POST /sign` contract unless explicitly changing the API and its documentation. PINs and private-key material must not enter that payload, diagnostics, caches, or logs; interactive desktop commands own PIN entry.
- PKCS#12/PFX identities and autofirming are development-only flows. Do not weaken the default manual approval path for physical tokens.
