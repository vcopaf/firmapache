#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

cargo fmt --all -- --check
cargo check
cargo test
cargo check --manifest-path src-tauri/Cargo.toml
node --check ui/app.js
