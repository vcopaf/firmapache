#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

build_status=0
cargo tauri build --bundles deb || build_status=$?
cargo tauri build --bundles appimage || build_status=$?

echo
echo "Artefactos Linux generados:"
find src-tauri/target/release/bundle -type f \
  \( -name '*.AppImage' -o -name '*.deb' -o -name 'firmapache' -o -name 'FirMapache' \) \
  -print 2>/dev/null | sort || true

exit "$build_status"
