#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ARTIFACT_DIR="src-tauri/target/release/bundle"
mapfile -t artifacts < <(
  find "$ARTIFACT_DIR" -type f \
    \( -name 'FirMapache*.AppImage' -o -name 'FirMapache*.deb' -o -name 'firmapache*.AppImage' -o -name 'firmapache*.deb' \) \
    -print 2>/dev/null | sort
)

if [[ ${#artifacts[@]} -eq 0 ]]; then
  echo "No se encontraron AppImage o .deb en $ARTIFACT_DIR" >&2
  exit 1
fi

sha256sum "${artifacts[@]}" > SHA256SUMS
cat SHA256SUMS
