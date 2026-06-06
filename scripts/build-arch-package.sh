#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR/packaging/arch"

makepkg -sf

echo
echo "Paquetes Arch generados:"
find . -maxdepth 1 -type f -name '*.pkg.tar.zst' -print | sort
