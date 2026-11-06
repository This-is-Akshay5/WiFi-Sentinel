#!/bin/bash
set -euo pipefail
APP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"
PYTHON="${APP_DIR}/.venv-macos-arm64/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  echo "[WiFiSentinel] Expected Apple Silicon environment not found: $PYTHON"
  echo "Run ./run_simulator.command once first, then retry this build."
  exit 1
fi
"$PYTHON" -m pip install --disable-pip-version-check 'pyinstaller>=6.11,<7'
"$PYTHON" -m PyInstaller --noconfirm --clean "$APP_DIR/macos/WiFiSentinel.spec"
echo
echo "Build complete: $APP_DIR/dist/WiFiSentinel.app"
echo "Move the app to /Applications, then launch it from Finder for the first permission test."
