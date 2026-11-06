#!/bin/bash
set -euo pipefail

APP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

fail() {
  printf '\n[WiFiSentinel] %s\n' "$1" >&2
  printf 'Press Return to close this window. '
  read -r _ || true
  exit 1
}

PYTHON=""
for candidate in python3 python3.12 python3.11 python3.10; do
  candidate_path="$(command -v "$candidate" 2>/dev/null || true)"
  if [[ -n "$candidate_path" ]] && "$candidate_path" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' 2>/dev/null; then
    PYTHON="$candidate_path"
    break
  fi
done
[[ -n "$PYTHON" ]] || fail "Python 3.10 or later is required. Install Python from python.org or Homebrew, then retry."
PYTHON_ARCH="$("$PYTHON" -c 'import platform; print(platform.machine())')"
VENV_DIR="$APP_DIR/.venv-macos-$PYTHON_ARCH"

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  printf '[WiFiSentinel] Creating the application environment…\n'
  "$PYTHON" -m venv "$VENV_DIR" || fail "Could not create the macOS virtual environment. Check write permissions for the project folder."
fi

printf '[WiFiSentinel] Checking application dependencies…\n'
"$VENV_DIR/bin/python" -m pip install --disable-pip-version-check -q -r "$APP_DIR/requirements.txt" || fail "Dependency installation failed. Check network access and the Python installation."

printf '[WiFiSentinel] Starting the desktop application…\n'
set +e
"$VENV_DIR/bin/python" "$APP_DIR/main.py"
APP_STATUS=$?
set -e
if [[ "$APP_STATUS" -ne 0 ]]; then
  fail "WiFiSentinel exited with status $APP_STATUS. Review the error above."
fi
