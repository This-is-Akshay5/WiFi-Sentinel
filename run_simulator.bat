@echo off
setlocal
cd /d "%~dp0"
title WiFiSentinel - Wireless Security Assessment
set "PYTHON_LAUNCHER=py -3"
py -3 -c "import sys; raise SystemExit(sys.version_info < (3, 10))" >nul 2>nul
if errorlevel 1 (
  set "PYTHON_LAUNCHER=python"
  python -c "import sys; raise SystemExit(sys.version_info < (3, 10))" >nul 2>nul
  if errorlevel 1 (
    echo [ERROR] Python 3.10 or later is required. Install it, then retry.
    pause
    exit /b 1
  )
)
if not exist ".venv\Scripts\python.exe" (
  echo [WiFiSentinel] Creating local Python environment...
  %PYTHON_LAUNCHER% -m venv .venv
  if errorlevel 1 (
    echo [ERROR] Could not create the local Python environment.
    pause
    exit /b 1
  )
)
".venv\Scripts\python.exe" -c "import sys; raise SystemExit(sys.version_info < (3, 10))" >nul 2>nul
if errorlevel 1 (
  echo [ERROR] The existing .venv uses Python older than 3.10. Recreate it with a supported Python version.
  pause
  exit /b 1
)
call ".venv\Scripts\python.exe" -m pip install -q --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
  echo [ERROR] Dependency installation failed. Check your internet connection and Python installation.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" main.py
if errorlevel 1 pause
endlocal
