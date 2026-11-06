#!/bin/bash

set -e

cd "$(dirname "$0")"

echo "WiFiSentinel - Wireless Security Assessment"

# Create virtual environment if it doesn't exist
if [ ! -f ".venv/bin/python" ]; then
    echo "Creating local Python environment..."

    if command -v python3 >/dev/null 2>&1; then
        python3 -m venv .venv
    else
        echo "[ERROR] Python 3 is required."
        exit 1
    fi
fi

# Install dependencies
echo "Installing dependencies..."
.venv/bin/python -m pip install --upgrade pip

.venv/bin/python -m pip install -q --disable-pip-version-check -r requirements.txt

# Run the simulator
echo "Starting WiFiSentinel..."
.venv/bin/python main.py