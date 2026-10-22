#!/usr/bin/env bash
# NightfallLX Universal Installer
set -e

echo -e "\033[1;36m:: NightfallLX Universal Installer ::\033[0m"

# 1. Determine target binary directory
TARGET_DIR="/usr/local/bin"
if [ ! -w "$TARGET_DIR" ] && [ "$EUID" -ne 0 ]; then
    TARGET_DIR="$HOME/.local/bin"
fi
mkdir -p "$TARGET_DIR"

# 2. Prefer High-Performance Go Edition
if command -v go >/dev/null 2>&1; then
    echo "[*] Building ultra-fast Go binary..."
    if [ -d "nightfalllx-go" ]; then
        cd nightfalllx-go
    fi
    go build -ldflags="-s -w" -o nightfalllx main.go
    cp nightfalllx "$TARGET_DIR/nightfalllx"
    chmod +x "$TARGET_DIR/nightfalllx"
    echo -e "\033[1;32m[✓] NightfallLX (Go Edition) successfully installed to: $TARGET_DIR/nightfalllx\033[0m"
    echo -e "You can now run \033[1;33mnightfalllx --version\033[0m or \033[1;33mnightfalllx -i\033[0m from any directory!"
    exit 0
fi

# 3. Fallback to Python Edition
if command -v python3 >/dev/null 2>&1; then
    echo "[*] Go compiler not detected. Installing Python edition..."
    python3 -m pip install -e .
    echo -e "\033[1;32m[✓] NightfallLX (Python Edition) installed successfully.\033[0m"
    echo -e "You can now run \033[1;33mnightfalllx --version\033[0m from any directory!"
    exit 0
fi

echo -e "\033[31m[!] Error: Neither Go compiler nor Python3 found on system.\033[0m"
exit 1
