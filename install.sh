#!/usr/bin/env bash
# NightfallLX Universal Installer for Linux, macOS and WSL
set -e

echo -e "\033[1;36m"
echo "  ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗███████╗ █████╗ ██╗     ██╗     ██╗   ██╗"
echo "  ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██╔══██╗██║     ██║     ╚██╗ ██╔╝"
echo "  ██╔██╗ ██║██║██║  ███╗███████║   ██║   █████╗  ███████║██║     ██║      ╚████╔╝ "
echo "  ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██╔══╝  ██╔══██║██║     ██║      ██╔═██╗ "
echo "  ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ██║     ██║  ██║███████╗███████╗██╔╝ ██╗"
echo "  ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝"
echo "  :: Next-Gen Web Assessment & Recon Suite :: [ Pure Go v2.0 ] ::"
echo -e "\033[0m"

# 1. Check Go
if ! command -v go >/dev/null 2>&1; then
    echo -e "\033[31m[!] Error: Go compiler (golang) is not installed.\033[0m"
    echo "    Please install Go 1.21+ from https://go.dev/dl/ and run this script again."
    exit 1
fi

echo -e "\033[34m[*] Compiling NightfallLX binary from source with optimizations...\033[0m"
go build -ldflags="-s -w" -o nightfalllx main.go

# 2. Determine best destination directory in PATH
TARGET_DIR="/usr/local/bin"
USE_SUDO=""

if [ "$EUID" -ne 0 ]; then
    if [ -w "/usr/local/bin" ]; then
        TARGET_DIR="/usr/local/bin"
    elif command -v sudo >/dev/null 2>&1; then
        USE_SUDO="sudo"
        TARGET_DIR="/usr/local/bin"
    else
        TARGET_DIR="$HOME/.local/bin"
        mkdir -p "$TARGET_DIR"
    fi
else
    TARGET_DIR="/usr/local/bin"
fi

echo -e "\033[34m[*] Installing binary to $TARGET_DIR/nightfalllx ...\033[0m"
if [ -n "$USE_SUDO" ]; then
    sudo cp nightfalllx "$TARGET_DIR/nightfalllx"
    sudo chmod +x "$TARGET_DIR/nightfalllx"
else
    cp nightfalllx "$TARGET_DIR/nightfalllx"
    chmod +x "$TARGET_DIR/nightfalllx"
fi

# Ensure TARGET_DIR is in user's PATH if installed to ~/.local/bin
if [ "$TARGET_DIR" = "$HOME/.local/bin" ]; then
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) ;;
        *)
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc" 2>/dev/null || true
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc" 2>/dev/null || true
            export PATH="$HOME/.local/bin:$PATH"
            ;;
    esac
fi

echo ""
echo -e "\033[1;32m[✓] NightfallLX successfully installed globally to: $TARGET_DIR/nightfalllx\033[0m"
echo -e "\033[1;33mYou can now run 'nightfalllx' from any directory in your terminal!\033[0m"
echo ""
nightfalllx --version 2>/dev/null || "$TARGET_DIR/nightfalllx" --version
