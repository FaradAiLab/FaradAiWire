#!/bin/sh
# FaradAiWire Native Installer (macOS & Linux)
# Usage: curl -fsSL https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/install.sh | sh

set -e

REPO="FaradAiLab/FaradAiWire"
BINARY_NAME="faradaiwire"

# 1. Detect Operating System
OS="$(uname -s)"
case "$OS" in
    Darwin)
        OS_NAME="darwin"
        ;;
    Linux)
        OS_NAME="linux"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        echo "For Windows, please run the PowerShell installer instead:"
        echo "  irm https://raw.githubusercontent.com/$REPO/main/install.ps1 | iex"
        exit 1
        ;;
    *)
        echo "Unsupported operating system: $OS"
        exit 1
        ;;
esac

# 2. Detect Architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)
        ARCH_NAME="amd64"
        ;;
    arm64|aarch64)
        ARCH_NAME="arm64"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

# 3. Determine Installation Directory
if [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
elif command -v sudo >/dev/null 2>&1; then
    INSTALL_DIR="/usr/local/bin"
    USE_SUDO="true"
else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

# 4. Resolve Latest Version from GitHub
echo "🔍 Discovering latest FaradAiWire release..."
LATEST_RELEASE=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null || true)
VERSION=$(echo "$LATEST_RELEASE" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true)

if [ -z "$VERSION" ]; then
    # Fallback to v1.0.0 if API is unreachable or rate limited
    VERSION="v1.0.0"
fi

CLEAN_VERSION="${VERSION#v}"
TARBALL_NAME="faradaiwire_${CLEAN_VERSION}_${OS_NAME}_${ARCH_NAME}.tar.gz"
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/$TARBALL_NAME"

echo "📦 Downloading FaradAiWire $VERSION ($OS_NAME/$ARCH_NAME)..."
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

if ! curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/$TARBALL_NAME"; then
    echo "❌ Failed to download $DOWNLOAD_URL"
    echo "Please check available releases at: https://github.com/$REPO/releases"
    exit 1
fi

echo "🚀 Installing FaradAiWire to $INSTALL_DIR..."
tar -xzf "$TMP_DIR/$TARBALL_NAME" -C "$TMP_DIR"

if [ "$USE_SUDO" = "true" ]; then
    sudo mv "$TMP_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"
else
    mv "$TMP_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
fi

echo ""
echo "🎉 FaradAiWire $VERSION installed successfully!"
echo "Run the gateway with:"
echo "  faradaiwire"
echo ""
echo "Or open the Admin Console at:"
echo "  http://localhost:8095/admin/dashboard"
