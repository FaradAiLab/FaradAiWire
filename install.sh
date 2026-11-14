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

# 3. Prefer Homebrew on macOS when available (zero sudo, managed PATH & launchd service)
if [ "$OS_NAME" = "darwin" ] && command -v brew >/dev/null 2>&1; then
    echo "🍺 Homebrew detected on macOS. Installing via FaradAiLab/tap..."
    if brew list --formula "$BINARY_NAME" >/dev/null 2>&1; then
        if HOMEBREW_NO_AUTO_UPDATE=1 brew upgrade "$BINARY_NAME"; then
            echo ""
            echo "🎉 FaradAiWire upgraded successfully via Homebrew!"
            echo "Run the gateway with:"
            echo "  faradaiwire run"
            exit 0
        fi
    elif HOMEBREW_NO_AUTO_UPDATE=1 brew tap FaradAiLab/tap && HOMEBREW_NO_AUTO_UPDATE=1 brew install "$BINARY_NAME"; then
        echo ""
        echo "🎉 FaradAiWire installed successfully via Homebrew!"
        echo "Run the gateway with:"
        echo "  faradaiwire run"
        echo ""
        echo "Or open the Admin Console at:"
        echo "  http://localhost:8095/admin/dashboard"
        exit 0
    fi
    echo "⚠️  Homebrew install could not complete; falling back to direct binary install..."
fi

# 4. Resolve Latest Version from GitHub
VERSION="${FARADAI_WIRE_VERSION:-}"
if [ -z "$VERSION" ]; then
    echo "🔍 Discovering latest FaradAiWire release..."
    LATEST_RELEASE=$(curl --proto '=https' --tlsv1.2 -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null || true)
    VERSION=$(echo "$LATEST_RELEASE" | grep '"tag_name":' | head -n 1 | sed -E 's/.*"([^"]+)".*/\1/' || true)
fi

if [ -z "$VERSION" ]; then
    echo "❌ Could not determine latest FaradAiWire release version from GitHub API."
    echo "   Set FARADAI_WIRE_VERSION=vX.Y.Z explicitly or check https://github.com/$REPO/releases"
    exit 1
fi

CLEAN_VERSION="${VERSION#v}"
TARBALL_NAME="faradaiwire_${CLEAN_VERSION}_${OS_NAME}_${ARCH_NAME}.tar.gz"
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/$TARBALL_NAME"
CHECKSUMS_URL="https://github.com/$REPO/releases/download/$VERSION/checksums.txt"

echo "📦 Downloading FaradAiWire $VERSION ($OS_NAME/$ARCH_NAME)..."
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

if ! curl --proto '=https' --tlsv1.2 -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/$TARBALL_NAME"; then
    echo "❌ Failed to download $DOWNLOAD_URL"
    echo "Please check available releases at: https://github.com/$REPO/releases"
    exit 1
fi

echo "🔐 Verifying SHA-256 checksum..."
if ! curl --proto '=https' --tlsv1.2 -fsSL "$CHECKSUMS_URL" -o "$TMP_DIR/checksums.txt"; then
    echo "❌ Failed to download $CHECKSUMS_URL; refusing unverified binary."
    exit 1
fi

EXPECTED_SHA=$(awk -v f="$TARBALL_NAME" '{
    name=$2;
    sub(/^\*\.\//, "", name);
    sub(/^\*/, "", name);
    sub(/^\.\//, "", name);
    if (name == f) { print tolower($1); exit }
}' "$TMP_DIR/checksums.txt")

if [ -z "$EXPECTED_SHA" ]; then
    echo "❌ No checksum entry found for $TARBALL_NAME in checksums.txt; aborting."
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_SHA=$(sha256sum "$TMP_DIR/$TARBALL_NAME" | awk '{print tolower($1)}')
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_SHA=$(shasum -a 256 "$TMP_DIR/$TARBALL_NAME" | awk '{print tolower($1)}')
elif command -v openssl >/dev/null 2>&1; then
    ACTUAL_SHA=$(openssl dgst -sha256 "$TMP_DIR/$TARBALL_NAME" | awk '{print tolower($NF)}')
else
    echo "❌ No SHA-256 verification tool found (sha256sum, shasum, or openssl required)."
    exit 1
fi

if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    echo "❌ SHA-256 checksum mismatch for $TARBALL_NAME!"
    echo "   Expected: $EXPECTED_SHA"
    echo "   Actual:   $ACTUAL_SHA"
    exit 1
fi

tar -xzf "$TMP_DIR/$TARBALL_NAME" -C "$TMP_DIR"

# 5. Install binary (/usr/local/bin if writable or sudo succeeds, else ~/.local/bin)
INSTALLED_TO_LOCAL_BIN="0"
install_to_local_bin() {
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
    mv "$TMP_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
    INSTALLED_TO_LOCAL_BIN="1"
}

if [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
    echo "🚀 Installing FaradAiWire to $INSTALL_DIR..."
    mv "$TMP_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"
elif command -v sudo >/dev/null 2>&1 && { ( : < /dev/tty ) 2>/dev/null || sudo -n true >/dev/null 2>&1; }; then
    echo "🚀 Installing FaradAiWire to /usr/local/bin (sudo may prompt for your password)..."
    if sudo mkdir -p "/usr/local/bin" && sudo install -m 0755 "$TMP_DIR/$BINARY_NAME" "/usr/local/bin/$BINARY_NAME"; then
        INSTALL_DIR="/usr/local/bin"
    else
        echo "⚠️  Could not install to /usr/local/bin; falling back to $HOME/.local/bin..."
        install_to_local_bin
    fi
else
    echo "🚀 Installing FaradAiWire to $HOME/.local/bin..."
    install_to_local_bin
fi

# 6. Ensure ~/.local/bin is persisted in shell startup files when needed
append_path_to_rc() {
    rc_file="$1"
    [ -n "$rc_file" ] || return 0
    if [ -f "$rc_file" ] && grep -qE '(# >>> FaradAiWire PATH >>>|\.local/bin)' "$rc_file" 2>/dev/null; then
        return 0
    fi
    {
        echo ""
        echo "# >>> FaradAiWire PATH >>>"
        echo 'export PATH="$HOME/.local/bin:$PATH"'
        echo "# <<< FaradAiWire PATH <<<"
    } >> "$rc_file"
    UPDATED_RC_FILES="${UPDATED_RC_FILES:+$UPDATED_RC_FILES, }$rc_file"
}

UPDATED_RC_FILES=""
IN_CURRENT_PATH="1"
if [ "$INSTALLED_TO_LOCAL_BIN" = "1" ]; then
    case ":$PATH:" in
        *":$HOME/.local/bin:"*) IN_CURRENT_PATH="1" ;;
        *) IN_CURRENT_PATH="0" ;;
    esac

    case "${SHELL:-}" in
        */zsh)
            append_path_to_rc "$HOME/.zshrc"
            ;;
        */bash)
            if [ "$OS_NAME" = "darwin" ] && [ -f "$HOME/.bash_profile" ]; then
                append_path_to_rc "$HOME/.bash_profile"
            else
                append_path_to_rc "$HOME/.bashrc"
                if [ ! -f "$HOME/.profile" ] || ! grep -q '\.local/bin' "$HOME/.profile" 2>/dev/null; then
                    append_path_to_rc "$HOME/.profile"
                fi
            fi
            ;;
        *)
            if [ "$OS_NAME" = "darwin" ] || [ -f "$HOME/.zshrc" ]; then
                append_path_to_rc "$HOME/.zshrc"
            fi
            if [ -f "$HOME/.bashrc" ]; then
                append_path_to_rc "$HOME/.bashrc"
            fi
            append_path_to_rc "$HOME/.profile"
            ;;
    esac
fi

echo ""
echo "🎉 FaradAiWire $VERSION installed successfully!"
if [ -n "$UPDATED_RC_FILES" ]; then
    echo "🔧 Added $HOME/.local/bin to PATH in: $UPDATED_RC_FILES"
fi
if [ "$INSTALLED_TO_LOCAL_BIN" = "1" ] && [ "$IN_CURRENT_PATH" = "0" ]; then
    echo "ℹ️  Open a new terminal (or run 'export PATH=\"\$HOME/.local/bin:\$PATH\"' in this one) before running:"
else
    echo "Run the gateway with:"
fi
echo "  faradaiwire run"
echo ""
echo "Or open the Admin Console at:"
echo "  http://localhost:8095/admin/dashboard"
