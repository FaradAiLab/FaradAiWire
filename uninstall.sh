#!/bin/sh
# FaradAiWire Native Uninstaller (macOS & Linux)
# Usage: curl -fsSL https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/uninstall.sh | sh
# Purge data too: curl -fsSL https://raw.githubusercontent.com/FaradAiLab/FaradAiWire/main/uninstall.sh | sh -s -- --purge

set -e

REPO="FaradAiLab/FaradAiWire"
BINARY_NAME="faradaiwire"
PURGE="${FARADAI_WIRE_PURGE:-0}"

for arg in "$@"; do
    case "$arg" in
        --purge|-p)
            PURGE="1"
            ;;
        --help|-h)
            echo "Usage: uninstall.sh [--purge]"
            echo "  --purge, -p   Also remove runtime configuration, keys, backups, and DuckDB analytics"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            exit 1
            ;;
    esac
done

# 1. Detect Operating System
OS="$(uname -s)"
case "$OS" in
    Darwin|Linux)
        ;;
    MINGW*|MSYS*|CYGWIN*)
        echo "For Windows, please run the PowerShell uninstaller instead:"
        echo "  irm https://raw.githubusercontent.com/$REPO/main/uninstall.ps1 | iex"
        exit 1
        ;;
    *)
        echo "Unsupported operating system: $OS" >&2
        exit 1
        ;;
esac

DATA_DIR="${FARADAI_WIRE_HOME:-$HOME/.faradaiwire}"
CLEAN_DATA_DIR="${DATA_DIR%/}"
HOME_CLEAN="${HOME%/}"

is_unsafe_data_dir() {
    case "$1" in
        ""|"/"|"."|".."|"$HOME_CLEAN"|"/usr"|"/etc"|"/var"|"/bin"|"/sbin"|"/System"|"/Applications"|"/Library"|"/Users"|"/home"|"/tmp")
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

if is_unsafe_data_dir "$CLEAN_DATA_DIR"; then
    echo "❌ Refusing unsafe data directory path: '$DATA_DIR'" >&2
    exit 1
fi

# Locate an installed binary to run IDE config rollback before removal
BIN_PATH=""
for candidate in "/usr/local/bin/$BINARY_NAME" "$HOME/.local/bin/$BINARY_NAME"; do
    if [ -f "$candidate" ] || [ -L "$candidate" ]; then
        BIN_PATH="$candidate"
        break
    fi
done
if [ -z "$BIN_PATH" ] && command -v "$BINARY_NAME" >/dev/null 2>&1; then
    BIN_PATH="$(command -v "$BINARY_NAME")"
fi

# 2. Restore adopted IDE configurations if backups exist
if [ -n "$BIN_PATH" ] && [ -d "$DATA_DIR/backups" ]; then
    if ls "$DATA_DIR/backups/"*.bak >/dev/null 2>&1; then
        echo "🔄 Restoring adopted IDE configurations from backups..."
        "$BIN_PATH" adopt --rollback --backup-dir "$DATA_DIR/backups" || echo "⚠️  Could not restore all client backups automatically."
    fi
fi

wait_for_daemon_exit() {
    command -v pkill >/dev/null 2>&1 || return 0
    _waited=0
    while pkill -0 -x "$BINARY_NAME" >/dev/null 2>&1; do
        if [ "$_waited" -ge 20 ]; then
            echo "⚠️  $BINARY_NAME did not exit gracefully within 10s; sending SIGKILL..."
            pkill -KILL -x "$BINARY_NAME" >/dev/null 2>&1 || true
            sleep 1
            break
        fi
        sleep 0.5
        _waited=$((_waited + 1))
    done
}

# 3. Handle Homebrew-managed installations cleanly if present
REMOVED_BIN="0"
if command -v brew >/dev/null 2>&1 && brew list --formula "$BINARY_NAME" >/dev/null 2>&1; then
    echo "🍺 Detected Homebrew installation of $BINARY_NAME..."
    brew services stop "$BINARY_NAME" >/dev/null 2>&1 || true
    if command -v pkill >/dev/null 2>&1; then
        pkill -TERM -x "$BINARY_NAME" >/dev/null 2>&1 || true
        wait_for_daemon_exit
    fi
    brew uninstall "$BINARY_NAME"
    REMOVED_BIN="1"
else
    # 4. Stop any running foreground/daemon process (wait up to 10s so DuckDB locks flush)
    if command -v pkill >/dev/null 2>&1; then
        if pkill -TERM -x "$BINARY_NAME" >/dev/null 2>&1; then
            echo "🛑 Stopping running $BINARY_NAME process (waiting up to 10s)..."
            wait_for_daemon_exit
        fi
    fi
fi

# 5. Remove manually / install.sh-installed binaries
BREW_MANAGED="0"
if [ "$REMOVED_BIN" = "1" ]; then
    BREW_MANAGED="1"
fi

for target in "/usr/local/bin/$BINARY_NAME" "$HOME/.local/bin/$BINARY_NAME"; do
    if [ -f "$target" ] || [ -L "$target" ]; then
        parent_dir="$(dirname "$target")"
        if [ -w "$parent_dir" ]; then
            rm -f "$target"
        elif command -v sudo >/dev/null 2>&1; then
            sudo rm -f "$target"
        else
            echo "❌ Insufficient permissions to remove $target" >&2
            exit 1
        fi
        echo "🗑️  Removed $target"
        REMOVED_BIN="1"
    fi
done

if [ "$BREW_MANAGED" = "0" ] && [ "$REMOVED_BIN" = "0" ] && [ -n "$BIN_PATH" ] && { [ -f "$BIN_PATH" ] || [ -L "$BIN_PATH" ]; }; then
    parent_dir="$(dirname "$BIN_PATH")"
    if [ -w "$parent_dir" ]; then
        rm -f "$BIN_PATH"
        echo "🗑️  Removed $BIN_PATH"
        REMOVED_BIN="1"
    fi
fi

if [ "$REMOVED_BIN" = "0" ]; then
    echo "ℹ️  No installed $BINARY_NAME binary found in standard locations."
fi

# 6. Optionally remove runtime data & analytics
if [ "$PURGE" = "1" ] || [ "$PURGE" = "true" ]; then
    if [ -d "$DATA_DIR" ]; then
        rm -rf "$DATA_DIR"
        echo "🗑️  Removed runtime data directory: $DATA_DIR"
    fi
elif [ -d "$DATA_DIR" ]; then
    echo ""
    echo "ℹ️  Runtime configuration & analytics preserved at: $DATA_DIR"
    echo "   To remove all data as well, run:"
    echo "     rm -rf \"$DATA_DIR\""
    echo "   Or re-run with --purge:"
    echo "     curl -fsSL https://raw.githubusercontent.com/$REPO/main/uninstall.sh | sh -s -- --purge"
fi

echo ""
echo "✅ FaradAiWire uninstalled successfully!"
