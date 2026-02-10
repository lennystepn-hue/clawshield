#!/usr/bin/env bash
set -euo pipefail

# ClawShield installer — compiles from source if available, otherwise downloads binary
INSTALL_DIR="/usr/local/bin"
BINARY="clawshield"
SOURCE_DIR="/root/workspace/clawshield"

echo "🛡️  Installing ClawShield..."

# Check if Go source exists locally
if [ -d "$SOURCE_DIR/cmd/clawshield" ] && command -v go &>/dev/null; then
  echo "  → Building from source..."
  cd "$SOURCE_DIR"
  CGO_ENABLED=0 go build -ldflags="-s -w" -o "$INSTALL_DIR/$BINARY" ./cmd/clawshield
  echo "  ✓ Built and installed to $INSTALL_DIR/$BINARY"
elif [ -f "$SOURCE_DIR/dist/$BINARY" ]; then
  echo "  → Installing from pre-built binary..."
  cp "$SOURCE_DIR/dist/$BINARY" "$INSTALL_DIR/$BINARY"
  chmod +x "$INSTALL_DIR/$BINARY"
  echo "  ✓ Installed to $INSTALL_DIR/$BINARY"
else
  echo "  → Downloading latest release..."
  ARCH=$(uname -m)
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
  esac
  URL="https://github.com/clawshield/clawshield/releases/latest/download/clawshield-${OS}-${ARCH}"
  curl -fsSL "$URL" -o "$INSTALL_DIR/$BINARY" || {
    echo "  ✗ Download failed. Build from source: cd $SOURCE_DIR && go build -o $INSTALL_DIR/$BINARY ./cmd/clawshield"
    exit 1
  }
  chmod +x "$INSTALL_DIR/$BINARY"
  echo "  ✓ Downloaded and installed to $INSTALL_DIR/$BINARY"
fi

# Create log directory for monitor
mkdir -p /var/log/clawshield

# Verify
if command -v clawshield &>/dev/null; then
  echo "  ✓ ClawShield $(clawshield version 2>/dev/null || echo 'installed') ready"
else
  echo "  ✗ Installation failed"
  exit 1
fi
