#!/bin/bash
set -euo pipefail

# ClawShield Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/openclaw/clawshield/main/scripts/install.sh | bash

REPO="openclaw/clawshield"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="clawshield"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}${BOLD}"
echo '   _____ _               _____ _     _      _     _'
echo '  / ____| |             / ____| |   (_)    | |   | |'
echo ' | |    | | __ ___   __| (___ | |__  _  ___| | __| |'
echo ' | |    | |/ _` \ \ /\ / /\___ \| '"'"'_ \| |/ _ \ |/ _` |'
echo ' | |____| | (_| |\ V  V / ____) | | | | |  __/ | (_| |'
echo '  \_____|_|\__,_| \_/\_/ |_____/|_| |_|_|\___|_|\__,_|'
echo -e "${NC}"
echo -e "${BOLD}  🛡️  Security Layer for AI Agents${NC}"
echo ""

# Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
    linux)  OS="linux" ;;
    darwin) OS="macos" ;;
    *)      echo -e "${RED}Unsupported OS: $OS${NC}"; exit 1 ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)  ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *)             echo -e "${RED}Unsupported architecture: $ARCH${NC}"; exit 1 ;;
esac

BINARY="clawshield-${OS}-${ARCH}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${BINARY}"

echo -e "  ${BOLD}OS:${NC}   $OS"
echo -e "  ${BOLD}Arch:${NC} $ARCH"
echo -e "  ${BOLD}URL:${NC}  $DOWNLOAD_URL"
echo ""

# Download
echo -e "${YELLOW}⬇️  Downloading ClawShield...${NC}"
if command -v curl &>/dev/null; then
    curl -fsSL -o "/tmp/${BINARY_NAME}" "$DOWNLOAD_URL"
elif command -v wget &>/dev/null; then
    wget -q -O "/tmp/${BINARY_NAME}" "$DOWNLOAD_URL"
else
    echo -e "${RED}Neither curl nor wget found. Please install one.${NC}"
    exit 1
fi

# Install
chmod +x "/tmp/${BINARY_NAME}"

if [ -w "$INSTALL_DIR" ]; then
    mv "/tmp/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
else
    echo -e "${YELLOW}🔑 Need sudo to install to ${INSTALL_DIR}${NC}"
    sudo mv "/tmp/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
fi

echo -e "${GREEN}${BOLD}✅ ClawShield installed to ${INSTALL_DIR}/${BINARY_NAME}${NC}"
echo ""

# Verify
if command -v clawshield &>/dev/null; then
    echo -e "${CYAN}Running first scan...${NC}"
    echo ""
    clawshield scan
else
    echo -e "${YELLOW}Installation complete. Run: clawshield scan${NC}"
fi
