#!/usr/bin/env bash
# ==============================================================================
# AI-SOC Linux Endpoint Agent (aisoc-agent) Installer
# Target: Ubuntu 20.04+, Debian 11+, RHEL/Rocky 8+
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}  AI-SOC Linux Endpoint Agent Installer (v1.0.0)    ${NC}"
echo -e "${BLUE}====================================================${NC}"

# 1. Verify Root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] Error: This installation script must be run as root (or via sudo).${NC}"
   exit 1
fi

# 2. Verify OS is Linux
if [[ "$(uname -s)" != "Linux" ]]; then
   echo -e "${RED}[!] Error: aisoc-agent is only supported on Linux operating systems.${NC}"
   exit 1
fi

# 3. Check Python 3.11+
PYTHON_BIN=""
for py in python3.12 python3.11 python3; do
    if command -v "$py" >/dev/null 2>&1; then
        PY_VER=$("$py" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        PY_MAJOR=$("$py" -c 'import sys; print(sys.version_info.major)')
        PY_MINOR=$("$py" -c 'import sys; print(sys.version_info.minor)')
        if [[ "$PY_MAJOR" -eq 3 ]] && [[ "$PY_MINOR" -ge 11 ]]; then
            PYTHON_BIN=$(command -v "$py")
            echo -e "${GREEN}[+] Found compatible Python: ${PYTHON_BIN} (v${PY_VER})${NC}"
            break
        fi
    fi
done

if [[ -z "$PYTHON_BIN" ]]; then
    echo -e "${RED}[!] Error: Python 3.11 or higher is required but was not found.${NC}"
    echo -e "    Please install Python 3.11+ via: apt update && apt install -y python3.11 python3-pip"
    exit 1
fi

# 4. Install Dependencies
echo -e "${BLUE}[*] Checking Python dependencies...${NC}"
if ! "$PYTHON_BIN" -c "import httpx" >/dev/null 2>&1; then
    echo -e "${YELLOW}[*] Installing 'httpx' via pip...${NC}"
    "$PYTHON_BIN" -m pip install "httpx>=0.25.0" || true
fi

# 5. Create Directory Structure
echo -e "${BLUE}[*] Creating system directories...${NC}"
mkdir -p /etc/aisoc
chmod 700 /etc/aisoc

mkdir -p /var/lib/aisoc/buffer
chmod -R 700 /var/lib/aisoc

# 6. Copy Source Code & Wrapper
INSTALL_DIR="/opt/aisoc-agent"
mkdir -p "$INSTALL_DIR"
cp -r "$(dirname "$0")/aisoc_agent" "$INSTALL_DIR/"

# Create executable wrapper in /usr/local/bin and /usr/bin for secure_path compatibility
cat << 'EOF' > /usr/local/bin/aisoc-agent
#!/usr/bin/env bash
PYTHONPATH=/opt/aisoc-agent exec python3 -m aisoc_agent.main "$@"
EOF
chmod 755 /usr/local/bin/aisoc-agent
ln -sf /usr/local/bin/aisoc-agent /usr/bin/aisoc-agent

# 7. Create Default Configuration if not present
if [[ ! -f /etc/aisoc/agent.conf ]]; then
    echo -e "${BLUE}[*] Generating /etc/aisoc/agent.conf...${NC}"
    cp "$(dirname "$0")/config/agent.conf.example" /etc/aisoc/agent.conf
    chmod 600 /etc/aisoc/agent.conf
fi

# 8. Install Systemd Service
if [[ -d /etc/systemd/system ]]; then
    echo -e "${BLUE}[*] Installing systemd service unit...${NC}"
    cp "$(dirname "$0")/systemd/aisoc-agent.service" /etc/systemd/system/aisoc-agent.service
    chmod 644 /etc/systemd/system/aisoc-agent.service
    systemctl daemon-reload || true
fi

echo -e "${GREEN}====================================================${NC}"
echo -e "${GREEN}  aisoc-agent installation completed successfully!  ${NC}"
echo -e "${GREEN}====================================================${NC}"
echo -e "Next steps:"
echo -e "  1. Edit configuration in /etc/aisoc/agent.conf with your Central SOC URL."
echo -e "  2. Register this host with the Central SOC:"
echo -e "     ${YELLOW}aisoc-agent register${NC}"
echo -e "  3. Verify connectivity and diagnostic health:"
echo -e "     ${YELLOW}aisoc-agent test${NC}"
echo -e "  4. Enable and start the background telemetry service:"
echo -e "     ${YELLOW}systemctl enable --now aisoc-agent${NC}"
echo -e "  5. Check live agent status:"
echo -e "     ${YELLOW}systemctl status aisoc-agent${NC}  or  ${YELLOW}aisoc-agent status${NC}"
