#!/usr/bin/env bash
# ==============================================================================
# AI-SOC Linux Endpoint Agent (aisoc-agent) Uninstaller
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] Error: Uninstaller must be run as root (or via sudo).${NC}"
   exit 1
fi

echo -e "${YELLOW}Stopping and disabling aisoc-agent systemd service...${NC}"
systemctl stop aisoc-agent || true
systemctl disable aisoc-agent || true

rm -f /etc/systemd/system/aisoc-agent.service
systemctl daemon-reload || true

echo -e "${YELLOW}Removing binaries and code from /opt/aisoc-agent and /usr/local/bin...${NC}"
rm -rf /opt/aisoc-agent
rm -f /usr/local/bin/aisoc-agent

echo -e "${BLUE}Configuration files located at /etc/aisoc and telemetry buffer at /var/lib/aisoc have been preserved.${NC}"
read -p "Do you want to completely purge /etc/aisoc and /var/lib/aisoc? [y/N]: " -r PURGE
if [[ $PURGE =~ ^[Yy]$ ]]; then
    rm -rf /etc/aisoc /var/lib/aisoc
    echo -e "${GREEN}All agent state and configuration successfully purged.${NC}"
fi

echo -e "${GREEN}aisoc-agent has been uninstalled.${NC}"
