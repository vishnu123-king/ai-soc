#!/usr/bin/env bash
# ==============================================================================
# AI-SOC One-Step Full Installation & Deployment Script
# Installs:
#   1. System packages & Node.js 20+
#   2. Python environment & backend dependencies
#   3. Frontend & unified Node/Express server production build
#   4. Database initialization & default admin user
#   5. AI-SOC Central Platform systemd service (aisoc.service)
#   6. AI-SOC Linux Endpoint Agent & systemd service (aisoc-agent.service)
#   7. Automatic agent enrollment & diagnostic verification
# ==============================================================================

set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

echo -e "${CYAN}${BOLD}"
echo "========================================================================"
echo "    AI-SOC: Automated Security Operations Center & Endpoint Agent       "
echo "                    Complete Installation Script                        "
echo "========================================================================"
echo -e "${NC}"

echo -e "[*] Target installation directory: ${BOLD}${ROOT_DIR}${NC}"

# Check for sudo privilege
if [[ $EUID -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo -e "${RED}[!] Error: This script requires root privileges. Please run with sudo or as root.${NC}"
        exit 1
    fi
else
    SUDO=""
fi

# Detect actual non-root invoking user (for owning services/files)
TARGET_USER="${SUDO_USER:-$(id -un)}"
TARGET_GROUP="$(id -gn "${TARGET_USER}")"
echo -e "[*] Running as effective user: ${BOLD}${TARGET_USER}:${TARGET_GROUP}${NC}"

# ------------------------------------------------------------------------------
# 1. System Package Dependencies
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[+] Step 1/7: Checking and installing OS package dependencies...${NC}"
if [[ -f /etc/debian_version ]]; then
    $SUDO apt-get update -y
    $SUDO apt-get install -y python3 python3-venv python3-pip build-essential curl sqlite3 openssl auditd
elif [[ -f /etc/redhat-release ]]; then
    $SUDO dnf install -y python3 python3-pip python3-devel gcc gcc-c++ make curl sqlite openssl audit
fi
echo -e "${GREEN}[✓] System packages verified and ready.${NC}"

# ------------------------------------------------------------------------------
# 2. Node.js & npm Setup
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[+] Step 2/7: Checking Node.js runtime...${NC}"
NODE_OK=0
if command -v node >/dev/null 2>&1; then
    NODE_VERSION=$(node -v | sed 's/v//' | cut -d'.' -f1)
    if [[ "${NODE_VERSION}" -ge 18 ]]; then
        echo -e "${GREEN}[✓] Node.js $(node -v) is installed.${NC}"
        NODE_OK=1
    fi
fi

if [[ "${NODE_OK}" -eq 0 ]]; then
    echo -e "${YELLOW}[*] Installing Node.js LTS (20.x)...${NC}"
    curl -fsSL https://deb.nodesource.com/setup_20.x | $SUDO -E bash -
    $SUDO apt-get install -y nodejs
    echo -e "${GREEN}[✓] Installed Node.js $(node -v) & npm $(npm -v)${NC}"
fi

# ------------------------------------------------------------------------------
# 3. Python Virtual Environment & Backend Setup
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[+] Step 3/7: Setting up Python backend virtual environment...${NC}"
if [[ ! -d ".venv" ]]; then
    python3 -m venv .venv
fi

PYTHON_BIN="${ROOT_DIR}/.venv/bin/python3"
PIP_BIN="${ROOT_DIR}/.venv/bin/pip"

"${PIP_BIN}" install --upgrade pip setuptools wheel >/dev/null 2>&1 || true
if [[ -f "backend/requirements.txt" ]]; then
    echo -e "[*] Installing Python backend packages..."
    "${PIP_BIN}" install -r backend/requirements.txt
fi
echo -e "${GREEN}[✓] Python backend environment configured.${NC}"

# ------------------------------------------------------------------------------
# 4. Environment Configuration (.env)
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[+] Step 4/7: Initializing environment configuration (.env)...${NC}"
if [[ ! -f ".env" ]]; then
    cp .env.example .env
    RANDOM_JWT=$(openssl rand -hex 32)
    RANDOM_ENROLL=$(openssl rand -hex 24)
    sed -i "s/replace-with-a-random-32-byte-hex-secret-in-production/${RANDOM_JWT}/g" .env
    sed -i "s/replace-with-a-secure-shared-agent-enrollment-key/${RANDOM_ENROLL}/g" .env
    echo -e "${GREEN}[✓] Generated secure secrets in .env${NC}"
else
    echo -e "${GREEN}[✓] Preserved existing .env configuration.${NC}"
fi

# Check for GEMINI_API_KEY
if grep -q "^GEMINI_API_KEY=$" .env 2>/dev/null || grep -q "^GEMINI_API_KEY=\s*$" .env 2>/dev/null; then
    if [[ -n "${GEMINI_API_KEY:-}" ]]; then
        echo -e "[*] Injecting GEMINI_API_KEY from environment into .env..."
        sed -i "s|^GEMINI_API_KEY=.*|GEMINI_API_KEY=${GEMINI_API_KEY}|g" .env
        echo -e "${GREEN}[✓] GEMINI_API_KEY successfully configured in .env${NC}"
    else
        echo -e "${YELLOW}[!] GEMINI_API_KEY is currently empty in .env.${NC}"
        echo -e "    The system will use the deterministic rule-augmented analysis engine until you set it."
        echo -e "    To add it anytime: edit .env or export GEMINI_API_KEY=... and restart aisoc.${NC}"
    fi
else
    echo -e "${GREEN}[✓] GEMINI_API_KEY already configured in .env${NC}"
fi

# ------------------------------------------------------------------------------
# 5. Build Frontend & Central Server Bundle
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[+] Step 5/7: Installing npm dependencies and building bundle...${NC}"
npm install --no-audit --no-fund
npm run build
echo -e "${GREEN}[✓] Production assets compiled in dist/${NC}"

# Initialize Database & Default Admin
if [[ -f "backend/app/database/connection.py" ]]; then
    "${PYTHON_BIN}" -c "
from backend.app.database.connection import init_db, SessionLocal
from backend.app.models.user import User
from backend.app.auth.security import get_password_hash

init_db()
db = SessionLocal()
try:
    admin = db.query(User).filter(User.username == 'admin').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@aisoc.local',
            hashed_password=get_password_hash('admin123'),
            role='ADMIN',
            is_active=True
        )
        db.add(admin)
        db.commit()
        print('    Admin user created.')
    else:
        print('    Admin user already exists.')
finally:
    db.close()
" || true
fi

# ------------------------------------------------------------------------------
# 6. Central SOC Service Installation
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[+] Step 6/7: Configuring systemd service for Central AI-SOC...${NC}"
mkdir -p "${ROOT_DIR}/systemd"

NODE_PATH_BIN="$(which node || echo /usr/bin/node)"
NPM_PATH_BIN="$(which npm || echo /usr/bin/npm)"

cat > "${ROOT_DIR}/systemd/aisoc.service" <<EOF
[Unit]
Description=AI-SOC Central Cybersecurity Monitoring & Incident Analysis Platform
After=network.target

[Service]
Type=simple
User=${TARGET_USER}
Group=${TARGET_GROUP}
WorkingDirectory=${ROOT_DIR}
Environment="NODE_ENV=production"
Environment="PATH=${ROOT_DIR}/.venv/bin:/usr/local/bin:/usr/bin:/bin"
EnvironmentFile=${ROOT_DIR}/.env
ExecStart=${NPM_PATH_BIN} run start
Restart=always
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

$SUDO cp "${ROOT_DIR}/systemd/aisoc.service" /etc/systemd/system/aisoc.service
$SUDO systemctl daemon-reload
$SUDO systemctl enable --now aisoc

echo -e "[*] Waiting for Central SOC service to initialize on port 3000..."
MAX_TRIES=20
COUNT=0
SOC_READY=0
while [[ $COUNT -lt $MAX_TRIES ]]; do
    if curl -s http://127.0.0.1:3000/api/health >/dev/null 2>&1; then
        SOC_READY=1
        break
    fi
    sleep 1
    COUNT=$((COUNT + 1))
done

if [[ $SOC_READY -eq 1 ]]; then
    echo -e "${GREEN}[✓] Central AI-SOC server is active and responding on http://localhost:3000${NC}"
else
    echo -e "${YELLOW}[!] Notice: SOC server is starting up. Check with: sudo systemctl status aisoc${NC}"
fi

# ------------------------------------------------------------------------------
# 7. Endpoint Agent Installation & Enrollment
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[+] Step 7/7: Installing and enrolling Linux Endpoint Agent (aisoc-agent)...${NC}"
if [[ -d "${ROOT_DIR}/aisoc-agent" ]]; then
    cd "${ROOT_DIR}/aisoc-agent"
    chmod +x install.sh
    $SUDO ./install.sh

    # Ensure CLI symlinks are set up in both /usr/local/bin and /usr/bin for sudo secure_path
    $SUDO ln -sf /usr/local/bin/aisoc-agent /usr/bin/aisoc-agent

    echo -e "[*] Enrolling endpoint agent with Central SOC..."
    # Give server another brief moment if needed
    sleep 1
    if $SUDO aisoc-agent register; then
        echo -e "${GREEN}[✓] Endpoint agent enrolled successfully.${NC}"
    else
        echo -e "${YELLOW}[!] Agent registration notice: If server is still starting, re-run: sudo aisoc-agent register${NC}"
    fi

    echo -e "[*] Running diagnostic check..."
    $SUDO aisoc-agent test || true

    echo -e "[*] Enabling and starting aisoc-agent background service..."
    $SUDO systemctl enable --now aisoc-agent
    echo -e "${GREEN}[✓] Endpoint Agent service active.${NC}"
    cd "${ROOT_DIR}"
fi

# ------------------------------------------------------------------------------
# Completion Overview
# ------------------------------------------------------------------------------
echo -e "\n${GREEN}${BOLD}========================================================================${NC}"
echo -e "${GREEN}${BOLD}       AI-SOC FULL INSTALLATION & DEPLOYMENT COMPLETED!                 ${NC}"
echo -e "${GREEN}${BOLD}========================================================================${NC}"
echo ""
echo -e "Web Platform:"
echo -e "  Dashboard:     ${CYAN}${BOLD}http://localhost:3000${NC}"
echo -e "  API Docs:      ${CYAN}${BOLD}http://localhost:3000/api/docs${NC}"
echo -e "  Credentials:   ${BOLD}admin / admin123${NC}"
echo ""
echo -e "System Services:"
echo -e "  Central SOC:   ${BOLD}sudo systemctl status aisoc${NC}"
echo -e "  Endpoint Agent: ${BOLD}sudo systemctl status aisoc-agent${NC}"
echo ""
echo -e "Helpful Agent Commands:"
echo -e "  sudo aisoc-agent test       # Run end-to-end diagnostic pipeline"
echo -e "  sudo aisoc-agent status     # View agent status & spool queue"
echo -e "  sudo journalctl -u aisoc -f # View central server logs"
echo -e "  sudo journalctl -u aisoc-agent -f # View agent telemetry logs"
echo -e "${CYAN}========================================================================${NC}"
