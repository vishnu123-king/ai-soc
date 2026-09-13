#!/usr/bin/env bash
# ==============================================================================
# AI-SOC Production Installation & Deployment Script
# Target Platforms: Ubuntu 22.04/24.04 LTS, Debian 12, Kali Linux 2023/2024
# ==============================================================================

set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

echo -e "${BLUE}${BOLD}"
echo "========================================================================"
echo "    AI-SOC: Automated Security Operations Center Deployment Setup       "
echo "========================================================================"
echo -e "${NC}"

echo -e "[*] Project root: ${BOLD}${ROOT_DIR}${NC}"

# 1. Check OS and Distribution
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_NAME="${NAME:-Linux}"
    echo -e "[*] Detected Operating System: ${GREEN}${OS_NAME}${NC}"
else
    echo -e "${YELLOW}[!] Warning: /etc/os-release not found. Assuming Debian/Ubuntu-like Linux.${NC}"
fi

# 2. Check and Install Required System Packages
echo -e "\n${BLUE}[+] Step 1: Checking and installing Linux system dependencies...${NC}"
REQUIRED_PACKAGES=(python3 python3-venv python3-pip build-essential curl sqlite3 openssl)
MISSING_PKGS=()

for pkg in "${REQUIRED_PACKAGES[@]}"; do
    if ! dpkg -s "${pkg}" >/dev/null 2>&1; then
        MISSING_PKGS+=("${pkg}")
    fi
done

if [[ ${#MISSING_PKGS[@]} -gt 0 ]]; then
    echo -e "[*] Installing missing system packages: ${MISSING_PKGS[*]}"
    if command -v sudo >/dev/null 2>&1; then
        sudo apt-get update -y
        sudo apt-get install -y "${MISSING_PKGS[@]}"
    else
        apt-get update -y
        apt-get install -y "${MISSING_PKGS[@]}"
    fi
else
    echo -e "${GREEN}[✓] All core system packages already installed.${NC}"
fi

# 3. Check Node.js and npm
echo -e "\n${BLUE}[+] Step 2: Checking Node.js runtime environment...${NC}"
NODE_OK=0
if command -v node >/dev/null 2>&1; then
    NODE_VERSION=$(node -v | sed 's/v//' | cut -d'.' -f1)
    if [[ "${NODE_VERSION}" -ge 18 ]]; then
        echo -e "${GREEN}[✓] Node.js $(node -v) is installed and compatible (>= 18 required).${NC}"
        NODE_OK=1
    else
        echo -e "${YELLOW}[!] Node.js $(node -v) is older than recommended Node 18+.${NC}"
    fi
fi

if [[ "${NODE_OK}" -eq 0 ]]; then
    echo -e "${YELLOW}[*] Node.js 18+ is required. Installing Node.js LTS via NodeSource...${NC}"
    if command -v sudo >/dev/null 2>&1; then
        curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
        sudo apt-get install -y nodejs
    else
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y nodejs
    fi
    echo -e "${GREEN}[✓] Installed Node.js $(node -v) and npm $(npm -v).${NC}"
fi

# 4. Set Up Python Virtual Environment
echo -e "\n${BLUE}[+] Step 3: Configuring Python virtual environment (.venv)...${NC}"
if [[ ! -d ".venv" ]]; then
    echo -e "[*] Creating isolated virtual environment at ${ROOT_DIR}/.venv"
    python3 -m venv .venv
else
    echo -e "${GREEN}[✓] Virtual environment .venv already exists.${NC}"
fi

PYTHON_BIN="${ROOT_DIR}/.venv/bin/python3"
PIP_BIN="${ROOT_DIR}/.venv/bin/pip"

# Upgrade pip and wheel in venv
echo -e "[*] Upgrading pip and essential build tools..."
"${PIP_BIN}" install --upgrade pip setuptools wheel >/dev/null

echo -e "[*] Installing AI-SOC backend dependencies from backend/requirements.txt..."
"${PIP_BIN}" install -r backend/requirements.txt

echo -e "${GREEN}[✓] Python dependencies successfully installed.${NC}"

# 5. Configure Production Environment Variables (.env)
echo -e "\n${BLUE}[+] Step 4: Configuring production environment (.env)...${NC}"
if [[ ! -f ".env" ]]; then
    echo -e "[*] Creating .env from .env.example..."
    cp .env.example .env

    # Generate secure random secrets
    RANDOM_JWT=$(openssl rand -hex 32)
    RANDOM_ENROLL=$(openssl rand -hex 24)

    sed -i "s/replace-with-a-random-32-byte-hex-secret-in-production/${RANDOM_JWT}/g" .env
    sed -i "s/replace-with-a-secure-shared-agent-enrollment-key/${RANDOM_ENROLL}/g" .env

    echo -e "${GREEN}[✓] Generated unique cryptographically secure secrets in .env${NC}"
else
    echo -e "${GREEN}[✓] Existing .env file detected; preserving configuration.${NC}"
fi

# 6. Install Node Modules and Build Frontend
echo -e "\n${BLUE}[+] Step 5: Building production frontend and server bundle...${NC}"
npm install --no-audit --no-fund
npm run build

echo -e "${GREEN}[✓] Frontend and backend production bundle compiled successfully in dist/${NC}"

# 7. Initialize Database & Seed Admin
echo -e "\n${BLUE}[+] Step 6: Initializing SQLite database and default credentials...${NC}"
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
        print('    Admin user successfully verified/created.')
    else:
        print('    Admin user already present.')
finally:
    db.close()
"

# 8. Create Systemd Service Unit Template
echo -e "\n${BLUE}[+] Step 7: Generating systemd service unit...${NC}"
CURRENT_USER=$(id -un)
CURRENT_GROUP=$(id -gn)

mkdir -p "${ROOT_DIR}/systemd"

cat > "${ROOT_DIR}/systemd/aisoc.service" <<EOF
[Unit]
Description=AI-SOC Central Cybersecurity Monitoring & Incident Analysis Platform
After=network.target

[Service]
Type=simple
User=${CURRENT_USER}
Group=${CURRENT_GROUP}
WorkingDirectory=${ROOT_DIR}
Environment="NODE_ENV=production"
Environment="PATH=${ROOT_DIR}/.venv/bin:/usr/local/bin:/usr/bin:/bin"
EnvironmentFile=${ROOT_DIR}/.env
ExecStart=/usr/bin/npm run start
Restart=always
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}[✓] Created systemd service definition at systemd/aisoc.service${NC}"

# 9. Offer to enable Systemd Service
echo -e "\n${BLUE}========================================================================${NC}"
echo -e "${GREEN}${BOLD}AI-SOC PRODUCTION INSTALLATION COMPLETE!${NC}"
echo -e "${BLUE}========================================================================${NC}"
echo ""
echo -e "You can run AI-SOC right now in the foreground:"
echo -e "    ${BOLD}npm run start${NC}"
echo ""
echo -e "Or deploy as a managed Linux systemd background service:"
echo -e "    ${BOLD}sudo cp ${ROOT_DIR}/systemd/aisoc.service /etc/systemd/system/${NC}"
echo -e "    ${BOLD}sudo systemctl daemon-reload${NC}"
echo -e "    ${BOLD}sudo systemctl enable --now aisoc${NC}"
echo -e "    ${BOLD}sudo systemctl status aisoc${NC}"
echo ""
echo -e "Platform Access:"
echo -e "    Dashboard:   ${BOLD}http://localhost:3000${NC} (or http://<your-ip>:3000)"
echo -e "    API Docs:    ${BOLD}http://localhost:3000/api/docs${NC}"
echo -e "    Credentials: ${BOLD}admin / admin123${NC}"
echo ""
echo -e "To deploy an Endpoint Agent on monitored machines:"
echo -e "    ${BOLD}cd aisoc-agent && sudo ./install.sh${NC}"
echo -e "${BLUE}========================================================================${NC}"
