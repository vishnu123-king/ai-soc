# AI-SOC Production Deployment & Hardening Guide

This production guide details the steps required to deploy the **AI-SOC Central Platform** and **AISOC Endpoint Agents** on production Linux servers (Ubuntu 22.04/24.04 LTS, Debian 12, or Kali Linux 2023/2024).

---

## 1. System Architecture Overview

AI-SOC operates as a high-performance modular platform:

```
[Linux Endpoint 1] ---> (HTTPS / TLS) ---\
[Linux Endpoint 2] ---> (HTTPS / TLS) ----+---> [Nginx Reverse Proxy]
[Linux Endpoint N] ---> (HTTPS / TLS) ---/             |
                                            [AI-SOC Unified Daemon]
                                            ├─ Express Proxy & React SPA (:3000)
                                            ├─ FastAPI Python Backend   (:8088)
                                            ├─ WebSocket Telemetry Bus  (/ws)
                                            └─ Persistent Store (SQLite / PostgreSQL)
```

---

## 2. Automated Production Setup (Recommended)

Run the included automated setup script in your terminal:

```bash
chmod +x scripts/setup_production.sh
./scripts/setup_production.sh
```

### What This Script Does:
1. Installs all required OS packages (`python3-venv`, `python3-pip`, `build-essential`, `sqlite3`, `curl`).
2. Configures Node.js 20 LTS.
3. Configures an isolated virtual environment (`.venv`) and installs backend dependencies.
4. Generates a production `.env` file with cryptographically secure random secrets (`JWT_SECRET_KEY` and `AGENT_ENROLLMENT_KEY`).
5. Compiles production frontend assets (`dist/`).
6. Initializes database tables and default administrator credentials (`admin` / `admin123`).
7. Creates a systemd service definition template at `systemd/aisoc.service`.

---

## 3. Manual Step-by-Step Installation

If you prefer to perform the setup manually:

### Step 1: Install System Prerequisites
```bash
sudo apt-get update -y
sudo apt-get install -y python3 python3-venv python3-pip build-essential curl sqlite3 openssl
```

### Step 2: Install Node.js 20 LTS (if not present)
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
```

### Step 3: Set Up Python Virtual Environment
```bash
cd /path/to/AI_SOC
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r backend/requirements.txt
```

### Step 4: Configure Production Environment
```bash
cp .env.example .env

# Generate secure random secrets
JWT_SECRET=$(openssl rand -hex 32)
ENROLL_SECRET=$(openssl rand -hex 24)

sed -i "s/replace-with-a-random-32-byte-hex-secret-in-production/${JWT_SECRET}/g" .env
sed -i "s/replace-with-a-secure-shared-agent-enrollment-key/${ENROLL_SECRET}/g" .env
```

### Step 5: Build Frontend & Server
```bash
npm install
npm run build
```

### Step 6: Initialize Database
```bash
.venv/bin/python3 -c "
from backend.app.database.connection import init_db
init_db()
print('Database initialized successfully.')
"
```

---

## 4. Running AI-SOC as a Linux Systemd Service

To ensure 24/7 uptime and automatic restart upon server reboot:

### 1. Copy Service File to Systemd
```bash
sudo cp systemd/aisoc.service /etc/systemd/system/aisoc.service
```

*(Verify the `User`, `Group`, and `WorkingDirectory` paths in `/etc/systemd/system/aisoc.service` match your system)*

### 2. Enable and Start Service
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aisoc
```

### 3. Check Service Status and Logs
```bash
sudo systemctl status aisoc
journalctl -u aisoc -f
```

---

## 5. Production Nginx Reverse Proxy & SSL Setup

For production deployments exposed to a network, place AI-SOC behind Nginx with Let's Encrypt SSL/TLS.

### 1. Install Nginx and Certbot
```bash
sudo apt-get install -y nginx certbot python3-certbot-nginx
```

### 2. Install Configuration
```bash
sudo cp deployment/nginx-aisoc.conf /etc/nginx/sites-available/aisoc
# Edit server_name with your actual domain or host IP:
sudo nano /etc/nginx/sites-available/aisoc

sudo ln -s /etc/nginx/sites-available/aisoc /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 3. Obtain SSL Certificate
```bash
sudo certbot --nginx -d your-soc-domain.com
```

---

## 6. PostgreSQL Database Migration (Optional for Large Scale)

For enterprise scale (millions of ingested events across dozens of agents), switch from SQLite to PostgreSQL:

1. Install PostgreSQL:
   ```bash
   sudo apt-get install -y postgresql postgresql-contrib libpq-dev
   ```
2. Create database and user:
   ```bash
   sudo -u postgres psql -c "CREATE USER aisoc WITH PASSWORD 'YourStrongPassword123!';"
   sudo -u postgres psql -c "CREATE DATABASE aisoc_prod OWNER aisoc;"
   ```
3. Install PostgreSQL driver in venv:
   ```bash
   .venv/bin/pip install psycopg2-binary
   ```
4. Update `DATABASE_URL` in `.env`:
   ```ini
   DATABASE_URL=postgresql://aisoc:YourStrongPassword123!@127.0.0.1:5432/aisoc_prod
   ```
5. Restart AI-SOC service:
   ```bash
   sudo systemctl restart aisoc
   ```

---

## 7. Firewall (UFW) Configuration

Lock down network ports for security:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 3000/tcp # Only if directly accessing without Nginx
sudo ufw enable
```

---

## 8. Endpoint Agent Deployment

Once the Central Platform is online, deploy lightweight agents to monitored servers:

```bash
cd aisoc-agent
sudo ./install.sh
```

Follow the interactive prompts to provide the Central SOC URL (e.g. `http://<soc-server-ip>:3000` or `https://soc.yourdomain.com`) and enrollment key. The agent will immediately register, obtain a secure bearer token, and start streaming real-time security telemetry!
