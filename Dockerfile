# syntax=docker/dockerfile:1
# ==============================================================================
# AI-SOC Production Multi-Stage Container Build
# ==============================================================================

# Stage 1: Build Frontend and Server bundle
FROM node:20-bookworm-slim AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# Stage 2: Final Production Runtime
FROM python:3.11-slim-bookworm

WORKDIR /app

# Install Node.js runtime and essential utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    sqlite3 \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python backend dependencies
COPY backend/requirements.txt ./backend/
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r backend/requirements.txt

# Copy application artifacts from builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY backend ./backend
COPY .env.example ./.env

ENV NODE_ENV=production \
    PORT=3000 \
    FASTAPI_PORT=8088 \
    HOST=0.0.0.0 \
    PYTHONUNBUFFERED=1

EXPOSE 3000 8088

CMD ["node", "dist/server.cjs"]
