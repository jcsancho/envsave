#!/bin/bash
# Deploy EnvSave to example.com VPS
# Usage: ssh deploy@example.com 'bash -s' < deploy/deploy.sh

set -e

APP_DIR="/opt/envsave"
REPO="https://github.com/jcsancho/envsave.git"

echo "=== Deploying EnvSave ==="

# Clone or pull
if [ -d "$APP_DIR" ]; then
  cd "$APP_DIR"
  git pull origin main
else
  git clone "$REPO" "$APP_DIR"
  cd "$APP_DIR"
fi

# Install dependencies
bun install --production

# Copy nginx config
cp deploy/nginx.conf /etc/nginx/sites-available/envsave
ln -sf /etc/nginx/sites-available/envsave /etc/nginx/sites-enabled/envsave

# SSL cert (first time only)
if [ ! -d "/etc/letsencrypt/live/envsave.example.com" ]; then
  certbot --nginx -d envsave.example.com --non-interactive --agree-tos -m admin@example.com
fi

nginx -t && systemctl reload nginx

# Copy and start service
cp deploy/envsave.service /etc/systemd/system/envsave.service
systemctl daemon-reload
systemctl enable envsave
systemctl restart envsave

echo "=== EnvSave deployed at https://envsave.example.com ==="
