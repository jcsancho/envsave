#!/bin/bash
# Deploy eVault to example.com VPS
# Usage: ssh deploy@example.com 'bash -s' < deploy/deploy.sh

set -e

APP_DIR="/opt/evault"
REPO="https://github.com/jcsancho/safebox.git"

echo "=== Deploying eVault ==="

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
cp deploy/nginx.conf /etc/nginx/sites-available/evault
ln -sf /etc/nginx/sites-available/evault /etc/nginx/sites-enabled/evault

# SSL cert (first time only)
if [ ! -d "/etc/letsencrypt/live/evault.example.com" ]; then
  certbot --nginx -d evault.example.com --non-interactive --agree-tos -m admin@example.com
fi

nginx -t && systemctl reload nginx

# Copy and start service
cp deploy/evault.service /etc/systemd/system/evault.service
systemctl daemon-reload
systemctl enable evault
systemctl restart evault

echo "=== eVault deployed at https://evault.example.com ==="
