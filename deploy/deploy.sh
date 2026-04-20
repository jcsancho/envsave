#!/bin/bash
# Deploy EnvSave to n8n droplet (203.0.113.10) behind containerized Caddy.
# Run from your local machine:  ./deploy/deploy.sh
#
# Prereqs on the server (one-time):
#   - bun installed for user jcsancho (~/.bun/bin/bun)
#   - n8n + Caddy docker-compose stack running at ~/n8n
#   - Caddyfile mounted from ~/n8n/caddy_config/Caddyfile
#   - ~/envsave/.env populated with CLERK_*, SUPABASE_*, ENVSAVE_TOKEN_SECRET
#
# First run installs the systemd unit and adds the Caddy block. Subsequent
# runs just pull + build + restart.

set -e

SSH_TARGET="jcsancho@203.0.113.10"
APP_DIR="/home/jcsancho/envsave"
REPO="https://github.com/jcsancho/envsave.git"
CADDYFILE="/home/jcsancho/n8n/caddy_config/Caddyfile"
N8N_DIR="/home/jcsancho/n8n"

echo "=== Deploying EnvSave to $SSH_TARGET ==="

ssh "$SSH_TARGET" bash -s <<'REMOTE'
set -e

APP_DIR="/home/jcsancho/envsave"
REPO="https://github.com/jcsancho/envsave.git"
CADDYFILE="/home/jcsancho/n8n/caddy_config/Caddyfile"
N8N_DIR="/home/jcsancho/n8n"
MARKER="# >>> envsave api.envsave.com >>>"

# Clone or pull
if [ -d "$APP_DIR/.git" ]; then
  cd "$APP_DIR"
  git pull origin main
else
  git clone "$REPO" "$APP_DIR"
  cd "$APP_DIR"
fi

# Install deps
~/.bun/bin/bun install --production

# Install/refresh systemd unit
if ! sudo cmp -s "$APP_DIR/deploy/envsave.service" /etc/systemd/system/envsave.service 2>/dev/null; then
  sudo cp "$APP_DIR/deploy/envsave.service" /etc/systemd/system/envsave.service
  sudo systemctl daemon-reload
  sudo systemctl enable envsave
fi

# Add Caddy block if not present (idempotent — guarded by MARKER)
# Caddy runs in docker and sees the Caddyfile at /etc/caddy/Caddyfile inside
# the container (mounted from ~/n8n/caddy_config). We append the block inline
# because files outside the mount aren't visible to the container.
if ! grep -qF "$MARKER" "$CADDYFILE"; then
  {
    echo ""
    echo "$MARKER"
    cat "$APP_DIR/deploy/Caddyfile.snippet"
    echo "# <<< envsave api.envsave.com <<<"
  } >> "$CADDYFILE"
  cd "$N8N_DIR"
  docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile
  echo "Caddy: added api.envsave.com block"
fi

# Restart the service
sudo systemctl restart envsave
sudo systemctl status envsave --no-pager --lines=5
REMOTE

echo ""
echo "=== Deployed. Test with: curl -I https://api.envsave.com ==="
