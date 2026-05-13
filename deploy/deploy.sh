#!/bin/bash
# Deploy EnvSave behind containerized Caddy on the configured droplet.
# Run from your local machine:  ENVSAVE_SSH_TARGET=user@host ./deploy/deploy.sh
#
# Required env vars:
#   ENVSAVE_SSH_TARGET   ssh target, e.g. deploy@1.2.3.4
#
# Optional env vars (with defaults):
#   ENVSAVE_REMOTE_USER  remote unix user (default: derived from SSH target)
#   ENVSAVE_APP_DIR      app dir on the server (default: /home/$REMOTE_USER/envsave)
#   ENVSAVE_N8N_DIR      n8n compose dir (default: /home/$REMOTE_USER/n8n)
#   ENVSAVE_CADDYFILE    path to Caddyfile (default: $N8N_DIR/caddy_config/Caddyfile)
#   ENVSAVE_REPO         git remote to clone/pull (default: https://github.com/jcsancho/envsave.git)
#
# Prereqs on the server (one-time):
#   - bun installed for the remote user (~/.bun/bin/bun)
#   - n8n + Caddy docker-compose stack running at $ENVSAVE_N8N_DIR
#   - Caddyfile mounted from $ENVSAVE_CADDYFILE
#   - $ENVSAVE_APP_DIR/.env populated with CLERK_*, SUPABASE_*, ENVSAVE_TOKEN_SECRET
#
# First run installs the systemd unit and adds the Caddy block. Subsequent
# runs just pull + build + restart.

set -e

if [ -z "${ENVSAVE_SSH_TARGET:-}" ]; then
  echo "ERROR: ENVSAVE_SSH_TARGET is required (e.g. ENVSAVE_SSH_TARGET=deploy@1.2.3.4 ./deploy/deploy.sh)" >&2
  exit 1
fi

SSH_TARGET="$ENVSAVE_SSH_TARGET"
REMOTE_USER="${ENVSAVE_REMOTE_USER:-${SSH_TARGET%@*}}"
APP_DIR="${ENVSAVE_APP_DIR:-/home/$REMOTE_USER/envsave}"
N8N_DIR="${ENVSAVE_N8N_DIR:-/home/$REMOTE_USER/n8n}"
CADDYFILE="${ENVSAVE_CADDYFILE:-$N8N_DIR/caddy_config/Caddyfile}"
REPO="${ENVSAVE_REPO:-https://github.com/jcsancho/envsave.git}"

echo "=== Deploying EnvSave to $SSH_TARGET ==="

ssh "$SSH_TARGET" \
  APP_DIR="$APP_DIR" \
  REPO="$REPO" \
  CADDYFILE="$CADDYFILE" \
  N8N_DIR="$N8N_DIR" \
  bash -s <<'REMOTE'
set -e

MARKER="# >>> envsave api block >>>"

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
# the container (mounted from the host). We append the block inline because
# files outside the mount aren't visible to the container.
if ! grep -qF "$MARKER" "$CADDYFILE"; then
  {
    echo ""
    echo "$MARKER"
    cat "$APP_DIR/deploy/Caddyfile.snippet"
    echo "# <<< envsave api block <<<"
  } >> "$CADDYFILE"
  cd "$N8N_DIR"
  docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile
  echo "Caddy: added envsave api block"
fi

# Restart the service
sudo systemctl restart envsave
sudo systemctl status envsave --no-pager --lines=5
REMOTE

echo ""
echo "=== Deployed. ==="
