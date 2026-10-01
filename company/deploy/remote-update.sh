#!/usr/bin/env bash
# Runs on the Ubuntu server (as root, via deploy.ps1) after the new code has
# been unpacked into /opt/aegisguard. .venv and .env are never shipped from
# Windows, so the server's own copies are kept.
set -euo pipefail

APP_DIR=/opt/aegisguard/AegisGuard/company/backend

chown -R aegisguard:aegisguard /opt/aegisguard
cd "$APP_DIR"

echo "==> Installing Python dependencies"
sudo -u aegisguard .venv/bin/pip install -q -r requirements.txt

echo "==> Applying database migrations"
sudo -u aegisguard .venv/bin/alembic upgrade head

echo "==> Restarting service"
systemctl restart aegisguard-company
sleep 2
if systemctl is-active --quiet aegisguard-company; then
  echo "==> Deployed OK: aegisguard-company is running"
else
  echo "!! aegisguard-company failed to start. Recent logs:"
  journalctl -u aegisguard-company -n 30 --no-pager
  exit 1
fi
