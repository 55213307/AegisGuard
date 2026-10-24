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

echo "==> Granting the service read access to Wazuh alerts (if Wazuh is installed)"
# The alert ingester reads /var/ossec/logs/alerts/alerts.json (wazuh:wazuh,
# mode 640). Being in the wazuh group lets the aegisguard service read it;
# the restart below picks up the new group membership.
if getent group wazuh >/dev/null 2>&1; then
  usermod -a -G wazuh aegisguard
fi

echo "==> Installing AegisGuard rules into the Wazuh manager (if Wazuh is installed)"
# PowerShell script blocks (event 4104) only become alerts with this rule. The
# manager is restarted only when the rule file changed, and the new rules are
# checked first: a broken rule file must not take the manager down.
RULES_SRC=/opt/aegisguard/AegisGuard/company/deploy/wazuh/aegisguard_rules.xml
RULES_DST=/var/ossec/etc/rules/aegisguard_rules.xml
if [ -d /var/ossec/etc/rules ]; then
  if ! cmp -s "$RULES_SRC" "$RULES_DST"; then
    cp "$RULES_SRC" "$RULES_DST"
    chown root:wazuh "$RULES_DST"
    chmod 660 "$RULES_DST"
    if /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1; then
      systemctl restart wazuh-manager
      echo "   rules installed, wazuh-manager restarted"
    else
      rm -f "$RULES_DST"
      echo "!! Wazuh rejected the AegisGuard rules; they were NOT installed (PowerShell commands will not be seen)."
      /var/ossec/bin/wazuh-analysisd -t 2>&1 | tail -5 || true
    fi
  else
    echo "   rules already up to date"
  fi
fi

echo "==> Updating Nginx site config"
cp /opt/aegisguard/AegisGuard/company/deploy/nginx-aegisguard.conf /etc/nginx/sites-available/aegisguard
nginx -t
systemctl reload nginx

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
