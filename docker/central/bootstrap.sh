#!/bin/sh
# One-off initialisation of the central database (idempotent).
set -e
python -m inspector.main init
python -m inspector.main check-config
if [ -n "$INSPECTOR_ADMIN_PASSWORD" ] && ! python - <<'PY'
import sqlite3, os, sys
c = sqlite3.connect(os.environ["INSPECTOR_DB"])
sys.exit(0 if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] else 1)
PY
then
  INSPECTOR_NEW_PASSWORD="$INSPECTOR_ADMIN_PASSWORD" python -m inspector.main create-user admin --role admin
fi
# Collector tokens are provisioned from the environment (in production: Ansible Vault / a secrets manager).
[ -n "$TOKEN_SH_NORTH" ] && python -m inspector.main add-collector sh-north --token "$TOKEN_SH_NORTH"
[ -n "$TOKEN_SH_SOUTH" ] && python -m inspector.main add-collector sh-south --token "$TOKEN_SH_SOUTH"
echo "bootstrap complete"
