#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if [ -f "backend/server_env.sh" ]; then
  source "backend/server_env.sh"
else
  source "backend/server_env.example.sh"
fi

if [ -f ".venv/bin/activate" ]; then
  source ".venv/bin/activate"
fi

python backend/import_mysql.py \
  --host "$MYSQL_HOST" \
  --port "$MYSQL_PORT" \
  --user "$MYSQL_USER" \
  --password "$MYSQL_PASSWORD" \
  --database "$MYSQL_DATABASE" \
  --reset
