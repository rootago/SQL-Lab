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

nohup python backend/app.py > app.log 2>&1 &
echo "Airfoil backend started on http://${FLASK_HOST}:${FLASK_PORT}"
echo "Log file: ${PROJECT_ROOT}/app.log"
