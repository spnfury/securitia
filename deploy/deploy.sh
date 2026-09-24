#!/usr/bin/env bash
# Redespliega Securitia desde git: pull → deps → build → reload pm2 (sin downtime perceptible)
set -euo pipefail
APP=/home/admin/web/securitia.es/private/app
export PATH=/root/.nvm/versions/node/v20.20.2/bin:$PATH
cd "$APP"
git pull --ff-only
npm ci --omit=dev --no-audit --no-fund 2>/dev/null || npm install --no-audit --no-fund
npm install --no-save vite >/dev/null 2>&1 || true
npx vite build
pm2 reload securitia --update-env
pm2 save >/dev/null
echo "✅ Securitia desplegado $(date -Is)"
