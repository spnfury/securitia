#!/usr/bin/env bash
# Copia de seguridad diaria de la BD SQLite (consistente gracias a .backup). Conserva 30 días.
set -euo pipefail
DATA=/home/admin/web/securitia.es/private/data
mkdir -p "$DATA/backups"
sqlite3 "$DATA/securitia.db" ".backup '$DATA/backups/securitia-$(date +%F).db'" 2>/dev/null || \
  node -e "const D=require('/home/admin/web/securitia.es/private/app/node_modules/better-sqlite3');new D('$DATA/securitia.db').backup('$DATA/backups/securitia-$(date +%F).db').then(()=>console.log('ok'))"
find "$DATA/backups" -name '*.db' -mtime +30 -delete
