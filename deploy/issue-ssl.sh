#!/usr/bin/env bash
# Ejecutar UNA VEZ cuando el DNS de securitia.es (A y www) apunte a 78.46.100.91.
set -euo pipefail
H=/usr/local/hestia/bin
IP=$(dig +short securitia.es A | tail -1)
if [ "$IP" != "78.46.100.91" ]; then
  echo "❌ securitia.es aún resuelve a ${IP:-nada}. Cambia el registro A a 78.46.100.91 y vuelve a ejecutar."; exit 1
fi
$H/v-add-letsencrypt-domain admin securitia.es www.securitia.es
$H/v-add-web-domain-ssl-force admin securitia.es
$H/v-add-web-domain-ssl-hsts admin securitia.es
echo "✅ SSL emitido, HTTPS forzado y HSTS activo."
curl -sI https://securitia.es | head -3
