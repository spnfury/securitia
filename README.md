# Securitia

Escáner online de vulnerabilidades web — https://securitia.es

## Stack
- **Frontend**: HTML + Vite (multi-página: `index`, `contact`, `payment`, `privacy`, `terms`, `admin`).
- **Backend**: Node 20 + Express 5 + SQLite (`better-sqlite3`). Sirve el `dist/`, la API y el blog SSR.
- **Blog / SEO / GEO**: `/blog`, `/blog/:slug`, `/sitemap.xml`, `/robots.txt`, `/llms.txt`, `/blog/rss.xml`, JSON-LD (Organization, WebSite, SoftwareApplication, FAQPage, BlogPosting, BreadcrumbList).
- **Generador de artículos IA**: `server/ai.js`. Proveedor por prioridad: `ANTHROPIC_API_KEY` → `OPENAI_API_KEY` → Ollama local. Cola de temas con autopublicación.
- **Admin** (`/admin`): dashboard, escaneos, leads, contactos, eventos (log completo), artículos, editor visual de textos, ajustes. Exportación CSV.

## Registros que se guardan (SQLite persistente)
`scans`, `leads`, `contacts`, `events` (visitas, escaneos, leads, errores de email, pagos, logins), `articles`, `article_topics`, `settings`, `site_texts_i18n`.

## Producción (servidor propio, Hestia + nginx + pm2)
- Código: `/home/admin/web/securitia.es/private/app`
- BD: `/home/admin/web/securitia.es/private/data/securitia.db` (backup diario en `data/backups/`)
- Proceso: `pm2` → `securitia` en `127.0.0.1:4020`; nginx (plantilla Hestia `securitia`) hace proxy y sirve `/assets/` directamente con caché inmutable.
- Redesplegar: `deploy/deploy.sh`. SSL (tras cambiar DNS): `deploy/issue-ssl.sh`.

## Desarrollo
```bash
npm install
cp .env.example .env   # y rellena ADMIN_PASSWORD
npm run build && npm run dev   # http://localhost:3001
```
