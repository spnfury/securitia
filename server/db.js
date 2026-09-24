import Database from "better-sqlite3";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { mkdirSync } from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Persistent path on the server (set DATABASE_PATH in .env). Falls back to repo root.
const dbPath =
  process.env.DATABASE_PATH ||
  (process.env.VERCEL
    ? "/tmp/securitia.db"
    : join(__dirname, "..", "securitia.db"));
try {
  mkdirSync(dirname(dbPath), { recursive: true });
} catch {}
const db = new Database(dbPath);

// Enable WAL mode for better performance
db.pragma("journal_mode = WAL");
db.pragma("synchronous = NORMAL");

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    score TEXT,
    total_vulnerabilities INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    warning_count INTEGER DEFAULT 0,
    passed_count INTEGER DEFAULT 0,
    results_json TEXT,
    ip TEXT,
    user_agent TEXT,
    referrer TEXT,
    lang TEXT,
    duration_ms INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS leads (
    id TEXT PRIMARY KEY,
    scan_id TEXT REFERENCES scans(id),
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    email_sent INTEGER DEFAULT 0,
    email_error TEXT,
    paid INTEGER DEFAULT 0,
    paid_at DATETIME,
    ip TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS contacts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    subject TEXT,
    message TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    read INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    path TEXT,
    ip TEXT,
    user_agent TEXT,
    referrer TEXT,
    lang TEXT,
    country TEXT,
    meta_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS articles (
    id TEXT PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    lang TEXT NOT NULL DEFAULT 'es',
    title TEXT NOT NULL,
    meta_description TEXT,
    excerpt TEXT,
    content_md TEXT NOT NULL,
    content_html TEXT NOT NULL,
    keywords TEXT,
    faq_json TEXT,
    cover_emoji TEXT DEFAULT '🛡️',
    author TEXT DEFAULT 'Equipo Securitia',
    status TEXT NOT NULL DEFAULT 'draft',
    source TEXT DEFAULT 'manual',
    model TEXT,
    views INTEGER DEFAULT 0,
    published_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS article_topics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    topic TEXT NOT NULL,
    lang TEXT NOT NULL DEFAULT 'es',
    keywords TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    article_id TEXT,
    error TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    processed_at DATETIME
  );

  CREATE TABLE IF NOT EXISTS admin_sessions (
    token TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    ip TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS site_texts_i18n (
    key TEXT NOT NULL,
    lang TEXT NOT NULL,
    value TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (key, lang)
  );

  CREATE INDEX IF NOT EXISTS idx_leads_token ON leads(token);
  CREATE INDEX IF NOT EXISTS idx_leads_email ON leads(email);
  CREATE INDEX IF NOT EXISTS idx_scans_url ON scans(url);
  CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
  CREATE INDEX IF NOT EXISTS idx_events_type_created ON events(type, created_at);
  CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
  CREATE INDEX IF NOT EXISTS idx_articles_status ON articles(status, published_at);
  CREATE INDEX IF NOT EXISTS idx_articles_slug ON articles(slug);
`);

// ─── Lightweight migrations for databases created by the old schema ───
function ensureColumn(table, column, ddl) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
  if (!cols.includes(column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${ddl}`);
}
ensureColumn("scans", "ip", "TEXT");
ensureColumn("scans", "user_agent", "TEXT");
ensureColumn("scans", "referrer", "TEXT");
ensureColumn("scans", "lang", "TEXT");
ensureColumn("scans", "duration_ms", "INTEGER");
ensureColumn("leads", "email_error", "TEXT");
ensureColumn("leads", "paid_at", "DATETIME");
ensureColumn("leads", "ip", "TEXT");
ensureColumn("leads", "user_agent", "TEXT");

const SUPPORTED_LANGS = ["es", "en"];
const DEFAULT_LANG = "es";

const DEFAULT_TEXTS = {
  es: {
    "nav.link.how": "Cómo funciona",
    "nav.link.vulns": "Vulnerabilidades",
    "nav.link.pricing": "Precios",
    "nav.link.blog": "Blog",

    "hero.badge": "Motor de análisis v2.0 — 15+ verificaciones reales",
    "hero.title.pre": "Detecta",
    "hero.title.highlight": "vulnerabilidades",
    "hero.title.post": "en tu sitio web",
    "hero.subtitle":
      "Escaneo de seguridad real con más de 15 verificaciones. Obtén un informe detallado con recomendaciones para proteger tu web.",
    "hero.btn": "Escanear ahora",
    "hero.hint": "Prueba con tu propio sitio web o cualquier URL pública",
    "hero.stats.scansLabel": "Escaneos realizados",
    "hero.stats.vulnsLabel": "Vulnerabilidades detectadas",
    "hero.stats.checksLabel": "Verificaciones de seguridad",

    "how.tag": "Proceso",
    "how.title": "Cómo funciona",
    "how.desc": "Un análisis de seguridad completo en tres sencillos pasos",
    "how.step1.title": "Introduce la URL",
    "how.step1.desc":
      "Pega la URL de cualquier sitio web público que quieras analizar.",
    "how.step2.title": "Escaneo automático",
    "how.step2.desc":
      "Nuestro motor ejecuta más de 15 verificaciones de seguridad en tiempo real contra tu sitio.",
    "how.step3.title": "Recibe tu informe",
    "how.step3.desc":
      "Obtén un informe detallado con vulnerabilidades encontradas y cómo solucionarlas.",

    "vulns.tag": "Protección",
    "vulns.title": "Qué analizamos",
    "vulns.desc":
      "Verificaciones reales contra las vulnerabilidades más comunes en sitios web",
    "vulns.card1.title": "HTTPS & TLS",
    "vulns.card1.desc":
      "Verificamos el cifrado de la comunicación y la configuración del certificado SSL.",
    "vulns.card2.title": "Security Headers",
    "vulns.card2.desc":
      "X-Frame-Options, X-Content-Type-Options, CSP y otros headers de seguridad críticos.",
    "vulns.card3.title": "Content Security Policy",
    "vulns.card3.desc":
      "Analizamos la configuración de CSP para prevenir ataques XSS e inyección de código.",
    "vulns.card4.title": "Cookie Security",
    "vulns.card4.desc":
      "Flags Secure, HttpOnly y SameSite. Protege las sesiones de tus usuarios.",
    "vulns.card5.title": "CORS & Access Control",
    "vulns.card5.desc":
      "Detectamos configuraciones CORS permisivas que expongan tu API a cualquier origen.",
    "vulns.card6.title": "Archivos Sensibles",
    "vulns.card6.desc":
      ".env, .git, wp-config.php y otros archivos que nunca deberían ser accesibles.",
    "vulns.card7.title": "Source Maps",
    "vulns.card7.desc":
      "¿Tus source maps están expuestos? Podrían revelar tu código fuente original.",
    "vulns.card8.title": "Open Redirects",
    "vulns.card8.desc":
      "Detectamos redirecciones abiertas que podrían usarse para phishing.",

    "pricing.tag": "Planes",
    "pricing.title": "Elige tu plan",
    "pricing.desc":
      "Desde un escaneo gratuito hasta un informe de seguridad completo",
    "pricing.free.name": "Gratuito",
    "pricing.free.price": "€0",
    "pricing.free.period": "por escaneo",
    "pricing.free.cta": "Escanear gratis",
    "pricing.premium.badge": "Más popular",
    "pricing.premium.name": "Premium",
    "pricing.premium.price": "€29",
    "pricing.premium.period": "por informe",
    "pricing.premium.cta": "Escanear y desbloquear",

    "faq.tag": "Preguntas frecuentes",
    "faq.title": "Todo lo que necesitas saber",
    "faq.q1": "¿Qué es Securitia?",
    "faq.a1":
      "Securitia es un escáner de vulnerabilidades web online. Analiza cualquier URL pública con más de 15 verificaciones reales (HTTPS, cabeceras de seguridad, CSP, cookies, CORS, archivos sensibles, source maps, redirecciones abiertas) y genera un informe con recomendaciones concretas.",
    "faq.q2": "¿El escaneo es legal y seguro para mi web?",
    "faq.a2":
      "Sí. Securitia solo realiza peticiones HTTP de lectura, iguales a las de un navegador. No explota vulnerabilidades ni envía cargas maliciosas, por lo que no afecta al funcionamiento del sitio analizado.",
    "faq.q3": "¿Cuánto tarda un escaneo?",
    "faq.a3":
      "Normalmente entre 5 y 20 segundos, dependiendo de la velocidad de respuesta del sitio analizado.",
    "faq.q4": "¿Qué incluye el informe Premium?",
    "faq.a4":
      "El informe Premium desbloquea las 15+ verificaciones completas con descripción detallada, nivel de riesgo y recomendación de corrección para cada hallazgo, además del informe descargable.",
    "faq.q5": "¿Guardáis los datos de mi web?",
    "faq.a5":
      "Guardamos el resultado del escaneo para poder enviarte el informe y mejorar el servicio. No almacenamos contraseñas ni datos privados de tus usuarios; solo información pública devuelta por tu servidor.",

    "results.cta.title": "Recibe el informe completo en tu email",
    "results.cta.desc":
      "Introduce tu nombre y email para recibir el reporte detallado con todas las recomendaciones.",
    "results.cta.btn": "Enviar informe →",

    "footer.desc":
      "Plataforma de detección de vulnerabilidades web. Protege tu presencia digital.",
    "footer.link.privacy": "Privacidad",
    "footer.link.terms": "Términos",
    "footer.link.contact": "Contacto",
    "footer.link.blog": "Blog",
    "footer.copy": "© 2026 Securitia. Todos los derechos reservados.",
  },
  en: {
    "nav.link.how": "How it works",
    "nav.link.vulns": "Vulnerabilities",
    "nav.link.pricing": "Pricing",
    "nav.link.blog": "Blog",

    "hero.badge": "Analysis engine v2.0 — 15+ real checks",
    "hero.title.pre": "Detect",
    "hero.title.highlight": "vulnerabilities",
    "hero.title.post": "on your website",
    "hero.subtitle":
      "Real security scan with 15+ checks. Get a detailed report with recommendations to protect your site.",
    "hero.btn": "Scan now",
    "hero.hint": "Try with your own website or any public URL",
    "hero.stats.scansLabel": "Scans performed",
    "hero.stats.vulnsLabel": "Vulnerabilities found",
    "hero.stats.checksLabel": "Security checks",

    "how.tag": "Process",
    "how.title": "How it works",
    "how.desc": "A complete security analysis in three simple steps",
    "how.step1.title": "Enter the URL",
    "how.step1.desc":
      "Paste the URL of any public website you want to analyze.",
    "how.step2.title": "Automatic scan",
    "how.step2.desc":
      "Our engine runs 15+ real-time security checks against your site.",
    "how.step3.title": "Get your report",
    "how.step3.desc":
      "Receive a detailed report with found vulnerabilities and how to fix them.",

    "vulns.tag": "Protection",
    "vulns.title": "What we analyze",
    "vulns.desc":
      "Real checks against the most common vulnerabilities on websites",
    "vulns.card1.title": "HTTPS & TLS",
    "vulns.card1.desc":
      "We verify communication encryption and SSL certificate configuration.",
    "vulns.card2.title": "Security Headers",
    "vulns.card2.desc":
      "X-Frame-Options, X-Content-Type-Options, CSP and other critical security headers.",
    "vulns.card3.title": "Content Security Policy",
    "vulns.card3.desc":
      "We analyze the CSP configuration to prevent XSS and code injection attacks.",
    "vulns.card4.title": "Cookie Security",
    "vulns.card4.desc":
      "Secure, HttpOnly and SameSite flags. Protect your users' sessions.",
    "vulns.card5.title": "CORS & Access Control",
    "vulns.card5.desc":
      "We detect permissive CORS configurations that expose your API to any origin.",
    "vulns.card6.title": "Sensitive Files",
    "vulns.card6.desc":
      ".env, .git, wp-config.php and other files that should never be accessible.",
    "vulns.card7.title": "Source Maps",
    "vulns.card7.desc":
      "Are your source maps exposed? They could reveal your original source code.",
    "vulns.card8.title": "Open Redirects",
    "vulns.card8.desc":
      "We detect open redirects that could be used for phishing.",

    "pricing.tag": "Plans",
    "pricing.title": "Choose your plan",
    "pricing.desc": "From a free scan to a complete security report",
    "pricing.free.name": "Free",
    "pricing.free.price": "€0",
    "pricing.free.period": "per scan",
    "pricing.free.cta": "Scan for free",
    "pricing.premium.badge": "Most popular",
    "pricing.premium.name": "Premium",
    "pricing.premium.price": "€29",
    "pricing.premium.period": "per report",
    "pricing.premium.cta": "Scan and unlock",

    "faq.tag": "FAQ",
    "faq.title": "Everything you need to know",
    "faq.q1": "What is Securitia?",
    "faq.a1":
      "Securitia is an online website vulnerability scanner. It analyzes any public URL with 15+ real checks (HTTPS, security headers, CSP, cookies, CORS, sensitive files, source maps, open redirects) and produces a report with concrete recommendations.",
    "faq.q2": "Is the scan legal and safe for my website?",
    "faq.a2":
      "Yes. Securitia only performs read-only HTTP requests, the same a browser would. It never exploits vulnerabilities or sends malicious payloads, so the scanned site is not affected.",
    "faq.q3": "How long does a scan take?",
    "faq.a3":
      "Usually between 5 and 20 seconds, depending on how fast the target site responds.",
    "faq.q4": "What does the Premium report include?",
    "faq.a4":
      "The Premium report unlocks all 15+ checks with a detailed description, risk level and remediation recommendation for each finding, plus a downloadable report.",
    "faq.q5": "Do you store data about my website?",
    "faq.a5":
      "We store the scan result so we can send you the report and improve the service. We never store passwords or your users' private data, only public information returned by your server.",

    "results.cta.title": "Get the full report in your email",
    "results.cta.desc":
      "Enter your name and email to receive the detailed report with all recommendations.",
    "results.cta.btn": "Send report →",

    "footer.desc":
      "Web vulnerability detection platform. Protect your digital presence.",
    "footer.link.privacy": "Privacy",
    "footer.link.terms": "Terms",
    "footer.link.contact": "Contact",
    "footer.link.blog": "Blog",
    "footer.copy": "© 2026 Securitia. All rights reserved.",
  },
};

// Migrate legacy single-table site_texts (Spanish only) into new i18n table if present.
const legacyTable = db
  .prepare(
    `SELECT name FROM sqlite_master WHERE type='table' AND name='site_texts'`,
  )
  .get();
if (legacyTable) {
  const rows = db.prepare(`SELECT key, value FROM site_texts`).all();
  const importLegacy = db.transaction((items) => {
    const stmt = db.prepare(
      `INSERT OR IGNORE INTO site_texts_i18n (key, lang, value) VALUES (?, 'es', ?)`,
    );
    for (const { key, value } of items) stmt.run(key, value);
  });
  importLegacy(rows);
  db.exec(`DROP TABLE site_texts`);
}

// Seed defaults only for keys/langs that don't exist yet (preserves admin edits).
const insertDefaultText = db.prepare(
  `INSERT OR IGNORE INTO site_texts_i18n (key, lang, value) VALUES (?, ?, ?)`,
);
const seedDefaults = db.transaction((items) => {
  for (const [key, lang, value] of items)
    insertDefaultText.run(key, lang, value);
});
const seedRows = [];
for (const lang of SUPPORTED_LANGS) {
  for (const [key, value] of Object.entries(DEFAULT_TEXTS[lang])) {
    seedRows.push([key, lang, value]);
  }
}
seedDefaults(seedRows);

// ─── Scans / leads ───
const insertScan = db.prepare(`
  INSERT INTO scans (id, url, score, total_vulnerabilities, critical_count, warning_count, passed_count, results_json, ip, user_agent, referrer, lang, duration_ms)
  VALUES (@id, @url, @score, @total, @critical, @warning, @passed, @results_json, @ip, @user_agent, @referrer, @lang, @duration_ms)
`);

const getScan = db.prepare(`SELECT * FROM scans WHERE id = ?`);

const insertLead = db.prepare(`
  INSERT INTO leads (id, scan_id, name, email, token, ip, user_agent)
  VALUES (@id, @scan_id, @name, @email, @token, @ip, @user_agent)
`);

const getLeadByToken = db.prepare(`SELECT * FROM leads WHERE token = ?`);

const markEmailSent = db.prepare(
  `UPDATE leads SET email_sent = 1, email_error = NULL WHERE id = ?`,
);
const markEmailError = db.prepare(
  `UPDATE leads SET email_sent = 0, email_error = ? WHERE id = ?`,
);

const markPaid = db.prepare(
  `UPDATE leads SET paid = 1, paid_at = CURRENT_TIMESTAMP WHERE token = ?`,
);

const getStats = db.prepare(`
  SELECT
    (SELECT COUNT(*) FROM scans) as total_scans,
    (SELECT COUNT(*) FROM leads) as total_leads,
    (SELECT SUM(total_vulnerabilities) FROM scans) as total_vulnerabilities
`);

// ─── Contacts ───
const insertContact = db.prepare(`
  INSERT INTO contacts (id, name, email, subject, message, ip, user_agent)
  VALUES (@id, @name, @email, @subject, @message, @ip, @user_agent)
`);

// ─── Events (analytics / audit log) ───
const insertEventStmt = db.prepare(`
  INSERT INTO events (type, path, ip, user_agent, referrer, lang, country, meta_json)
  VALUES (@type, @path, @ip, @user_agent, @referrer, @lang, @country, @meta_json)
`);
function logEvent(evt) {
  try {
    insertEventStmt.run({
      type: evt.type,
      path: evt.path ?? null,
      ip: evt.ip ?? null,
      user_agent: evt.user_agent ? String(evt.user_agent).slice(0, 500) : null,
      referrer: evt.referrer ? String(evt.referrer).slice(0, 500) : null,
      lang: evt.lang ?? null,
      country: evt.country ?? null,
      meta_json: evt.meta ? JSON.stringify(evt.meta) : null,
    });
  } catch (err) {
    console.error("event log error:", err.message);
  }
}

// ─── Admin sessions (persisted so restarts don't log admins out) ───
const insertSession = db.prepare(
  `INSERT INTO admin_sessions (token, expires_at, ip) VALUES (?, ?, ?)`,
);
const getSession = db.prepare(`SELECT * FROM admin_sessions WHERE token = ?`);
const deleteSession = db.prepare(`DELETE FROM admin_sessions WHERE token = ?`);
const purgeSessions = db.prepare(`DELETE FROM admin_sessions WHERE expires_at < ?`);

// ─── Settings ───
const getSettingStmt = db.prepare(`SELECT value FROM settings WHERE key = ?`);
const setSettingStmt = db.prepare(`
  INSERT INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)
  ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
`);
function getSetting(key, fallback = null) {
  const row = getSettingStmt.get(key);
  return row ? row.value : fallback;
}
function setSetting(key, value) {
  setSettingStmt.run(key, value == null ? null : String(value));
}
function getAllSettings() {
  return Object.fromEntries(
    db.prepare(`SELECT key, value FROM settings`).all().map((r) => [r.key, r.value]),
  );
}

// ─── Articles ───
const insertArticle = db.prepare(`
  INSERT INTO articles (id, slug, lang, title, meta_description, excerpt, content_md, content_html, keywords, faq_json, cover_emoji, author, status, source, model, published_at)
  VALUES (@id, @slug, @lang, @title, @meta_description, @excerpt, @content_md, @content_html, @keywords, @faq_json, @cover_emoji, @author, @status, @source, @model, @published_at)
`);
const updateArticle = db.prepare(`
  UPDATE articles SET slug=@slug, lang=@lang, title=@title, meta_description=@meta_description, excerpt=@excerpt,
    content_md=@content_md, content_html=@content_html, keywords=@keywords, faq_json=@faq_json, cover_emoji=@cover_emoji,
    author=@author, status=@status, published_at=@published_at, updated_at=CURRENT_TIMESTAMP
  WHERE id=@id
`);
const deleteArticle = db.prepare(`DELETE FROM articles WHERE id = ?`);
const getArticleById = db.prepare(`SELECT * FROM articles WHERE id = ?`);
const getArticleBySlug = db.prepare(`SELECT * FROM articles WHERE slug = ?`);
const getPublishedArticleBySlug = db.prepare(
  `SELECT * FROM articles WHERE slug = ? AND status = 'published'`,
);
const listPublishedArticles = db.prepare(`
  SELECT id, slug, lang, title, meta_description, excerpt, keywords, cover_emoji, author, views, published_at, updated_at
  FROM articles WHERE status = 'published' AND (? = 'all' OR lang = ?)
  ORDER BY published_at DESC LIMIT ? OFFSET ?
`);
const countPublishedArticles = db.prepare(
  `SELECT COUNT(*) as n FROM articles WHERE status = 'published' AND (? = 'all' OR lang = ?)`,
);
const listAllArticles = db.prepare(`
  SELECT id, slug, lang, title, status, source, model, views, published_at, created_at, updated_at
  FROM articles ORDER BY created_at DESC
`);
const bumpArticleViews = db.prepare(`UPDATE articles SET views = views + 1 WHERE id = ?`);
const slugExists = db.prepare(`SELECT 1 FROM articles WHERE slug = ? AND id != ?`);

// ─── Topics queue ───
const insertTopic = db.prepare(
  `INSERT INTO article_topics (topic, lang, keywords) VALUES (?, ?, ?)`,
);
const listTopics = db.prepare(`SELECT * FROM article_topics ORDER BY created_at DESC LIMIT 200`);
const nextPendingTopic = db.prepare(
  `SELECT * FROM article_topics WHERE status = 'pending' ORDER BY created_at ASC LIMIT 1`,
);
const markTopic = db.prepare(
  `UPDATE article_topics SET status = ?, article_id = ?, error = ?, processed_at = CURRENT_TIMESTAMP WHERE id = ?`,
);
const deleteTopic = db.prepare(`DELETE FROM article_topics WHERE id = ?`);

// ─── Site texts ───
const getTextsByLangStmt = db.prepare(
  `SELECT key, value FROM site_texts_i18n WHERE lang = ? ORDER BY key`,
);
const upsertTextStmt = db.prepare(`
  INSERT INTO site_texts_i18n (key, lang, value, updated_at)
  VALUES (?, ?, ?, CURRENT_TIMESTAMP)
  ON CONFLICT(key, lang) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
`);

function normalizeLang(lang) {
  return SUPPORTED_LANGS.includes(lang) ? lang : DEFAULT_LANG;
}

function getAllTexts(lang = DEFAULT_LANG) {
  const rows = getTextsByLangStmt.all(normalizeLang(lang));
  return Object.fromEntries(rows.map((r) => [r.key, r.value]));
}

// Only persists keys defined in defaults, so the admin UI can't inject arbitrary rows.
const updateTexts = db.transaction((entries, lang = DEFAULT_LANG) => {
  const normalized = normalizeLang(lang);
  const allowed = DEFAULT_TEXTS[normalized];
  for (const [key, value] of entries) {
    if (!(key in allowed)) continue;
    upsertTextStmt.run(key, normalized, String(value));
  }
});

// ─── Admin dashboard queries ───
function adminOverview() {
  const q = (sql, ...p) => db.prepare(sql).get(...p);
  const all = (sql, ...p) => db.prepare(sql).all(...p);
  return {
    totals: {
      scans: q(`SELECT COUNT(*) n FROM scans`).n,
      leads: q(`SELECT COUNT(*) n FROM leads`).n,
      paid: q(`SELECT COUNT(*) n FROM leads WHERE paid = 1`).n,
      contacts: q(`SELECT COUNT(*) n FROM contacts`).n,
      unreadContacts: q(`SELECT COUNT(*) n FROM contacts WHERE read = 0`).n,
      articles: q(`SELECT COUNT(*) n FROM articles WHERE status = 'published'`).n,
      drafts: q(`SELECT COUNT(*) n FROM articles WHERE status = 'draft'`).n,
      pageviews: q(`SELECT COUNT(*) n FROM events WHERE type = 'pageview'`).n,
      visitors30d: q(
        `SELECT COUNT(DISTINCT ip) n FROM events WHERE type = 'pageview' AND created_at >= datetime('now','-30 days')`,
      ).n,
    },
    last24h: {
      scans: q(`SELECT COUNT(*) n FROM scans WHERE created_at >= datetime('now','-1 day')`).n,
      leads: q(`SELECT COUNT(*) n FROM leads WHERE created_at >= datetime('now','-1 day')`).n,
      pageviews: q(
        `SELECT COUNT(*) n FROM events WHERE type = 'pageview' AND created_at >= datetime('now','-1 day')`,
      ).n,
    },
    daily: all(`
      SELECT d.day,
        (SELECT COUNT(*) FROM events e WHERE e.type='pageview' AND date(e.created_at)=d.day) AS pageviews,
        (SELECT COUNT(*) FROM scans s WHERE date(s.created_at)=d.day) AS scans,
        (SELECT COUNT(*) FROM leads l WHERE date(l.created_at)=d.day) AS leads
      FROM (
        SELECT date('now', '-' || value || ' days') AS day
        FROM (WITH RECURSIVE seq(value) AS (SELECT 0 UNION ALL SELECT value+1 FROM seq WHERE value < 29) SELECT value FROM seq)
      ) d ORDER BY d.day ASC
    `),
    topPages: all(
      `SELECT path, COUNT(*) n FROM events WHERE type='pageview' AND created_at >= datetime('now','-30 days') GROUP BY path ORDER BY n DESC LIMIT 12`,
    ),
    topReferrers: all(
      `SELECT referrer, COUNT(*) n FROM events WHERE type='pageview' AND referrer IS NOT NULL AND referrer != '' AND created_at >= datetime('now','-30 days') GROUP BY referrer ORDER BY n DESC LIMIT 12`,
    ),
    topScannedDomains: all(
      `SELECT url, COUNT(*) n, MAX(created_at) last FROM scans GROUP BY url ORDER BY n DESC LIMIT 12`,
    ),
    scoreDistribution: all(`SELECT score, COUNT(*) n FROM scans GROUP BY score ORDER BY score`),
    recentEvents: all(
      `SELECT id, type, path, ip, referrer, lang, meta_json, created_at FROM events ORDER BY id DESC LIMIT 50`,
    ),
  };
}

function paginate(sql, countSql, params, page, perPage) {
  const offset = (page - 1) * perPage;
  const rows = db.prepare(`${sql} LIMIT ? OFFSET ?`).all(...params, perPage, offset);
  const total = db.prepare(countSql).get(...params).n;
  return { rows, total, page, perPage, pages: Math.max(1, Math.ceil(total / perPage)) };
}

function listScansAdmin({ page = 1, perPage = 50, q = "" }) {
  const like = `%${q}%`;
  return paginate(
    `SELECT id, url, score, total_vulnerabilities, critical_count, warning_count, passed_count, ip, referrer, lang, duration_ms, created_at
     FROM scans WHERE url LIKE ? OR ip LIKE ? ORDER BY created_at DESC`,
    `SELECT COUNT(*) n FROM scans WHERE url LIKE ? OR ip LIKE ?`,
    [like, like],
    page,
    perPage,
  );
}

function listLeadsAdmin({ page = 1, perPage = 50, q = "" }) {
  const like = `%${q}%`;
  return paginate(
    `SELECT l.*, s.url AS scan_url, s.score AS scan_score
     FROM leads l LEFT JOIN scans s ON s.id = l.scan_id
     WHERE l.name LIKE ? OR l.email LIKE ? OR s.url LIKE ? ORDER BY l.created_at DESC`,
    `SELECT COUNT(*) n FROM leads l LEFT JOIN scans s ON s.id = l.scan_id WHERE l.name LIKE ? OR l.email LIKE ? OR s.url LIKE ?`,
    [like, like, like],
    page,
    perPage,
  );
}

function listContactsAdmin({ page = 1, perPage = 50, q = "" }) {
  const like = `%${q}%`;
  return paginate(
    `SELECT * FROM contacts WHERE name LIKE ? OR email LIKE ? OR subject LIKE ? OR message LIKE ? ORDER BY created_at DESC`,
    `SELECT COUNT(*) n FROM contacts WHERE name LIKE ? OR email LIKE ? OR subject LIKE ? OR message LIKE ?`,
    [like, like, like, like],
    page,
    perPage,
  );
}

function listEventsAdmin({ page = 1, perPage = 100, type = "" }) {
  const t = type ? type : "%";
  return paginate(
    `SELECT * FROM events WHERE type LIKE ? ORDER BY id DESC`,
    `SELECT COUNT(*) n FROM events WHERE type LIKE ?`,
    [t],
    page,
    perPage,
  );
}

const markContactRead = db.prepare(`UPDATE contacts SET read = 1 WHERE id = ?`);

export {
  db,
  dbPath,
  insertScan,
  getScan,
  insertLead,
  getLeadByToken,
  markEmailSent,
  markEmailError,
  markPaid,
  getStats,
  insertContact,
  markContactRead,
  logEvent,
  insertSession,
  getSession,
  deleteSession,
  purgeSessions,
  getSetting,
  setSetting,
  getAllSettings,
  insertArticle,
  updateArticle,
  deleteArticle,
  getArticleById,
  getArticleBySlug,
  getPublishedArticleBySlug,
  listPublishedArticles,
  countPublishedArticles,
  listAllArticles,
  bumpArticleViews,
  slugExists,
  insertTopic,
  listTopics,
  nextPendingTopic,
  markTopic,
  deleteTopic,
  getAllTexts,
  updateTexts,
  adminOverview,
  listScansAdmin,
  listLeadsAdmin,
  listContactsAdmin,
  listEventsAdmin,
  SUPPORTED_LANGS,
  DEFAULT_LANG,
  DEFAULT_TEXTS,
};
