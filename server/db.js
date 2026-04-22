import Database from "better-sqlite3";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const dbPath = join(__dirname, "..", "securitia.db");
const db = new Database(dbPath);

// Enable WAL mode for better performance
db.pragma("journal_mode = WAL");

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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS leads (
    id TEXT PRIMARY KEY,
    scan_id TEXT REFERENCES scans(id),
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    email_sent INTEGER DEFAULT 0,
    paid INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
`);

const SUPPORTED_LANGS = ["es", "en"];
const DEFAULT_LANG = "es";

const DEFAULT_TEXTS = {
  es: {
    "nav.link.how": "Cómo funciona",
    "nav.link.vulns": "Vulnerabilidades",
    "nav.link.pricing": "Precios",

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

    "results.cta.title": "Recibe el informe completo en tu email",
    "results.cta.desc":
      "Introduce tu nombre y email para recibir el reporte detallado con todas las recomendaciones.",
    "results.cta.btn": "Enviar informe →",

    "footer.desc":
      "Plataforma de detección de vulnerabilidades web. Protege tu presencia digital.",
    "footer.link.privacy": "Privacidad",
    "footer.link.terms": "Términos",
    "footer.link.contact": "Contacto",
    "footer.copy": "© 2026 Securitia. Todos los derechos reservados.",
  },
  en: {
    "nav.link.how": "How it works",
    "nav.link.vulns": "Vulnerabilities",
    "nav.link.pricing": "Pricing",

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

    "results.cta.title": "Get the full report in your email",
    "results.cta.desc":
      "Enter your name and email to receive the detailed report with all recommendations.",
    "results.cta.btn": "Send report →",

    "footer.desc":
      "Web vulnerability detection platform. Protect your digital presence.",
    "footer.link.privacy": "Privacy",
    "footer.link.terms": "Terms",
    "footer.link.contact": "Contact",
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

// Prepared statements
const insertScan = db.prepare(`
  INSERT INTO scans (id, url, score, total_vulnerabilities, critical_count, warning_count, passed_count, results_json)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);

const getScan = db.prepare(`SELECT * FROM scans WHERE id = ?`);

const insertLead = db.prepare(`
  INSERT INTO leads (id, scan_id, name, email, token)
  VALUES (?, ?, ?, ?, ?)
`);

const getLeadByToken = db.prepare(`SELECT * FROM leads WHERE token = ?`);

const markEmailSent = db.prepare(
  `UPDATE leads SET email_sent = 1 WHERE id = ?`,
);

const markPaid = db.prepare(`UPDATE leads SET paid = 1 WHERE token = ?`);

const getStats = db.prepare(`
  SELECT
    (SELECT COUNT(*) FROM scans) as total_scans,
    (SELECT COUNT(*) FROM leads) as total_leads,
    (SELECT SUM(total_vulnerabilities) FROM scans) as total_vulnerabilities
`);

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

export {
  db,
  insertScan,
  getScan,
  insertLead,
  getLeadByToken,
  markEmailSent,
  markPaid,
  getStats,
  getAllTexts,
  updateTexts,
  SUPPORTED_LANGS,
  DEFAULT_LANG,
};
