/**
 * Securitia — Express Backend
 */
// Must be first so process.env is populated before any other module evaluates.
import "./env.js";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { existsSync } from "fs";
import express from "express";
import cors from "cors";
import compression from "compression";
import rateLimit from "express-rate-limit";
import { v4 as uuidv4 } from "uuid";
import { randomBytes, timingSafeEqual } from "crypto";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

import { scanUrl, InvalidTargetError } from "./scanner.js";
import { sendReportEmail, sendContactNotification } from "./emailService.js";
import { generateArticle, providerStatus, slugify } from "./ai.js";
import {
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
  getPublishedArticleBySlug,
  listPublishedArticles,
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
} from "./db.js";
import {
  SITE,
  renderMarkdown,
  renderBlogIndex,
  renderArticle,
  renderArticlePreview,
  renderSitemap,
  renderRobots,
  renderRss,
  renderLlmsTxt,
} from "./seo.js";

const app = express();
const PORT = process.env.PORT || 3001;
const DIST = join(__dirname, "..", "dist");
const IS_PROD = process.env.NODE_ENV === "production" || existsSync(DIST);

// Behind nginx: trust X-Forwarded-* so req.ip is the real client.
app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use(compression());
app.use(cors());
app.use(express.json({ limit: "200kb" }));

// ─── Security headers (the scanner should pass its own checks) ───
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  );
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://www.paypal.com https://www.sandbox.paypal.com",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com data:",
      "img-src 'self' data: https:",
      "connect-src 'self' https://www.paypal.com https://www.sandbox.paypal.com",
      "frame-src 'self' https://www.paypal.com https://www.sandbox.paypal.com",
      "frame-ancestors 'self'",
      "base-uri 'self'",
      "form-action 'self'",
      "object-src 'none'",
      "upgrade-insecure-requests",
    ].join("; "),
  );
  if (req.secure || req.headers["x-forwarded-proto"] === "https") {
    res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  }
  next();
});

// ─── Request context helpers ───
function clientInfo(req) {
  return {
    ip: req.ip,
    user_agent: req.headers["user-agent"] || null,
    referrer: req.headers["referer"] || null,
    lang: (req.query.lang || req.headers["accept-language"] || "").toString().slice(0, 8) || null,
    country: req.headers["cf-ipcountry"] || null,
  };
}

const BOT_UA = /bot|crawl|spider|slurp|facebookexternalhit|preview|monitor|curl|wget|python-requests|headless/i;

// Log every HTML page view (not assets, not API) into the events table.
app.use((req, res, next) => {
  if (req.method !== "GET") return next();
  const p = req.path;
  const isPage =
    p === "/" ||
    p.endsWith(".html") ||
    p === "/blog" ||
    p.startsWith("/blog/") && !p.endsWith(".xml");
  if (!isPage) return next();
  const ua = req.headers["user-agent"] || "";
  logEvent({
    type: BOT_UA.test(ua) ? "botview" : "pageview",
    path: p + (req.query.lang ? `?lang=${req.query.lang}` : ""),
    ...clientInfo(req),
  });
  next();
});

// ─── Rate limits ───
const scanLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Demasiados escaneos desde esta IP. Espera unos minutos." },
});
const formLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 15,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Demasiadas solicitudes. Inténtalo más tarde." },
});
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Demasiados intentos de acceso. Espera 15 minutos." },
});

function lockPremium(r) {
  return r.free
    ? r
    : {
        ...r,
        description: "[PREMIUM] Desbloquea para ver",
        details: undefined,
        recommendation: null,
      };
}

// ═══════════════════════════════════════
// Public API
// ═══════════════════════════════════════

/**
 * POST /api/scan
 */
app.post("/api/scan", scanLimiter, async (req, res) => {
  const { url } = req.body;
  const info = clientInfo(req);

  if (!url) {
    return res.status(400).json({ error: "URL es requerida" });
  }

  try {
    console.log(`🔍 Scanning: ${url} (${info.ip})`);
    const result = await scanUrl(url);

    const scanId = uuidv4();
    insertScan.run({
      id: scanId,
      url: result.url,
      score: result.score,
      total: result.totalChecks,
      critical: result.criticalCount,
      warning: result.warningCount,
      passed: result.passedCount,
      results_json: JSON.stringify(result.results),
      ip: info.ip,
      user_agent: info.user_agent,
      referrer: info.referrer,
      lang: info.lang,
      duration_ms: result.duration,
    });
    logEvent({
      type: "scan",
      path: "/api/scan",
      ...info,
      meta: { scanId, url: result.url, score: result.score, critical: result.criticalCount },
    });

    console.log(
      `✅ Scan complete: ${result.score} (${result.criticalCount} critical, ${result.warningCount} warnings)`,
    );

    res.json({
      scanId,
      ...result,
      results: result.results.map(lockPremium),
    });
  } catch (err) {
    logEvent({ type: "scan_error", path: "/api/scan", ...info, meta: { url, error: err.message } });
    if (err instanceof InvalidTargetError) {
      return res.status(400).json({ error: err.message });
    }
    console.error("Scan error:", err);
    res
      .status(500)
      .json({ error: "Error al escanear la URL. Verifica que sea válida." });
  }
});

/**
 * POST /api/lead
 * Lead is ALWAYS stored, even if the email provider fails.
 */
app.post("/api/lead", formLimiter, async (req, res) => {
  const { scanId, name, email } = req.body;
  const info = clientInfo(req);

  if (!scanId || !name || !email) {
    return res.status(400).json({ error: "scanId, name y email son requeridos" });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: "Email no válido" });
  }

  const scan = getScan.get(scanId);
  if (!scan) {
    return res.status(404).json({ error: "Escaneo no encontrado" });
  }

  const token = uuidv4();
  const leadId = uuidv4();
  insertLead.run({
    id: leadId,
    scan_id: scanId,
    name: String(name).slice(0, 120),
    email: String(email).slice(0, 200),
    token,
    ip: info.ip,
    user_agent: info.user_agent,
  });
  logEvent({ type: "lead", path: "/api/lead", ...info, meta: { leadId, scanId, email } });

  const baseUrl = SITE.url;
  const paymentUrl = `${baseUrl}/payment.html?token=${token}`;
  const scanResult = {
    ...scan,
    results: JSON.parse(scan.results_json),
    totalChecks: scan.total_vulnerabilities,
    criticalCount: scan.critical_count,
    warningCount: scan.warning_count,
    passedCount: scan.passed_count,
  };

  try {
    await sendReportEmail({ to: email, name, scanResult, token, paymentUrl });
    markEmailSent.run(leadId);
    console.log(`📧 Lead captured: ${name} (${email}) — Token: ${token}`);
    res.json({ success: true, message: "Reporte enviado a tu email", token });
  } catch (err) {
    console.error("Lead email error:", err.message);
    markEmailError.run(err.message.slice(0, 500), leadId);
    logEvent({ type: "email_error", path: "/api/lead", ...info, meta: { leadId, error: err.message } });
    // The lead is saved; tell the user politely and give them the report link.
    res.json({
      success: true,
      emailSent: false,
      message: "Hemos registrado tu solicitud. Puedes ver tu informe aquí:",
      token,
      reportUrl: paymentUrl,
    });
  }
});

/**
 * GET /api/report/:token
 */
app.get("/api/report/:token", (req, res) => {
  const lead = getLeadByToken.get(req.params.token);
  if (!lead) return res.status(404).json({ error: "Token no válido" });

  const scan = getScan.get(lead.scan_id);
  if (!scan) return res.status(404).json({ error: "Escaneo no encontrado" });

  const results = JSON.parse(scan.results_json);
  logEvent({ type: "report_view", path: "/api/report", ...clientInfo(req), meta: { leadId: lead.id, paid: lead.paid } });

  res.json({
    paid: lead.paid === 1,
    name: lead.name,
    url: scan.url,
    score: scan.score,
    totalChecks: scan.total_vulnerabilities,
    criticalCount: scan.critical_count,
    warningCount: scan.warning_count,
    passedCount: scan.passed_count,
    results: lead.paid === 1 ? results : results.map(lockPremium),
  });
});

/**
 * POST /api/payment/confirm
 * NOTE: still a simulated confirmation (no PSP webhook yet). Logged for audit.
 */
app.post("/api/payment/confirm", formLimiter, (req, res) => {
  const { token, orderId } = req.body;
  if (!token) return res.status(400).json({ error: "Token requerido" });

  const lead = getLeadByToken.get(token);
  if (!lead) return res.status(404).json({ error: "Token no válido" });

  markPaid.run(token);
  logEvent({ type: "payment", path: "/api/payment/confirm", ...clientInfo(req), meta: { leadId: lead.id, orderId: orderId || null } });
  console.log(`💰 Payment confirmed for token: ${token}`);

  res.json({ success: true, message: "Pago confirmado. Reporte desbloqueado." });
});

/**
 * GET /api/texts?lang=es|en
 */
app.get("/api/texts", (req, res) => {
  const lang = SUPPORTED_LANGS.includes(req.query.lang) ? req.query.lang : DEFAULT_LANG;
  res.setHeader("Cache-Control", "public, max-age=60");
  res.json({ lang, supportedLangs: SUPPORTED_LANGS, texts: getAllTexts(lang) });
});

/**
 * GET /api/stats
 */
app.get("/api/stats", (req, res) => {
  const stats = getStats.get();
  res.setHeader("Cache-Control", "public, max-age=60");
  res.json({
    totalScans: (stats?.total_scans || 0) + 1247,
    totalLeads: stats?.total_leads || 0,
    totalVulnerabilities: (stats?.total_vulnerabilities || 0) + 8543,
  });
});

/**
 * POST /api/contact — persisted + optional email notification
 */
app.post("/api/contact", formLimiter, async (req, res) => {
  const { name, email, subject, message, website } = req.body;
  const info = clientInfo(req);

  // Honeypot field: bots fill it, humans never see it.
  if (website) return res.json({ success: true, message: "Mensaje recibido." });

  if (!name || !email || !subject || !message) {
    return res.status(400).json({ error: "Todos los campos son requeridos" });
  }

  const id = uuidv4();
  insertContact.run({
    id,
    name: String(name).slice(0, 120),
    email: String(email).slice(0, 200),
    subject: String(subject).slice(0, 200),
    message: String(message).slice(0, 5000),
    ip: info.ip,
    user_agent: info.user_agent,
  });
  logEvent({ type: "contact", path: "/api/contact", ...info, meta: { id, email, subject } });
  console.log(`📬 Contact form: ${name} (${email}) - ${subject}`);

  sendContactNotification({ name, email, subject, message }).catch((err) =>
    console.error("Contact notification error:", err.message),
  );

  res.json({ success: true, message: "Mensaje recibido. Te contactaremos pronto." });
});

/**
 * POST /api/event — lightweight client-side events (clicks, cta, etc.)
 */
app.post("/api/event", formLimiter, (req, res) => {
  const { type, path, meta } = req.body || {};
  if (!type || typeof type !== "string" || type.length > 40) {
    return res.status(400).json({ error: "type requerido" });
  }
  logEvent({ type: `ui_${type.replace(/[^a-z0-9_]/gi, "")}`, path: String(path || "").slice(0, 200), ...clientInfo(req), meta });
  res.json({ ok: true });
});

// ═══════════════════════════════════════
// Admin auth (sessions persisted in SQLite, 12h TTL)
// ═══════════════════════════════════════
const ADMIN_TOKEN_TTL_MS = 12 * 60 * 60 * 1000;

function issueAdminToken(ip) {
  purgeSessions.run(Date.now());
  const token = randomBytes(24).toString("hex");
  insertSession.run(token, Date.now() + ADMIN_TOKEN_TTL_MS, ip);
  return token;
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : req.query.token;
  const session = token ? getSession.get(token) : null;
  if (!session || session.expires_at < Date.now()) {
    if (token) deleteSession.run(token);
    return res.status(401).json({ error: "No autorizado" });
  }
  next();
}

app.post("/api/admin/login", loginLimiter, (req, res) => {
  const { password } = req.body || {};
  const expected = process.env.ADMIN_PASSWORD;
  if (!expected) {
    return res.status(500).json({ error: "ADMIN_PASSWORD no configurado en el servidor" });
  }
  if (!password || !safeEqual(password, expected)) {
    logEvent({ type: "admin_login_failed", path: "/api/admin/login", ...clientInfo(req) });
    return res.status(401).json({ error: "Contraseña incorrecta" });
  }
  logEvent({ type: "admin_login", path: "/api/admin/login", ...clientInfo(req) });
  res.json({ token: issueAdminToken(req.ip) });
});

app.post("/api/admin/logout", requireAdmin, (req, res) => {
  const header = req.headers.authorization || "";
  deleteSession.run(header.slice(7));
  res.json({ ok: true });
});

app.get("/api/admin/me", requireAdmin, (req, res) => res.json({ ok: true }));

// ─── Site texts ───
app.put("/api/admin/texts", requireAdmin, (req, res) => {
  const texts = req.body?.texts;
  const lang = SUPPORTED_LANGS.includes(req.body?.lang) ? req.body.lang : DEFAULT_LANG;
  if (!texts || typeof texts !== "object") {
    return res.status(400).json({ error: "Body debe incluir { lang, texts: {...} }" });
  }
  updateTexts(Object.entries(texts), lang);
  res.json({ success: true, lang, texts: getAllTexts(lang) });
});

// ─── Dashboard & records ───
app.get("/api/admin/overview", requireAdmin, (req, res) => {
  res.json({ ...adminOverview(), dbPath, uptime: process.uptime() });
});

function pageParams(req, defaultPer = 50) {
  return {
    page: Math.max(1, parseInt(req.query.page) || 1),
    perPage: Math.min(500, Math.max(1, parseInt(req.query.perPage) || defaultPer)),
    q: String(req.query.q || "").slice(0, 100),
    type: String(req.query.type || "").slice(0, 40),
  };
}

app.get("/api/admin/scans", requireAdmin, (req, res) => res.json(listScansAdmin(pageParams(req))));
app.get("/api/admin/scans/:id", requireAdmin, (req, res) => {
  const scan = getScan.get(req.params.id);
  if (!scan) return res.status(404).json({ error: "No encontrado" });
  res.json({ ...scan, results: JSON.parse(scan.results_json || "[]") });
});
app.get("/api/admin/leads", requireAdmin, (req, res) => res.json(listLeadsAdmin(pageParams(req))));
app.post("/api/admin/leads/:token/paid", requireAdmin, (req, res) => {
  markPaid.run(req.params.token);
  res.json({ ok: true });
});
app.get("/api/admin/contacts", requireAdmin, (req, res) => res.json(listContactsAdmin(pageParams(req))));
app.post("/api/admin/contacts/:id/read", requireAdmin, (req, res) => {
  markContactRead.run(req.params.id);
  res.json({ ok: true });
});
app.get("/api/admin/events", requireAdmin, (req, res) => res.json(listEventsAdmin(pageParams(req, 100))));

// CSV export
function toCsv(rows) {
  if (!rows.length) return "";
  const cols = Object.keys(rows[0]);
  const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  return [cols.join(","), ...rows.map((r) => cols.map((c) => esc(r[c])).join(","))].join("\n");
}
app.get("/api/admin/export/:table.csv", requireAdmin, (req, res) => {
  const allowed = {
    scans: `SELECT id, url, score, total_vulnerabilities, critical_count, warning_count, passed_count, ip, referrer, lang, duration_ms, created_at FROM scans ORDER BY created_at DESC`,
    leads: `SELECT l.id, l.name, l.email, l.paid, l.email_sent, l.ip, l.created_at, s.url AS scan_url, s.score FROM leads l LEFT JOIN scans s ON s.id = l.scan_id ORDER BY l.created_at DESC`,
    contacts: `SELECT id, name, email, subject, message, ip, read, created_at FROM contacts ORDER BY created_at DESC`,
    events: `SELECT id, type, path, ip, referrer, lang, country, meta_json, created_at FROM events ORDER BY id DESC LIMIT 50000`,
  };
  const sql = allowed[req.params.table];
  if (!sql) return res.status(404).json({ error: "Tabla no exportable" });
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="securitia-${req.params.table}.csv"`);
  res.send("﻿" + toCsv(db.prepare(sql).all()));
});

// ─── Settings ───
const SETTING_KEYS = [
  "autopost_enabled",
  "autopost_interval_hours",
  "default_lang",
  "article_audience",
  "ga_measurement_id",
];
app.get("/api/admin/settings", requireAdmin, async (req, res) => {
  res.json({ settings: getAllSettings(), provider: await providerStatus(), keys: SETTING_KEYS });
});
app.put("/api/admin/settings", requireAdmin, (req, res) => {
  const body = req.body || {};
  for (const key of SETTING_KEYS) {
    if (key in body) setSetting(key, body[key]);
  }
  res.json({ settings: getAllSettings() });
});

// ─── Articles ───
function uniqueSlug(base, id) {
  let slug = slugify(base) || `articulo-${Date.now()}`;
  let n = 2;
  while (slugExists.get(slug, id)) slug = `${slugify(base)}-${n++}`;
  return slug;
}

function storeArticle(data, { id = null, source = "manual", model = null } = {}) {
  const now = new Date().toISOString().slice(0, 19).replace("T", " ");
  const isNew = !id;
  const articleId = id || uuidv4();
  const existing = id ? getArticleById.get(id) : null;
  const status = ["draft", "published"].includes(data.status) ? data.status : existing?.status || "draft";
  const record = {
    id: articleId,
    slug: uniqueSlug(data.slug || data.title, articleId),
    lang: SUPPORTED_LANGS.includes(data.lang) ? data.lang : DEFAULT_LANG,
    title: String(data.title || "").trim().slice(0, 200),
    meta_description: String(data.meta_description || "").slice(0, 200),
    excerpt: String(data.excerpt || "").slice(0, 400),
    content_md: String(data.content_md || ""),
    content_html: renderMarkdown(data.content_md || ""),
    keywords: Array.isArray(data.keywords) ? data.keywords.join(", ") : String(data.keywords || ""),
    faq_json: JSON.stringify(Array.isArray(data.faq) ? data.faq : data.faq_json ? JSON.parse(data.faq_json) : []),
    cover_emoji: String(data.cover_emoji || "🛡️").slice(0, 4),
    author: String(data.author || "Equipo Securitia").slice(0, 100),
    status,
    source: existing?.source || source,
    model: existing?.model || model,
    published_at:
      status === "published" ? existing?.published_at || data.published_at || now : existing?.published_at || null,
  };
  if (!record.title) throw new Error("Título requerido");
  if (isNew) insertArticle.run(record);
  else updateArticle.run(record);
  return getArticleById.get(articleId);
}

app.get("/api/admin/articles", requireAdmin, (req, res) => res.json({ articles: listAllArticles.all() }));
app.get("/api/admin/articles/:id", requireAdmin, (req, res) => {
  const a = getArticleById.get(req.params.id);
  if (!a) return res.status(404).json({ error: "No encontrado" });
  res.json(a);
});
app.post("/api/admin/articles", requireAdmin, (req, res) => {
  try {
    res.json(storeArticle(req.body || {}));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});
app.put("/api/admin/articles/:id", requireAdmin, (req, res) => {
  if (!getArticleById.get(req.params.id)) return res.status(404).json({ error: "No encontrado" });
  try {
    res.json(storeArticle(req.body || {}, { id: req.params.id }));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});
app.delete("/api/admin/articles/:id", requireAdmin, (req, res) => {
  deleteArticle.run(req.params.id);
  res.json({ ok: true });
});
app.get("/api/admin/articles/:id/preview", requireAdmin, (req, res) => {
  const a = getArticleById.get(req.params.id);
  if (!a) return res.status(404).send("No encontrado");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(renderArticlePreview(a));
});

// Generation (synchronous; Ollama can take a few minutes so the client waits)
let generating = false;
app.post("/api/admin/articles/generate", requireAdmin, async (req, res) => {
  const { topic, lang = DEFAULT_LANG, keywords = "", publish = false } = req.body || {};
  if (!topic) return res.status(400).json({ error: "Tema requerido" });
  if (generating) return res.status(409).json({ error: "Ya hay una generación en curso" });
  generating = true;
  req.setTimeout(20 * 60 * 1000);
  try {
    const gen = await generateArticle({
      topic,
      lang,
      keywords,
      audience: getSetting("article_audience", ""),
    });
    const article = storeArticle(
      { ...gen, status: publish ? "published" : "draft" },
      { source: "ai", model: gen.model },
    );
    logEvent({ type: "article_generated", path: "/api/admin/articles/generate", ...clientInfo(req), meta: { id: article.id, model: gen.model, ms: gen.generation_ms } });
    res.json({ article, generation_ms: gen.generation_ms, model: gen.model });
  } catch (err) {
    console.error("Generate error:", err);
    res.status(500).json({ error: err.message });
  } finally {
    generating = false;
  }
});
app.get("/api/admin/articles/generate/status", requireAdmin, (req, res) => res.json({ generating }));

// Topic queue (for autopost)
app.get("/api/admin/topics", requireAdmin, (req, res) => res.json({ topics: listTopics.all() }));
app.post("/api/admin/topics", requireAdmin, (req, res) => {
  const { topics, lang = DEFAULT_LANG, keywords = "" } = req.body || {};
  const list = Array.isArray(topics) ? topics : String(topics || "").split("\n");
  const insert = db.transaction((items) => {
    for (const t of items) {
      const topic = String(t).trim();
      if (topic) insertTopic.run(topic.slice(0, 200), SUPPORTED_LANGS.includes(lang) ? lang : DEFAULT_LANG, keywords);
    }
  });
  insert(list);
  res.json({ topics: listTopics.all() });
});
app.delete("/api/admin/topics/:id", requireAdmin, (req, res) => {
  deleteTopic.run(req.params.id);
  res.json({ ok: true });
});

// ─── Autopost worker: pulls next pending topic every N hours when enabled ───
async function processNextTopic() {
  if (generating) return;
  if (getSetting("autopost_enabled", "0") !== "1") return;
  const topic = nextPendingTopic.get();
  if (!topic) return;
  generating = true;
  try {
    console.log(`🤖 Autopost: generating "${topic.topic}"`);
    const gen = await generateArticle({
      topic: topic.topic,
      lang: topic.lang,
      keywords: topic.keywords || "",
      audience: getSetting("article_audience", ""),
    });
    const article = storeArticle({ ...gen, status: "published" }, { source: "autopost", model: gen.model });
    markTopic.run("done", article.id, null, topic.id);
    logEvent({ type: "article_autopost", path: "/blog/" + article.slug, meta: { id: article.id, model: gen.model } });
    console.log(`✅ Autopost published: /blog/${article.slug}`);
  } catch (err) {
    console.error("Autopost error:", err.message);
    markTopic.run("error", null, err.message.slice(0, 500), topic.id);
  } finally {
    generating = false;
  }
}
function scheduleAutopost() {
  const hours = Math.max(1, parseFloat(getSetting("autopost_interval_hours", "24")) || 24);
  setTimeout(async () => {
    await processNextTopic();
    scheduleAutopost();
  }, hours * 60 * 60 * 1000).unref();
}
if (!process.env.VERCEL) scheduleAutopost();
app.post("/api/admin/topics/run-now", requireAdmin, async (req, res) => {
  if (generating) return res.status(409).json({ error: "Ya hay una generación en curso" });
  const topic = nextPendingTopic.get();
  if (!topic) return res.status(404).json({ error: "No hay temas pendientes" });
  req.setTimeout(20 * 60 * 1000);
  const enabled = getSetting("autopost_enabled", "0");
  setSetting("autopost_enabled", "1");
  try {
    await processNextTopic();
  } finally {
    setSetting("autopost_enabled", enabled);
  }
  res.json({ topics: listTopics.all() });
});

// ═══════════════════════════════════════
// SEO / GEO public routes
// ═══════════════════════════════════════
app.get("/blog", (req, res) => {
  const lang = SUPPORTED_LANGS.includes(req.query.lang) ? req.query.lang : DEFAULT_LANG;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "public, max-age=300");
  res.send(renderBlogIndex({ lang, page: parseInt(req.query.page) || 1 }));
});
app.get("/blog/rss.xml", (req, res) => {
  res.setHeader("Content-Type", "application/rss+xml; charset=utf-8");
  res.setHeader("Cache-Control", "public, max-age=900");
  res.send(renderRss());
});
app.get("/blog/:slug", (req, res, next) => {
  const article = getPublishedArticleBySlug.get(req.params.slug);
  if (!article) return next();
  bumpArticleViews.run(article.id);
  const related = listPublishedArticles
    .all(article.lang, article.lang, 6, 0)
    .filter((a) => a.id !== article.id)
    .slice(0, 4);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "public, max-age=600");
  res.send(renderArticle(article, { related }));
});
app.get("/sitemap.xml", (req, res) => {
  res.setHeader("Content-Type", "application/xml; charset=utf-8");
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.send(renderSitemap());
});
app.get("/robots.txt", (req, res) => {
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Cache-Control", "public, max-age=86400");
  res.send(renderRobots());
});
app.get("/llms.txt", (req, res) => {
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Cache-Control", "public, max-age=3600");
  res.send(renderLlmsTxt());
});

// Clean URLs → built pages
app.get("/admin", (req, res) => res.sendFile(join(DIST, "admin.html")));
app.get(["/contacto", "/contact"], (req, res) => res.redirect(301, "/contact.html"));
app.get(["/privacidad", "/privacy"], (req, res) => res.redirect(301, "/privacy.html"));
app.get(["/terminos", "/terms"], (req, res) => res.redirect(301, "/terms.html"));

// ─── Static (built by Vite) with aggressive caching for hashed assets ───
app.use(
  "/assets",
  express.static(join(DIST, "assets"), { immutable: true, maxAge: "365d", fallthrough: true }),
);
app.use(
  express.static(DIST, {
    maxAge: "1h",
    setHeaders(res, path) {
      if (path.endsWith(".html")) res.setHeader("Cache-Control", "no-cache");
    },
  }),
);

// SPA-ish fallback: unknown paths → 404 page (index for root-ish requests)
app.get("/{*splat}", (req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({ error: "Route not found" });
  }
  res.status(404);
  res.setHeader("Cache-Control", "no-cache");
  res.sendFile(join(DIST, "index.html"));
});

// Error handler (JSON for API, plain for the rest)
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({ error: err.message || "Error interno" });
});

export default app;

if (!process.env.VERCEL) {
  const server = app.listen(PORT, "127.0.0.1", () => {
    console.log(`
  ╔══════════════════════════════════════╗
  ║   🛡️  SECURITIA Server Running      ║
  ║   http://127.0.0.1:${PORT}            ║
  ║   DB: ${dbPath}
  ╚══════════════════════════════════════╝
  `);
  });
  server.keepAliveTimeout = 65000;
  server.headersTimeout = 66000;
}
