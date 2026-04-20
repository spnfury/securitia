/**
 * Securitia — Express Backend
 */
import "dotenv/config";
import express from "express";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

import { scanUrl } from "./scanner.js";
import { sendReportEmail } from "./emailService.js";
import {
  insertScan,
  getScan,
  insertLead,
  getLeadByToken,
  markEmailSent,
  markPaid,
  getStats,
  getAllTexts,
  updateTexts,
} from "./db.js";
import { randomBytes } from "crypto";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

// Serve static files in production
app.use(express.static(join(__dirname, "..", "dist")));

// ─── API Routes ───

/**
 * POST /api/scan
 * Scan a URL for vulnerabilities
 */
app.post("/api/scan", async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: "URL es requerida" });
  }

  try {
    console.log(`🔍 Scanning: ${url}`);
    const result = await scanUrl(url);

    // Save to database
    const scanId = uuidv4();
    insertScan.run(
      scanId,
      result.url,
      result.score,
      result.totalChecks,
      result.criticalCount,
      result.warningCount,
      result.passedCount,
      JSON.stringify(result.results),
    );

    console.log(
      `✅ Scan complete: ${result.score} (${result.criticalCount} critical, ${result.warningCount} warnings)`,
    );

    res.json({
      scanId,
      ...result,
    });
  } catch (err) {
    console.error("Scan error:", err);
    res
      .status(500)
      .json({ error: "Error al escanear la URL. Verifica que sea válida." });
  }
});

/**
 * POST /api/lead
 * Capture a lead and send the report email
 */
app.post("/api/lead", async (req, res) => {
  const { scanId, name, email } = req.body;

  if (!scanId || !name || !email) {
    return res
      .status(400)
      .json({ error: "scanId, name y email son requeridos" });
  }

  try {
    // Get scan data
    const scan = getScan.get(scanId);
    if (!scan) {
      return res.status(404).json({ error: "Escaneo no encontrado" });
    }

    // Generate unique token
    const token = uuidv4();
    const leadId = uuidv4();

    // Save lead to database
    insertLead.run(leadId, scanId, name, email, token);

    // Build payment URL
    const baseUrl = process.env.BASE_URL || `http://localhost:${PORT}`;
    const paymentUrl = `${baseUrl}/payment.html?token=${token}`;

    // Send email via Resend
    const scanResult = {
      ...scan,
      results: JSON.parse(scan.results_json),
      totalChecks: scan.total_vulnerabilities,
      criticalCount: scan.critical_count,
      warningCount: scan.warning_count,
      passedCount: scan.passed_count,
    };

    await sendReportEmail({
      to: email,
      name,
      scanResult,
      token,
      paymentUrl,
    });

    // Mark email as sent
    markEmailSent.run(leadId);

    console.log(`📧 Lead captured: ${name} (${email}) — Token: ${token}`);

    res.json({
      success: true,
      message: "Reporte enviado a tu email",
      token,
    });
  } catch (err) {
    console.error("Lead error:", err);
    res.status(500).json({ error: `Error al procesar: ${err.message}` });
  }
});

/**
 * GET /api/report/:token
 * Get full report for a paid user
 */
app.get("/api/report/:token", (req, res) => {
  const lead = getLeadByToken.get(req.params.token);

  if (!lead) {
    return res.status(404).json({ error: "Token no válido" });
  }

  const scan = getScan.get(lead.scan_id);
  if (!scan) {
    return res.status(404).json({ error: "Escaneo no encontrado" });
  }

  const results = JSON.parse(scan.results_json);

  res.json({
    paid: lead.paid === 1,
    name: lead.name,
    url: scan.url,
    score: scan.score,
    totalChecks: scan.total_vulnerabilities,
    criticalCount: scan.critical_count,
    warningCount: scan.warning_count,
    passedCount: scan.passed_count,
    results:
      lead.paid === 1
        ? results
        : results.map((r) =>
            r.free
              ? r
              : {
                  ...r,
                  description: "[PREMIUM] Desbloquea para ver",
                  recommendation: null,
                },
          ),
  });
});

/**
 * POST /api/payment/confirm
 * Simulate payment confirmation (in production, this would be a webhook from PayPal)
 */
app.post("/api/payment/confirm", (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: "Token requerido" });
  }

  const lead = getLeadByToken.get(token);
  if (!lead) {
    return res.status(404).json({ error: "Token no válido" });
  }

  markPaid.run(token);
  console.log(`💰 Payment confirmed for token: ${token}`);

  res.json({
    success: true,
    message: "Pago confirmado. Reporte desbloqueado.",
  });
});

// ─── Admin auth (in-memory tokens, 4h TTL) ───
const ADMIN_TOKEN_TTL_MS = 4 * 60 * 60 * 1000;
const adminTokens = new Map(); // token -> expiresAt

function issueAdminToken() {
  const token = randomBytes(24).toString("hex");
  adminTokens.set(token, Date.now() + ADMIN_TOKEN_TTL_MS);
  return token;
}

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  const expiresAt = token ? adminTokens.get(token) : null;
  if (!expiresAt || expiresAt < Date.now()) {
    if (token) adminTokens.delete(token);
    return res.status(401).json({ error: "No autorizado" });
  }
  next();
}

/**
 * GET /api/texts
 * Public: all editable site copy, keyed by id.
 */
app.get("/api/texts", (req, res) => {
  res.json(getAllTexts());
});

/**
 * POST /api/admin/login
 * Exchange ADMIN_PASSWORD for a bearer token.
 */
app.post("/api/admin/login", (req, res) => {
  const { password } = req.body || {};
  const expected = process.env.ADMIN_PASSWORD;
  if (!expected) {
    return res
      .status(500)
      .json({ error: "ADMIN_PASSWORD no configurado en el servidor" });
  }
  if (!password || password !== expected) {
    return res.status(401).json({ error: "Contraseña incorrecta" });
  }
  res.json({ token: issueAdminToken() });
});

/**
 * PUT /api/admin/texts
 * Update one or many site text entries. Body: { texts: { key: value, ... } }
 */
app.put("/api/admin/texts", requireAdmin, (req, res) => {
  const texts = req.body?.texts;
  if (!texts || typeof texts !== "object") {
    return res
      .status(400)
      .json({ error: "Body debe incluir { texts: {...} }" });
  }
  updateTexts(Object.entries(texts));
  res.json({ success: true, texts: getAllTexts() });
});

/**
 * GET /api/stats
 * Public stats for the landing page
 */
app.get("/api/stats", (req, res) => {
  const stats = getStats.get();
  res.json({
    totalScans: (stats?.total_scans || 0) + 1247, // Base count for social proof
    totalLeads: stats?.total_leads || 0,
    totalVulnerabilities: (stats?.total_vulnerabilities || 0) + 8543,
  });
});

/**
 * POST /api/contact
 * Handle contact form submissions
 */
app.post("/api/contact", (req, res) => {
  const { name, email, subject, message } = req.body;

  if (!name || !email || !subject || !message) {
    return res.status(400).json({ error: "Todos los campos son requeridos" });
  }

  // In production, this would send an email or save to a database
  console.log(`📬 Contact form: ${name} (${email}) - ${subject}`);
  console.log(`   Message: ${message}`);

  res.json({ success: true, message: "Mensaje recibido. Te contactaremos pronto." });
});

// SPA fallback for Vite build
app.get("/{*splat}", (req, res) => {
  if (req.path.startsWith("/api/")) {
    return res.status(404).json({ error: "Route not found" });
  }
  res.sendFile(join(__dirname, "..", "dist", "index.html"));
});

app.listen(PORT, () => {
  console.log(`
  ╔══════════════════════════════════════╗
  ║   🛡️  SECURITIA Server Running      ║
  ║   http://localhost:${PORT}             ║
  ╚══════════════════════════════════════╝
  `);
});
