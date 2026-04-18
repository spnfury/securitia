/**
 * Securitia — Email Service (Resend)
 */
import { Resend } from 'resend';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const resend = new Resend(process.env.RESEND_API_KEY);

function loadTemplate() {
  return readFileSync(join(__dirname, 'templates', 'report.html'), 'utf8');
}

function getSeverityColor(severity) {
  switch (severity) {
    case 'critical': return '#ef4444';
    case 'warning': return '#f59e0b';
    case 'passed': return '#22c55e';
    default: return '#6b7280';
  }
}

function getSeverityIcon(severity) {
  switch (severity) {
    case 'critical': return '🔴';
    case 'warning': return '🟡';
    case 'passed': return '🟢';
    default: return '⚪';
  }
}

function getScoreColor(score) {
  const colors = { A: '#22c55e', B: '#84cc16', C: '#f59e0b', D: '#f97316', F: '#ef4444' };
  return colors[score] || '#6b7280';
}

function buildResultsHTML(results, showPremium = false) {
  const freeResults = results.filter(r => r.free);
  const premiumResults = results.filter(r => !r.free);

  let html = '';

  // Free results — always show full detail
  freeResults.forEach(r => {
    html += `
      <div style="background: #1a1a2e; border-left: 4px solid ${getSeverityColor(r.severity)}; border-radius: 8px; padding: 16px; margin-bottom: 12px;">
        <div style="font-size: 14px; font-weight: 700; color: #fff; margin-bottom: 4px;">
          ${getSeverityIcon(r.severity)} ${r.name}
        </div>
        <div style="font-size: 12px; color: #94a3b8; margin-bottom: 6px;">${r.category}</div>
        <div style="font-size: 13px; color: #cbd5e1; line-height: 1.5;">${r.description}</div>
        ${r.recommendation ? `<div style="font-size: 12px; color: #00f0ff; margin-top: 8px;">💡 ${r.recommendation}</div>` : ''}
      </div>
    `;
  });

  // Premium results
  premiumResults.forEach(r => {
    if (showPremium) {
      html += `
        <div style="background: #1a1a2e; border-left: 4px solid ${getSeverityColor(r.severity)}; border-radius: 8px; padding: 16px; margin-bottom: 12px;">
          <div style="font-size: 14px; font-weight: 700; color: #fff; margin-bottom: 4px;">
            ${getSeverityIcon(r.severity)} ${r.name}
          </div>
          <div style="font-size: 12px; color: #94a3b8; margin-bottom: 6px;">${r.category}</div>
          <div style="font-size: 13px; color: #cbd5e1; line-height: 1.5;">${r.description}</div>
          ${r.recommendation ? `<div style="font-size: 12px; color: #00f0ff; margin-top: 8px;">💡 ${r.recommendation}</div>` : ''}
        </div>
      `;
    } else {
      html += `
        <div style="background: #1a1a2e; border-left: 4px solid #374151; border-radius: 8px; padding: 16px; margin-bottom: 12px; position: relative; overflow: hidden;">
          <div style="position: absolute; inset: 0; backdrop-filter: blur(4px); background: rgba(10,10,15,0.7); display: flex; align-items: center; justify-content: center;">
            <span style="font-size: 18px;">🔒</span>
          </div>
          <div style="font-size: 14px; font-weight: 700; color: #555; margin-bottom: 4px;">
            ${r.name}
          </div>
          <div style="font-size: 12px; color: #444;">${r.category}</div>
          <div style="font-size: 13px; color: #444; filter: blur(3px);">Resultado disponible en la versión premium...</div>
        </div>
      `;
    }
  });

  return html;
}

export async function sendReportEmail({ to, name, scanResult, token, paymentUrl }) {
  let template = loadTemplate();

  const resultsHTML = buildResultsHTML(scanResult.results, false);

  // Replace placeholders
  template = template
    .replace(/{{NAME}}/g, name)
    .replace(/{{URL}}/g, scanResult.url)
    .replace(/{{SCORE}}/g, scanResult.score)
    .replace(/{{SCORE_COLOR}}/g, getScoreColor(scanResult.score))
    .replace(/{{TOTAL_CHECKS}}/g, scanResult.totalChecks)
    .replace(/{{CRITICAL_COUNT}}/g, scanResult.criticalCount)
    .replace(/{{WARNING_COUNT}}/g, scanResult.warningCount)
    .replace(/{{PASSED_COUNT}}/g, scanResult.passedCount)
    .replace(/{{RESULTS_HTML}}/g, resultsHTML)
    .replace(/{{PAYMENT_URL}}/g, paymentUrl)
    .replace(/{{DATE}}/g, new Date().toLocaleDateString('es-ES', { year: 'numeric', month: 'long', day: 'numeric' }));

  const { data, error } = await resend.emails.send({
    from: 'Securitia <onboarding@resend.dev>',
    to: [to],
    subject: `🛡️ Securitia — Informe de Seguridad para ${scanResult.url}`,
    html: template,
  });

  if (error) {
    console.error('Resend error:', error);
    throw new Error(`Error enviando email: ${error.message}`);
  }

  console.log(`✅ Email sent to ${to} — ID: ${data.id}`);
  return data;
}
