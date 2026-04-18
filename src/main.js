/**
 * Securitia — Main Frontend Logic
 */
import { runScanAnimation } from "./scanner-ui.js";

// ─── DOM References ───
const urlInput = document.getElementById("url-input");
const scanBtn = document.getElementById("scan-btn");
const scanBtnText = document.querySelector(".scanner-input__btn-text");
const scanBtnLoading = document.querySelector(".scanner-input__btn-loading");

const terminalSection = document.getElementById("terminal-section");
const resultsSection = document.getElementById("results-section");

const scoreValue = document.getElementById("score-value");
const resultCritical = document.getElementById("result-critical");
const resultWarning = document.getElementById("result-warning");
const resultPassed = document.getElementById("result-passed");
const resultsList = document.getElementById("results-list");

const leadForm = document.getElementById("lead-form");
const leadName = document.getElementById("lead-name");
const leadEmail = document.getElementById("lead-email");
const leadBtn = document.getElementById("lead-btn");
const leadBtnText = document.querySelector(".lead-form__btn-text");
const leadBtnLoading = document.querySelector(".lead-form__btn-loading");
const leadStatus = document.getElementById("lead-status");

const statScans = document.getElementById("stat-scans");
const statVulns = document.getElementById("stat-vulns");

// ─── State ───
let currentScanId = null;
let scanResults = null;

// ─── Utility ───
function animateCounter(element, target, duration = 1500) {
  let start = 0;
  const step = target / (duration / 16);
  const timer = setInterval(() => {
    start += step;
    if (start >= target) {
      element.textContent = target.toLocaleString();
      clearInterval(timer);
    } else {
      element.textContent = Math.floor(start).toLocaleString();
    }
  }, 16);
}

function getSeverityIcon(severity) {
  switch (severity) {
    case "critical":
      return "🔴";
    case "warning":
      return "🟡";
    case "passed":
      return "🟢";
    default:
      return "⚪";
  }
}

// ─── Hydrate site texts from admin panel ───
async function hydrateTexts() {
  try {
    const res = await fetch("/api/texts");
    if (!res.ok) return;
    const texts = await res.json();
    document.querySelectorAll("[data-text]").forEach((el) => {
      const key = el.getAttribute("data-text");
      if (key && key in texts) el.textContent = texts[key];
    });
  } catch {
    // Keep hardcoded defaults if the API fails.
  }
}

// ─── Load Stats ───
async function loadStats() {
  try {
    const res = await fetch("/api/stats");
    const data = await res.json();
    animateCounter(statScans, data.totalScans);
    animateCounter(statVulns, data.totalVulnerabilities);
  } catch {
    statScans.textContent = "1,247";
    statVulns.textContent = "8,543";
  }
}

// ─── Scan Handler ───
async function handleScan() {
  const url = urlInput.value.trim();
  if (!url) {
    urlInput.focus();
    urlInput.style.borderColor = "#ef4444";
    setTimeout(() => (urlInput.style.borderColor = ""), 2000);
    return;
  }

  // Toggle loading
  scanBtn.disabled = true;
  scanBtnText.hidden = true;
  scanBtnLoading.hidden = false;

  // Hide previous results
  resultsSection.hidden = true;

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || "Error al escanear");
    }

    currentScanId = data.scanId;
    scanResults = data;

    // Run terminal animation
    await runScanAnimation(data.url, data.results);

    // Wait a moment then show results
    setTimeout(() => showResults(data), 800);
  } catch (err) {
    alert(`Error: ${err.message}`);
  } finally {
    scanBtn.disabled = false;
    scanBtnText.hidden = false;
    scanBtnLoading.hidden = true;
  }
}

// ─── Show Results ───
function showResults(data) {
  resultsSection.hidden = false;

  // Score
  scoreValue.textContent = data.score;
  scoreValue.dataset.score = data.score;

  // Stats
  resultCritical.textContent = data.criticalCount;
  resultWarning.textContent = data.warningCount;
  resultPassed.textContent = data.passedCount;

  // Results list
  resultsList.innerHTML = "";

  data.results.forEach((r, i) => {
    const item = document.createElement("div");
    const isFree = r.free;
    const severityClass = isFree ? r.severity : "locked";

    item.className = `result-item result-item--${severityClass}`;
    item.style.animationDelay = `${i * 0.05}s`;

    if (isFree) {
      item.innerHTML = `
        <div class="result-item__header">
          <span class="result-item__icon">${getSeverityIcon(r.severity)}</span>
          <span class="result-item__name">${r.name}</span>
          <span class="result-item__category">${r.category}</span>
        </div>
        <p class="result-item__desc">${r.description}</p>
        ${r.recommendation ? `<div class="result-item__recommendation">💡 ${r.recommendation}</div>` : ""}
      `;
    } else {
      item.innerHTML = `
        <div class="result-item__header">
          <span class="result-item__icon">🔒</span>
          <span class="result-item__name">${r.name}</span>
          <span class="result-item__category">${r.category}</span>
        </div>
        <p class="result-item__desc">Resultado disponible en el informe premium. Introduce tu email para recibir un resumen gratuito.</p>
        <div class="result-item__lock-overlay">🔒 Premium</div>
      `;
    }

    resultsList.appendChild(item);
  });

  // Scroll to results
  setTimeout(() => {
    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }, 200);
}

// ─── Lead Form Handler ───
async function handleLeadSubmit(e) {
  e.preventDefault();

  if (!currentScanId) {
    leadStatus.textContent = "Primero realiza un escaneo";
    leadStatus.className = "lead-form__hint lead-form__hint--error";
    return;
  }

  const name = leadName.value.trim();
  const email = leadEmail.value.trim();

  if (!name || !email) return;

  leadBtn.disabled = true;
  leadBtnText.hidden = true;
  leadBtnLoading.hidden = false;
  leadStatus.textContent = "";

  try {
    const res = await fetch("/api/lead", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scanId: currentScanId, name, email }),
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || "Error al enviar");
    }

    leadStatus.textContent =
      "✅ ¡Informe enviado! Revisa tu bandeja de entrada.";
    leadStatus.className = "lead-form__hint";
    leadForm.reset();
  } catch (err) {
    leadStatus.textContent = `❌ ${err.message}`;
    leadStatus.className = "lead-form__hint lead-form__hint--error";
  } finally {
    leadBtn.disabled = false;
    leadBtnText.hidden = false;
    leadBtnLoading.hidden = true;
  }
}

// ─── Event Listeners ───
scanBtn.addEventListener("click", handleScan);
urlInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") handleScan();
});
leadForm.addEventListener("submit", handleLeadSubmit);

// ─── Init ───
hydrateTexts();
loadStats();

// Smooth scroll for nav links
document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
  anchor.addEventListener("click", (e) => {
    e.preventDefault();
    const target = document.querySelector(anchor.getAttribute("href"));
    if (target) target.scrollIntoView({ behavior: "smooth" });
  });
});
