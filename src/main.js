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

// ─── Language & admin mode detection ───
const urlParams = new URLSearchParams(window.location.search);
const SUPPORTED_LANGS = ["es", "en"];
const storedLang = localStorage.getItem("securitia_lang");
const requestedLang = urlParams.get("lang") || storedLang;
const CURRENT_LANG = SUPPORTED_LANGS.includes(requestedLang)
  ? requestedLang
  : "es";
if (urlParams.get("lang") && SUPPORTED_LANGS.includes(urlParams.get("lang"))) {
  localStorage.setItem("securitia_lang", urlParams.get("lang"));
}
document.documentElement.lang = CURRENT_LANG;
const IS_ADMIN = urlParams.get("admin") === "1";

// ─── Hydrate site texts from admin panel ───
function applyTexts(texts) {
  document.querySelectorAll("[data-text]").forEach((el) => {
    const key = el.getAttribute("data-text");
    if (key && key in texts) el.textContent = texts[key];
  });
}

async function hydrateTexts() {
  try {
    const res = await fetch(`/api/texts?lang=${CURRENT_LANG}`);
    if (!res.ok) return;
    const payload = await res.json();
    const texts = payload.texts || payload;
    applyTexts(texts);
  } catch {
    // Keep hardcoded defaults if the API fails.
  }
}

// ─── Language switcher (nav) ───
function setupLangSwitcher() {
  document.querySelectorAll("[data-lang-switch]").forEach((btn) => {
    const lang = btn.getAttribute("data-lang-switch");
    if (lang === CURRENT_LANG) btn.classList.add("is-active");
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      if (lang === CURRENT_LANG) return;
      localStorage.setItem("securitia_lang", lang);
      const params = new URLSearchParams(window.location.search);
      params.set("lang", lang);
      window.location.search = params.toString();
    });
  });
}

// ─── Admin visual editor mode (loaded inside iframe) ───
function setupAdminEditor() {
  const style = document.createElement("style");
  style.textContent = `
    [data-text] {
      outline: 1px dashed rgba(99, 102, 241, 0.45);
      outline-offset: 2px;
      cursor: text;
      transition: outline-color 0.15s ease, background-color 0.15s ease;
    }
    [data-text]:hover {
      outline-color: #6366f1;
      background-color: rgba(99, 102, 241, 0.08);
    }
    [data-text].securitia-admin-selected {
      outline: 2px solid #6366f1 !important;
      background-color: rgba(99, 102, 241, 0.12);
    }
    [data-text][contenteditable="true"] {
      outline: 2px solid #10b981 !important;
      background-color: rgba(16, 185, 129, 0.1);
    }
  `;
  document.head.appendChild(style);

  // Disable forms and navigation clicks that would break the edit session.
  document.addEventListener(
    "submit",
    (e) => {
      e.preventDefault();
      e.stopPropagation();
    },
    true,
  );
  document.addEventListener(
    "click",
    (e) => {
      const a = e.target.closest("a");
      if (a && !a.hasAttribute("data-text")) {
        e.preventDefault();
      }
    },
    true,
  );

  let selected = null;

  function clearSelected() {
    if (selected) selected.classList.remove("securitia-admin-selected");
    selected = null;
  }

  function commitEdit(el) {
    if (el.getAttribute("contenteditable") !== "true") return;
    el.setAttribute("contenteditable", "false");
    const key = el.getAttribute("data-text");
    const value = el.textContent;
    window.parent.postMessage(
      { type: "securitia:edit", key, value, lang: CURRENT_LANG },
      "*",
    );
  }

  document.querySelectorAll("[data-text]").forEach((el) => {
    el.addEventListener("click", (e) => {
      if (el.getAttribute("contenteditable") === "true") return;
      e.preventDefault();
      e.stopPropagation();
      clearSelected();
      el.classList.add("securitia-admin-selected");
      selected = el;
      window.parent.postMessage(
        { type: "securitia:select", key: el.getAttribute("data-text") },
        "*",
      );
    });

    el.addEventListener("dblclick", (e) => {
      e.preventDefault();
      e.stopPropagation();
      el.setAttribute("contenteditable", "true");
      el.focus();
      // place caret at end
      const range = document.createRange();
      range.selectNodeContents(el);
      range.collapse(false);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    });

    el.addEventListener("keydown", (e) => {
      if (el.getAttribute("contenteditable") !== "true") return;
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        el.blur();
      } else if (e.key === "Escape") {
        e.preventDefault();
        el.blur();
      }
    });

    el.addEventListener("blur", () => commitEdit(el));
    el.addEventListener("input", () => {
      const key = el.getAttribute("data-text");
      window.parent.postMessage(
        {
          type: "securitia:input",
          key,
          value: el.textContent,
          lang: CURRENT_LANG,
        },
        "*",
      );
    });
  });

  window.addEventListener("message", (event) => {
    const msg = event.data;
    if (!msg || typeof msg !== "object") return;
    if (msg.type === "securitia:setText") {
      const el = document.querySelector(`[data-text="${msg.key}"]`);
      if (el && el.getAttribute("contenteditable") !== "true") {
        el.textContent = msg.value;
      }
    } else if (msg.type === "securitia:focusText") {
      const el = document.querySelector(`[data-text="${msg.key}"]`);
      if (!el) return;
      clearSelected();
      el.classList.add("securitia-admin-selected");
      selected = el;
      el.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  });

  window.parent.postMessage({ type: "securitia:ready" }, "*");
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
hydrateTexts().then(() => {
  setupLangSwitcher();
  if (IS_ADMIN) setupAdminEditor();
});
loadStats();

// Smooth scroll for nav links
document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
  anchor.addEventListener("click", (e) => {
    e.preventDefault();
    const target = document.querySelector(anchor.getAttribute("href"));
    if (target) target.scrollIntoView({ behavior: "smooth" });
  });
});
