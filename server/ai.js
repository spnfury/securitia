/**
 * Securitia — AI article generator
 *
 * Provider chain (first available wins):
 *   1. Anthropic API      → ANTHROPIC_API_KEY (+ optional ANTHROPIC_MODEL)
 *   2. Groq (cloud)       → GROQ_API_KEY (+ optional GROQ_MODEL)
 *   3. OpenAI-compatible  → OPENAI_API_KEY (+ OPENAI_BASE_URL, OPENAI_MODEL)
 *
 * Local Ollama was removed on 2026-09-24 (it is stopped permanently on this
 * server because it saturated the CPU).
 *
 * All providers are asked for the same JSON document so the rest of the app
 * never has to care which model wrote the article.
 */

const DEFAULTS = {
  anthropicModel: "claude-sonnet-5",
  openaiModel: "gpt-4o-mini",
  groqModel: "openai/gpt-oss-120b",
};

export function activeProvider() {
  if (process.env.ANTHROPIC_API_KEY) {
    return { name: "anthropic", model: process.env.ANTHROPIC_MODEL || DEFAULTS.anthropicModel };
  }
  if (process.env.GROQ_API_KEY) {
    return { name: "groq", model: process.env.GROQ_MODEL || DEFAULTS.groqModel };
  }
  if (process.env.OPENAI_API_KEY) {
    return { name: "openai", model: process.env.OPENAI_MODEL || DEFAULTS.openaiModel };
  }
  return { name: "none", model: null };
}

const SITE_CONTEXT = {
  es: `Securitia (https://securitia.es) es un escáner online de vulnerabilidades web. Analiza cualquier URL pública con más de 15 verificaciones reales: HTTPS/TLS, cabeceras de seguridad (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), cookies (Secure/HttpOnly/SameSite), CORS, archivos sensibles expuestos (.env, .git, wp-config.php), source maps, listado de directorios, redirecciones abiertas y contenido mixto. El escaneo básico es gratuito; el informe Premium completo cuesta 29 €.`,
  en: `Securitia (https://securitia.es) is an online website vulnerability scanner. It analyzes any public URL with 15+ real checks: HTTPS/TLS, security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), cookies (Secure/HttpOnly/SameSite), CORS, exposed sensitive files (.env, .git, wp-config.php), source maps, directory listing, open redirects and mixed content. The basic scan is free; the full Premium report costs €29.`,
};

function buildPrompt({ topic, lang, keywords, audience }) {
  const es = lang === "es";
  return `${es ? "Eres un redactor experto en ciberseguridad y SEO que escribe para el blog de Securitia." : "You are an expert cybersecurity and SEO writer for the Securitia blog."}

${SITE_CONTEXT[lang]}

${es ? "TAREA: escribe un artículo completo, original y útil sobre el tema:" : "TASK: write a complete, original and useful article about:"}
"${topic}"
${keywords ? `${es ? "Palabras clave objetivo" : "Target keywords"}: ${keywords}` : ""}
${audience ? `${es ? "Audiencia" : "Audience"}: ${audience}` : ""}

${es ? "REQUISITOS" : "REQUIREMENTS"}:
- ${es ? "Idioma: español de España, tono profesional pero cercano." : "Language: English, professional but approachable tone."}
- ${es ? "Extensión: entre 1100 y 1600 palabras." : "Length: between 1100 and 1600 words."}
- ${es ? "Formato Markdown: usa ## para secciones y ### para subsecciones. Nada de H1 (el título va aparte)." : "Markdown format: use ## for sections and ### for subsections. No H1 (title goes separately)."}
- ${es ? "Empieza con un párrafo de respuesta directa (40-60 palabras) que resuma la respuesta al tema, pensado para que motores de IA y fragmentos destacados lo citen." : "Start with a direct-answer paragraph (40-60 words) summarizing the answer, optimized for AI engines and featured snippets."}
- ${es ? "Incluye listas, pasos accionables y, cuando aplique, ejemplos de configuración (nginx, Apache, cabeceras HTTP) en bloques de código." : "Include lists, actionable steps and, when relevant, configuration examples (nginx, Apache, HTTP headers) in code blocks."}
- ${es ? "Incluye una sección '## Preguntas frecuentes' con 3-4 preguntas y respuestas breves." : "Include a '## Frequently asked questions' section with 3-4 short Q&As."}
- ${es ? "Termina con una llamada a la acción natural para escanear la web gratis en https://securitia.es (una sola vez, sin ser agresivo)." : "End with a natural call to action to scan the website for free at https://securitia.es (once, not pushy)."}
- ${es ? "No inventes estadísticas con cifras exactas ni cites estudios que no existan." : "Do not invent exact statistics or cite non-existent studies."}

${es ? "RESPONDE ÚNICAMENTE con un objeto JSON válido (sin markdown alrededor, sin comentarios) con esta forma exacta" : "RESPOND ONLY with a valid JSON object (no surrounding markdown, no comments) with this exact shape"}:
{
  "title": "${es ? "Título SEO atractivo, máx 65 caracteres" : "Catchy SEO title, max 65 chars"}",
  "slug": "${es ? "slug-url-en-minusculas-sin-acentos" : "lowercase-url-slug"}",
  "meta_description": "${es ? "Meta descripción de 140-155 caracteres" : "140-155 char meta description"}",
  "excerpt": "${es ? "Resumen de 1-2 frases para el listado del blog" : "1-2 sentence summary for the blog list"}",
  "keywords": ["kw1", "kw2", "kw3", "kw4", "kw5"],
  "cover_emoji": "🛡️",
  "faq": [{"q": "...", "a": "..."}],
  "content_md": "${es ? "El artículo completo en Markdown (escapa correctamente las comillas y saltos de línea)" : "The full article in Markdown (properly escape quotes and newlines)"}"
}`;
}

// ─── Providers ───

async function callAnthropic(prompt, model) {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": process.env.ANTHROPIC_API_KEY,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model,
      max_tokens: 8000,
      temperature: 0.7,
      messages: [{ role: "user", content: prompt }],
    }),
  });
  if (!res.ok) throw new Error(`Anthropic HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
  const data = await res.json();
  return data.content?.map((c) => c.text || "").join("") || "";
}

async function callOpenAI(prompt, model) {
  const base = (process.env.OPENAI_BASE_URL || "https://api.openai.com/v1").replace(/\/$/, "");
  const res = await fetch(`${base}/chat/completions`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model,
      temperature: 0.7,
      response_format: { type: "json_object" },
      messages: [{ role: "user", content: prompt }],
    }),
  });
  if (!res.ok) throw new Error(`OpenAI HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
  const data = await res.json();
  return data.choices?.[0]?.message?.content || "";
}

async function callGroqOnce(prompt, model) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5 * 60 * 1000);
  try {
    const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${process.env.GROQ_API_KEY}`,
      },
      signal: controller.signal,
      body: JSON.stringify({
        model,
        temperature: 0.7,
        max_tokens: 12000,
        ...(model.startsWith("openai/gpt-oss") ? { reasoning_effort: "low" } : {}),
        response_format: { type: "json_object" },
        messages: [{ role: "user", content: prompt }],
      }),
    });
    if (!res.ok) throw new Error(`Groq HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
    const data = await res.json();
    return data.choices?.[0]?.message?.content || "";
  } finally {
    clearTimeout(timer);
  }
}

// Groq free tier has per-model daily token caps; on 429/404/5xx fall through
// to the next model so a single exhausted model does not stop generation.
async function callGroq(prompt, model) {
  const fallbacks = (process.env.GROQ_FALLBACK_MODELS || "openai/gpt-oss-20b,qwen/qwen3.8-27b")
    .split(",").map((m) => m.trim()).filter(Boolean);
  const chain = [model, ...fallbacks.filter((m) => m !== model)];
  let lastErr;
  for (const m of chain) {
    try {
      const text = await callGroqOnce(prompt, m);
      if (text) return text;
      lastErr = new Error(`Groq ${m}: respuesta vacía`);
    } catch (err) {
      lastErr = err;
      if (!/HTTP (429|404|413|5\d\d)/.test(err.message)) throw err;
      console.warn(`[ai] Groq ${m} falló (${err.message.slice(0, 80)}), probando siguiente modelo`);
    }
  }
  throw lastErr;
}

// ─── Parsing helpers ───

function extractJson(text) {
  const trimmed = text.trim().replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/, "");
  try {
    return JSON.parse(trimmed);
  } catch {}
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start >= 0 && end > start) {
    const candidate = trimmed.slice(start, end + 1);
    try {
      return JSON.parse(candidate);
    } catch {}
    // Common LLM failure: literal newlines inside the content string.
    try {
      return JSON.parse(candidate.replace(/\r?\n/g, "\\n").replace(/\t/g, "\\t"));
    } catch {}
  }
  throw new Error("El modelo no devolvió JSON válido");
}

export function slugify(str) {
  return String(str || "")
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 90);
}

function normalizeArticle(raw, { topic, lang }) {
  const title = String(raw.title || topic).trim().slice(0, 120);
  const content_md = String(raw.content_md || raw.content || "").trim();
  if (content_md.length < 400) throw new Error("Artículo demasiado corto o vacío");
  const keywords = Array.isArray(raw.keywords)
    ? raw.keywords.map((k) => String(k).trim()).filter(Boolean).slice(0, 10)
    : String(raw.keywords || "").split(",").map((k) => k.trim()).filter(Boolean);
  const faq = Array.isArray(raw.faq)
    ? raw.faq
        .filter((f) => f && f.q && f.a)
        .map((f) => ({ q: String(f.q).trim(), a: String(f.a).trim() }))
        .slice(0, 6)
    : [];
  return {
    title,
    slug: slugify(raw.slug || title),
    lang,
    meta_description: String(raw.meta_description || raw.excerpt || "").trim().slice(0, 160),
    excerpt: String(raw.excerpt || raw.meta_description || "").trim().slice(0, 300),
    keywords: keywords.join(", "),
    faq,
    cover_emoji: String(raw.cover_emoji || "🛡️").slice(0, 4),
    content_md,
  };
}

/**
 * Generate one article. Returns a normalized object ready to store.
 */
export async function generateArticle({ topic, lang = "es", keywords = "", audience = "" }) {
  if (!topic || !topic.trim()) throw new Error("Tema requerido");
  const provider = activeProvider();
  const prompt = buildPrompt({ topic: topic.trim(), lang, keywords, audience });
  const started = Date.now();

  let text;
  if (provider.name === "anthropic") text = await callAnthropic(prompt, provider.model);
  else if (provider.name === "groq") text = await callGroq(prompt, provider.model);
  else if (provider.name === "openai") text = await callOpenAI(prompt, provider.model);
  else throw new Error("No hay proveedor de IA configurado (define GROQ_API_KEY, ANTHROPIC_API_KEY u OPENAI_API_KEY)");

  const raw = extractJson(text);
  const article = normalizeArticle(raw, { topic, lang });
  return {
    ...article,
    model: `${provider.name}:${provider.model}`,
    generation_ms: Date.now() - started,
  };
}

/** Quick health probe for the admin panel. */
export async function providerStatus() {
  const provider = activeProvider();
  if (provider.name === "none") return { ...provider, available: false, error: "Sin proveedor de IA configurado" };
  return { ...provider, available: true };
}
