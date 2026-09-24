/**
 * Securitia — SEO / GEO rendering: blog pages (SSR), sitemap, robots, RSS, llms.txt
 */
import { marked } from "marked";
import {
  listPublishedArticles,
  countPublishedArticles,
  getAllTexts,
} from "./db.js";

export const SITE = {
  name: "Securitia",
  url: (process.env.BASE_URL || "https://securitia.es").replace(/\/$/, ""),
  logo: "/icon.svg",
  twitter: process.env.TWITTER_HANDLE || "",
  email: process.env.CONTACT_EMAIL || "hola@securitia.es",
};

marked.setOptions({ gfm: true, breaks: false });

export function escapeHtml(value) {
  return String(value ?? "").replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );
}

// Very small sanitizer for model/admin-authored markdown: strips scripts,
// inline handlers and javascript: URLs. Content is trusted-ish (admin only)
// but the model output should never be able to inject scripts.
function sanitizeHtml(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<iframe[\s\S]*?<\/iframe>/gi, "")
    .replace(/\son\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, "")
    .replace(/(href|src)\s*=\s*(["']?)\s*javascript:[^"'>\s]*/gi, "$1=$2#");
}

export function renderMarkdown(md) {
  const html = marked.parse(String(md || ""));
  return sanitizeHtml(html);
}

export function readingTime(md) {
  const words = String(md || "").split(/\s+/).filter(Boolean).length;
  return Math.max(1, Math.round(words / 200));
}

function fmtDate(iso, lang = "es") {
  if (!iso) return "";
  const d = new Date(iso.replace(" ", "T") + (iso.endsWith("Z") ? "" : "Z"));
  return d.toLocaleDateString(lang === "en" ? "en-GB" : "es-ES", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });
}
function isoDate(iso) {
  if (!iso) return new Date().toISOString();
  return new Date(iso.replace(" ", "T") + (iso.endsWith("Z") ? "" : "Z")).toISOString();
}

function jsonLd(obj) {
  return `<script type="application/ld+json">${JSON.stringify(obj).replace(/</g, "\\u003c")}</script>`;
}

export function organizationLd() {
  return {
    "@context": "https://schema.org",
    "@type": "Organization",
    name: SITE.name,
    url: SITE.url,
    logo: `${SITE.url}${SITE.logo}`,
    email: SITE.email,
    description:
      "Escáner online de vulnerabilidades web con más de 15 verificaciones reales de seguridad.",
    sameAs: SITE.twitter ? [`https://twitter.com/${SITE.twitter.replace("@", "")}`] : undefined,
  };
}

function layout({ lang, title, description, canonical, body, extraHead = "", ogType = "website", noindex = false }) {
  const t = getAllTexts(lang);
  const altLang = lang === "es" ? "en" : "es";
  return `<!doctype html>
<html lang="${lang}">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>${escapeHtml(title)}</title>
<meta name="description" content="${escapeHtml(description)}" />
<link rel="canonical" href="${canonical}" />
${noindex ? '<meta name="robots" content="noindex,follow" />' : '<meta name="robots" content="index,follow,max-image-preview:large,max-snippet:-1" />'}
<meta property="og:site_name" content="Securitia" />
<meta property="og:type" content="${ogType}" />
<meta property="og:title" content="${escapeHtml(title)}" />
<meta property="og:description" content="${escapeHtml(description)}" />
<meta property="og:url" content="${canonical}" />
<meta property="og:image" content="${SITE.url}/og-image.svg" />
<meta property="og:locale" content="${lang === "es" ? "es_ES" : "en_US"}" />
<meta name="twitter:card" content="summary_large_image" />
<meta name="twitter:title" content="${escapeHtml(title)}" />
<meta name="twitter:description" content="${escapeHtml(description)}" />
<link rel="alternate" type="application/rss+xml" title="Securitia Blog" href="${SITE.url}/blog/rss.xml" />
<link rel="icon" href="/icon.svg" type="image/svg+xml" />
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet" />
<link rel="stylesheet" href="/blog.css?v=3" />
${extraHead}
</head>
<body>
<div class="bg-grid"></div>
<div class="bg-glow bg-glow--1"></div>
<div class="bg-glow bg-glow--2"></div>
<nav class="nav">
  <div class="nav__container">
    <a href="/" class="nav__logo"><span class="nav__logo-icon">🛡️</span><span class="nav__logo-text">SECURITIA</span></a>
    <div class="nav__links">
      <a href="/#how-it-works" class="nav__link">${escapeHtml(t["nav.link.how"])}</a>
      <a href="/#vulnerabilities" class="nav__link">${escapeHtml(t["nav.link.vulns"])}</a>
      <a href="/#pricing" class="nav__link">${escapeHtml(t["nav.link.pricing"])}</a>
      <a href="/blog${lang === "en" ? "?lang=en" : ""}" class="nav__link is-active">${escapeHtml(t["nav.link.blog"] || "Blog")}</a>
      <a href="/#hero" class="nav__cta">${escapeHtml(t["hero.btn"])}</a>
    </div>
  </div>
</nav>
<main class="page">
${body}
</main>
<footer class="footer">
  <div class="footer__container">
    <div class="footer__brand">
      <span class="footer__logo">🛡️ SECURITIA</span>
      <p class="footer__desc">${escapeHtml(t["footer.desc"])}</p>
    </div>
    <div class="footer__links">
      <a href="/blog" class="footer__link">Blog</a>
      <a href="/privacy.html" class="footer__link">${escapeHtml(t["footer.link.privacy"])}</a>
      <a href="/terms.html" class="footer__link">${escapeHtml(t["footer.link.terms"])}</a>
      <a href="/contact.html" class="footer__link">${escapeHtml(t["footer.link.contact"])}</a>
      <a href="/blog?lang=${altLang}" class="footer__link" hreflang="${altLang}">${altLang.toUpperCase()}</a>
    </div>
    <div class="footer__copy">${escapeHtml(t["footer.copy"])}</div>
  </div>
</footer>
</body>
</html>`;
}

// ─── Blog index ───
export function renderBlogIndex({ lang = "es", page = 1, perPage = 12 }) {
  const total = countPublishedArticles.get(lang, lang).n;
  const pages = Math.max(1, Math.ceil(total / perPage));
  page = Math.min(Math.max(1, page), pages);
  const articles = listPublishedArticles.all(lang, lang, perPage, (page - 1) * perPage);
  const es = lang === "es";
  const title = es
    ? "Blog de seguridad web — Securitia"
    : "Web security blog — Securitia";
  const description = es
    ? "Guías prácticas sobre seguridad web: cabeceras HTTP, HTTPS, CSP, cookies, CORS, archivos expuestos y cómo proteger tu sitio. Por el equipo de Securitia."
    : "Practical guides on web security: HTTP headers, HTTPS, CSP, cookies, CORS, exposed files and how to protect your site. By the Securitia team.";
  const canonical = `${SITE.url}/blog${page > 1 ? `?page=${page}` : ""}${lang === "en" ? `${page > 1 ? "&" : "?"}lang=en` : ""}`;

  const cards = articles
    .map(
      (a) => `
    <article class="card">
      <a href="/blog/${a.slug}" class="card__link">
        <div class="card__emoji">${escapeHtml(a.cover_emoji || "🛡️")}</div>
        <h2 class="card__title">${escapeHtml(a.title)}</h2>
        <p class="card__excerpt">${escapeHtml(a.excerpt || a.meta_description || "")}</p>
        <div class="card__meta"><time datetime="${isoDate(a.published_at)}">${fmtDate(a.published_at, lang)}</time> · ${escapeHtml(a.author || "Securitia")}</div>
      </a>
    </article>`,
    )
    .join("");

  const pager =
    pages > 1
      ? `<nav class="pager" aria-label="Paginación">${
          page > 1 ? `<a href="/blog?page=${page - 1}${lang === "en" ? "&lang=en" : ""}">←</a>` : ""
        }<span>${page} / ${pages}</span>${
          page < pages ? `<a href="/blog?page=${page + 1}${lang === "en" ? "&lang=en" : ""}">→</a>` : ""
        }</nav>`
      : "";

  const body = `
  <header class="page__header">
    <span class="section-tag">${es ? "Blog" : "Blog"}</span>
    <h1 class="page__title">${es ? "Seguridad web, explicada" : "Web security, explained"}</h1>
    <p class="page__desc">${escapeHtml(description)}</p>
  </header>
  ${
    articles.length
      ? `<section class="grid">${cards}</section>${pager}`
      : `<p class="empty">${es ? "Todavía no hay artículos publicados. Vuelve pronto." : "No articles published yet. Check back soon."}</p>`
  }
  <section class="cta-box">
    <h2>${es ? "¿Tu web es segura?" : "Is your website secure?"}</h2>
    <p>${es ? "Escanea cualquier URL gratis en segundos con más de 15 verificaciones reales." : "Scan any URL for free in seconds with 15+ real checks."}</p>
    <a href="/#hero" class="btn">${es ? "Escanear ahora →" : "Scan now →"}</a>
  </section>`;

  const ld = [
    organizationLd(),
    {
      "@context": "https://schema.org",
      "@type": "Blog",
      name: "Securitia Blog",
      url: `${SITE.url}/blog`,
      description,
      publisher: { "@type": "Organization", name: SITE.name, url: SITE.url },
      blogPost: articles.map((a) => ({
        "@type": "BlogPosting",
        headline: a.title,
        url: `${SITE.url}/blog/${a.slug}`,
        datePublished: isoDate(a.published_at),
      })),
    },
    {
      "@context": "https://schema.org",
      "@type": "BreadcrumbList",
      itemListElement: [
        { "@type": "ListItem", position: 1, name: "Inicio", item: SITE.url },
        { "@type": "ListItem", position: 2, name: "Blog", item: `${SITE.url}/blog` },
      ],
    },
  ];

  return layout({
    lang,
    title,
    description,
    canonical,
    body,
    extraHead: ld.map(jsonLd).join("\n") +
      `\n<link rel="alternate" hreflang="es" href="${SITE.url}/blog" />\n<link rel="alternate" hreflang="en" href="${SITE.url}/blog?lang=en" />\n<link rel="alternate" hreflang="x-default" href="${SITE.url}/blog" />`,
  });
}

// ─── Article page ───
export function renderArticle(article, { related = [] } = {}) {
  const lang = article.lang || "es";
  const es = lang === "es";
  const canonical = `${SITE.url}/blog/${article.slug}`;
  const faq = article.faq_json ? JSON.parse(article.faq_json) : [];
  const minutes = readingTime(article.content_md);
  const keywords = (article.keywords || "").split(",").map((k) => k.trim()).filter(Boolean);

  const faqHtml = faq.length
    ? `<section class="faq"><h2>${es ? "Preguntas frecuentes" : "Frequently asked questions"}</h2>${faq
        .map(
          (f) => `<details><summary>${escapeHtml(f.q)}</summary><p>${escapeHtml(f.a)}</p></details>`,
        )
        .join("")}</section>`
    : "";

  const relatedHtml = related.length
    ? `<section class="related"><h2>${es ? "Artículos relacionados" : "Related articles"}</h2><ul>${related
        .map((r) => `<li><a href="/blog/${r.slug}">${escapeHtml(r.cover_emoji || "🛡️")} ${escapeHtml(r.title)}</a></li>`)
        .join("")}</ul></section>`
    : "";

  const body = `
  <article class="article" itemscope itemtype="https://schema.org/BlogPosting">
    <nav class="breadcrumb" aria-label="breadcrumb"><a href="/">Inicio</a> › <a href="/blog${lang === "en" ? "?lang=en" : ""}">Blog</a> › <span>${escapeHtml(article.title)}</span></nav>
    <header class="article__header">
      <div class="article__emoji">${escapeHtml(article.cover_emoji || "🛡️")}</div>
      <h1 class="article__title" itemprop="headline">${escapeHtml(article.title)}</h1>
      <p class="article__lead" itemprop="description">${escapeHtml(article.excerpt || article.meta_description || "")}</p>
      <div class="article__meta">
        <span itemprop="author" itemscope itemtype="https://schema.org/Organization"><span itemprop="name">${escapeHtml(article.author || "Equipo Securitia")}</span></span>
        · <time itemprop="datePublished" datetime="${isoDate(article.published_at)}">${fmtDate(article.published_at, lang)}</time>
        · ${minutes} min
      </div>
      ${keywords.length ? `<div class="tags">${keywords.map((k) => `<span class="tag">${escapeHtml(k)}</span>`).join("")}</div>` : ""}
    </header>
    <div class="article__body" itemprop="articleBody">
      ${article.content_html}
    </div>
    ${faqHtml}
    <section class="cta-box">
      <h2>${es ? "Comprueba ahora la seguridad de tu web" : "Check your website security now"}</h2>
      <p>${es ? "Escaneo gratuito con más de 15 verificaciones reales. Sin registro." : "Free scan with 15+ real checks. No sign-up."}</p>
      <a href="/#hero" class="btn">${es ? "Escanear gratis →" : "Scan for free →"}</a>
    </section>
    ${relatedHtml}
  </article>`;

  const ld = [
    {
      "@context": "https://schema.org",
      "@type": "BlogPosting",
      headline: article.title,
      description: article.meta_description || article.excerpt,
      url: canonical,
      mainEntityOfPage: canonical,
      inLanguage: lang,
      keywords: keywords.join(", "),
      wordCount: String(article.content_md || "").split(/\s+/).length,
      datePublished: isoDate(article.published_at),
      dateModified: isoDate(article.updated_at || article.published_at),
      author: { "@type": "Organization", name: article.author || "Equipo Securitia", url: SITE.url },
      publisher: {
        "@type": "Organization",
        name: SITE.name,
        url: SITE.url,
        logo: { "@type": "ImageObject", url: `${SITE.url}${SITE.logo}` },
      },
      image: `${SITE.url}/og-image.svg`,
    },
    {
      "@context": "https://schema.org",
      "@type": "BreadcrumbList",
      itemListElement: [
        { "@type": "ListItem", position: 1, name: "Inicio", item: SITE.url },
        { "@type": "ListItem", position: 2, name: "Blog", item: `${SITE.url}/blog` },
        { "@type": "ListItem", position: 3, name: article.title, item: canonical },
      ],
    },
  ];
  if (faq.length) {
    ld.push({
      "@context": "https://schema.org",
      "@type": "FAQPage",
      mainEntity: faq.map((f) => ({
        "@type": "Question",
        name: f.q,
        acceptedAnswer: { "@type": "Answer", text: f.a },
      })),
    });
  }

  return layout({
    lang,
    title: `${article.title} — Securitia`,
    description: article.meta_description || article.excerpt || "",
    canonical,
    body,
    ogType: "article",
    extraHead:
      ld.map(jsonLd).join("\n") +
      `\n<meta property="article:published_time" content="${isoDate(article.published_at)}" />` +
      (keywords.length ? `\n<meta name="keywords" content="${escapeHtml(keywords.join(", "))}" />` : ""),
  });
}

export function renderArticlePreview(article) {
  // Draft preview for admins: same template, noindex.
  const html = renderArticle(article);
  return html.replace('<meta name="robots" content="index,follow,max-image-preview:large,max-snippet:-1" />', '<meta name="robots" content="noindex,nofollow" />');
}

// ─── sitemap.xml ───
export function renderSitemap() {
  const staticPages = [
    { loc: "/", priority: "1.0", changefreq: "weekly" },
    { loc: "/blog", priority: "0.8", changefreq: "daily" },
    { loc: "/contact.html", priority: "0.5", changefreq: "yearly" },
    { loc: "/privacy.html", priority: "0.3", changefreq: "yearly" },
    { loc: "/terms.html", priority: "0.3", changefreq: "yearly" },
  ];
  const articles = listPublishedArticles.all("all", "all", 5000, 0);
  const urls = [
    ...staticPages.map(
      (p) => `<url><loc>${SITE.url}${p.loc}</loc><changefreq>${p.changefreq}</changefreq><priority>${p.priority}</priority></url>`,
    ),
    ...articles.map(
      (a) =>
        `<url><loc>${SITE.url}/blog/${a.slug}</loc><lastmod>${isoDate(a.updated_at || a.published_at).slice(0, 10)}</lastmod><changefreq>monthly</changefreq><priority>0.7</priority></url>`,
    ),
  ];
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join("\n")}\n</urlset>`;
}

// ─── robots.txt ───
export function renderRobots() {
  return `User-agent: *
Allow: /
Disallow: /admin
Disallow: /admin.html
Disallow: /payment.html
Disallow: /api/

# AI crawlers welcome (GEO)
User-agent: GPTBot
Allow: /
User-agent: ClaudeBot
Allow: /
User-agent: PerplexityBot
Allow: /
User-agent: Google-Extended
Allow: /

Sitemap: ${SITE.url}/sitemap.xml
`;
}

// ─── RSS ───
export function renderRss() {
  const articles = listPublishedArticles.all("all", "all", 50, 0);
  const items = articles
    .map(
      (a) => `<item>
<title>${escapeHtml(a.title)}</title>
<link>${SITE.url}/blog/${a.slug}</link>
<guid isPermaLink="true">${SITE.url}/blog/${a.slug}</guid>
<pubDate>${new Date(isoDate(a.published_at)).toUTCString()}</pubDate>
<description>${escapeHtml(a.excerpt || a.meta_description || "")}</description>
</item>`,
    )
    .join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
<title>Securitia Blog</title>
<link>${SITE.url}/blog</link>
<atom:link href="${SITE.url}/blog/rss.xml" rel="self" type="application/rss+xml" />
<description>Guías prácticas de seguridad web por Securitia.</description>
<language>es</language>
${items}
</channel>
</rss>`;
}

// ─── llms.txt (GEO: structured summary for AI engines) ───
export function renderLlmsTxt() {
  const articles = listPublishedArticles.all("all", "all", 200, 0);
  const t = getAllTexts("es");
  return `# Securitia

> ${t["hero.subtitle"]}

Securitia (${SITE.url}) es un escáner online de vulnerabilidades web. Analiza cualquier URL pública con más de 15 verificaciones reales y de solo lectura: HTTPS/TLS, cabeceras de seguridad (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), cookies (Secure, HttpOnly, SameSite), CORS, archivos sensibles expuestos (.env, .git, wp-config.php), source maps, listado de directorios, redirecciones abiertas y contenido mixto.

## Producto
- Escaneo gratuito: HTTPS, cabeceras de seguridad y CSP con recomendaciones.
- Informe Premium (29 €): las 15+ verificaciones completas con detalle y recomendación de corrección.
- El escaneo no explota vulnerabilidades ni envía cargas maliciosas; solo peticiones HTTP equivalentes a las de un navegador.

## Páginas principales
- Inicio y escáner: ${SITE.url}/
- Blog: ${SITE.url}/blog
- Contacto: ${SITE.url}/contact.html
- Privacidad: ${SITE.url}/privacy.html
- Términos: ${SITE.url}/terms.html

## Preguntas frecuentes
${[1, 2, 3, 4, 5].map((i) => `- **${t[`faq.q${i}`]}** ${t[`faq.a${i}`]}`).join("\n")}

## Artículos
${articles.map((a) => `- [${a.title}](${SITE.url}/blog/${a.slug}): ${a.excerpt || a.meta_description || ""}`).join("\n") || "- (aún sin artículos)"}
`;
}
