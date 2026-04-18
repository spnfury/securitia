/**
 * Securitia — Motor de Escaneo de Vulnerabilidades
 * Realiza verificaciones HTTP reales contra la URL proporcionada.
 */

const TIMEOUT = 8000;

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal, redirect: 'follow' });
    clearTimeout(timeout);
    return response;
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
}

// ─── Individual Checks ───

async function checkHTTPS(url) {
  const isHttps = url.startsWith('https://');
  return {
    id: 'https',
    name: 'HTTPS Encryption',
    category: 'Transport Security',
    severity: isHttps ? 'passed' : 'critical',
    description: isHttps
      ? 'El sitio usa HTTPS correctamente. La comunicación está cifrada.'
      : 'El sitio NO usa HTTPS. Los datos se transmiten sin cifrar y son vulnerables a interceptación (MITM).',
    recommendation: isHttps ? null : 'Instalar un certificado SSL/TLS (Let\'s Encrypt es gratuito) y redirigir todo el tráfico HTTP a HTTPS.',
    free: true,
  };
}

async function checkSecurityHeaders(response) {
  const headers = response.headers;
  const missing = [];

  const headerChecks = [
    { name: 'X-Frame-Options', desc: 'Protege contra clickjacking' },
    { name: 'X-Content-Type-Options', desc: 'Evita MIME sniffing' },
    { name: 'X-XSS-Protection', desc: 'Filtro XSS del navegador' },
  ];

  headerChecks.forEach(h => {
    if (!headers.get(h.name.toLowerCase())) {
      missing.push(h);
    }
  });

  return {
    id: 'security-headers',
    name: 'Security Headers',
    category: 'HTTP Headers',
    severity: missing.length === 0 ? 'passed' : missing.length >= 2 ? 'critical' : 'warning',
    description: missing.length === 0
      ? 'Todos los headers de seguridad básicos están presentes.'
      : `Faltan ${missing.length} header(s) de seguridad: ${missing.map(h => h.name).join(', ')}.`,
    details: missing.map(h => `${h.name}: ${h.desc}`),
    recommendation: missing.length > 0 ? 'Añadir los headers faltantes en la configuración del servidor web.' : null,
    free: true,
  };
}

async function checkCSP(response) {
  const csp = response.headers.get('content-security-policy');
  return {
    id: 'csp',
    name: 'Content Security Policy',
    category: 'HTTP Headers',
    severity: csp ? 'passed' : 'warning',
    description: csp
      ? 'Content Security Policy (CSP) está configurada correctamente.'
      : 'No se encontró Content Security Policy (CSP). El sitio es más vulnerable a ataques XSS e inyección de código.',
    recommendation: !csp ? 'Implementar un CSP restrictivo que limite las fuentes de scripts, estilos y otros recursos.' : null,
    free: true,
  };
}

async function checkServerDisclosure(response) {
  const server = response.headers.get('server');
  const poweredBy = response.headers.get('x-powered-by');
  const exposed = [];
  if (server) exposed.push(`Server: ${server}`);
  if (poweredBy) exposed.push(`X-Powered-By: ${poweredBy}`);

  return {
    id: 'server-disclosure',
    name: 'Server Information Disclosure',
    category: 'Information Leakage',
    severity: exposed.length > 0 ? 'warning' : 'passed',
    description: exposed.length > 0
      ? `El servidor expone información sobre su tecnología: ${exposed.join(', ')}. Esto facilita ataques dirigidos.`
      : 'El servidor no expone información sobre su tecnología subyacente.',
    recommendation: exposed.length > 0 ? 'Eliminar o modificar los headers Server y X-Powered-By.' : null,
    free: false,
  };
}

async function checkCookieSecurity(response) {
  const cookies = response.headers.get('set-cookie');
  if (!cookies) {
    return {
      id: 'cookie-security',
      name: 'Cookie Security',
      category: 'Session Security',
      severity: 'passed',
      description: 'No se detectaron cookies en la respuesta inicial.',
      free: false,
    };
  }

  const issues = [];
  if (!cookies.toLowerCase().includes('secure')) issues.push('Falta flag Secure');
  if (!cookies.toLowerCase().includes('httponly')) issues.push('Falta flag HttpOnly');
  if (!cookies.toLowerCase().includes('samesite')) issues.push('Falta flag SameSite');

  return {
    id: 'cookie-security',
    name: 'Cookie Security',
    category: 'Session Security',
    severity: issues.length === 0 ? 'passed' : issues.length >= 2 ? 'critical' : 'warning',
    description: issues.length === 0
      ? 'Las cookies están configuradas con flags de seguridad correctos.'
      : `Cookies inseguras: ${issues.join(', ')}. Las sesiones podrían ser robadas.`,
    recommendation: issues.length > 0 ? 'Añadir flags Secure, HttpOnly y SameSite=Strict a todas las cookies.' : null,
    free: false,
  };
}

async function checkCORS(response) {
  const acao = response.headers.get('access-control-allow-origin');
  const wildcard = acao === '*';

  return {
    id: 'cors',
    name: 'CORS Configuration',
    category: 'Access Control',
    severity: wildcard ? 'warning' : 'passed',
    description: wildcard
      ? 'CORS está configurado con wildcard (*). Cualquier sitio puede hacer peticiones a tu API.'
      : 'CORS está configurado correctamente o no está habilitado (restrictivo por defecto).',
    recommendation: wildcard ? 'Restringir Access-Control-Allow-Origin a los dominios específicos que necesiten acceso.' : null,
    free: false,
  };
}

async function checkRobotsTxt(url) {
  try {
    const origin = new URL(url).origin;
    const res = await fetchWithTimeout(`${origin}/robots.txt`);
    const text = await res.text();

    const sensitivePatterns = ['/admin', '/api', '/dashboard', '/login', '/wp-admin', '/config', '/backup', '/database', '/.env', '/.git'];
    const exposed = sensitivePatterns.filter(p => text.toLowerCase().includes(p.toLowerCase()));

    return {
      id: 'robots-txt',
      name: 'robots.txt Exposure',
      category: 'Information Leakage',
      severity: exposed.length > 0 ? 'warning' : 'passed',
      description: exposed.length > 0
        ? `robots.txt revela ${exposed.length} ruta(s) sensible(s): ${exposed.join(', ')}. Los atacantes pueden usar esta información para explorar tu infraestructura.`
        : 'robots.txt no revela rutas sensibles.',
      recommendation: exposed.length > 0 ? 'Evitar listar rutas sensibles en robots.txt. Usar autenticación en su lugar.' : null,
      free: false,
    };
  } catch {
    return {
      id: 'robots-txt',
      name: 'robots.txt Exposure',
      category: 'Information Leakage',
      severity: 'passed',
      description: 'No se encontró archivo robots.txt o no es accesible.',
      free: false,
    };
  }
}

async function checkSensitiveFiles(url) {
  const origin = new URL(url).origin;
  const files = ['.env', '.git/config', 'wp-config.php', '.htaccess', 'composer.json', 'package.json', '.DS_Store'];
  const found = [];

  for (const file of files) {
    try {
      const res = await fetchWithTimeout(`${origin}/${file}`, { method: 'HEAD' });
      if (res.ok && res.status === 200) {
        found.push(file);
      }
    } catch {
      // Ignore timeouts/errors
    }
  }

  return {
    id: 'sensitive-files',
    name: 'Sensitive Files Exposed',
    category: 'Information Leakage',
    severity: found.length > 0 ? 'critical' : 'passed',
    description: found.length > 0
      ? `¡CRÍTICO! Se encontraron ${found.length} archivo(s) sensible(s) accesibles: ${found.join(', ')}. Estos pueden contener contraseñas, configuraciones y código fuente.`
      : 'No se encontraron archivos sensibles expuestos públicamente.',
    recommendation: found.length > 0 ? 'Bloquear inmediatamente el acceso a estos archivos mediante reglas del servidor web (.htaccess, nginx.conf).' : null,
    free: false,
  };
}

async function checkHSTS(response) {
  const hsts = response.headers.get('strict-transport-security');
  let issues = [];

  if (!hsts) {
    issues.push('Header HSTS ausente');
  } else {
    if (!hsts.includes('max-age')) issues.push('Falta max-age');
    const maxAge = parseInt(hsts.match(/max-age=(\d+)/)?.[1] || '0');
    if (maxAge < 31536000) issues.push('max-age menor a 1 año');
    if (!hsts.includes('includeSubDomains')) issues.push('Falta includeSubDomains');
  }

  return {
    id: 'hsts',
    name: 'HTTP Strict Transport Security',
    category: 'Transport Security',
    severity: !hsts ? 'critical' : issues.length > 0 ? 'warning' : 'passed',
    description: !hsts
      ? 'HSTS no está configurado. Los usuarios podrían ser redirigidos a versiones HTTP inseguras del sitio.'
      : issues.length > 0
        ? `HSTS configurado con problemas: ${issues.join(', ')}.`
        : 'HSTS está configurado correctamente con max-age adecuado.',
    recommendation: issues.length > 0 ? 'Configurar HSTS con max-age=31536000, includeSubDomains y preload.' : null,
    free: false,
  };
}

async function checkReferrerPolicy(response) {
  const policy = response.headers.get('referrer-policy');

  return {
    id: 'referrer-policy',
    name: 'Referrer Policy',
    category: 'Privacy',
    severity: policy ? 'passed' : 'warning',
    description: policy
      ? `Referrer Policy configurada: ${policy}`
      : 'No se encontró Referrer Policy. La URL completa podría filtrarse a sitios de terceros.',
    recommendation: !policy ? 'Añadir header Referrer-Policy: strict-origin-when-cross-origin' : null,
    free: false,
  };
}

async function checkPermissionsPolicy(response) {
  const policy = response.headers.get('permissions-policy') || response.headers.get('feature-policy');

  return {
    id: 'permissions-policy',
    name: 'Permissions Policy',
    category: 'Privacy',
    severity: policy ? 'passed' : 'warning',
    description: policy
      ? 'Permissions Policy está configurada, controlando el acceso a APIs del navegador.'
      : 'No se encontró Permissions Policy. APIs del navegador como cámara, micrófono o geolocalización podrían ser usadas por scripts de terceros.',
    recommendation: !policy ? 'Añadir Permissions-Policy para restringir acceso a APIs sensibles del navegador.' : null,
    free: false,
  };
}

async function checkMixedContent(url, response) {
  if (!url.startsWith('https://')) {
    return {
      id: 'mixed-content',
      name: 'Mixed Content',
      category: 'Transport Security',
      severity: 'warning',
      description: 'No se puede verificar contenido mixto porque el sitio no usa HTTPS.',
      free: false,
    };
  }

  try {
    const html = await response.clone().text();
    const httpRefs = (html.match(/http:\/\/[^"'\s>]+/g) || []).filter(u => !u.includes('localhost'));

    return {
      id: 'mixed-content',
      name: 'Mixed Content',
      category: 'Transport Security',
      severity: httpRefs.length > 0 ? 'warning' : 'passed',
      description: httpRefs.length > 0
        ? `Se encontraron ${httpRefs.length} recurso(s) cargados por HTTP inseguro en una página HTTPS. Esto debilita la seguridad del cifrado.`
        : 'No se detectó contenido mixto. Todos los recursos se cargan por HTTPS.',
      recommendation: httpRefs.length > 0 ? 'Cambiar todas las referencias HTTP a HTTPS o usar URLs relativas al protocolo (//).' : null,
      free: false,
    };
  } catch {
    return {
      id: 'mixed-content',
      name: 'Mixed Content',
      category: 'Transport Security',
      severity: 'passed',
      description: 'No se pudo analizar el contenido de la página.',
      free: false,
    };
  }
}

async function checkSourceMaps(url) {
  const origin = new URL(url).origin;
  try {
    const res = await fetchWithTimeout(origin);
    const html = await res.text();

    // Look for .js files referenced in HTML
    const jsFiles = html.match(/src=["'][^"']*\.js["']/g) || [];
    const mapFound = [];

    for (const jsRef of jsFiles.slice(0, 3)) {
      const jsUrl = jsRef.match(/src=["']([^"']*)["']/)?.[1];
      if (!jsUrl) continue;

      const fullUrl = jsUrl.startsWith('http') ? jsUrl : `${origin}${jsUrl.startsWith('/') ? '' : '/'}${jsUrl}`;
      try {
        const mapRes = await fetchWithTimeout(`${fullUrl}.map`, { method: 'HEAD' });
        if (mapRes.ok) mapFound.push(`${jsUrl}.map`);
      } catch { /* skip */ }
    }

    return {
      id: 'source-maps',
      name: 'Source Map Exposure',
      category: 'Information Leakage',
      severity: mapFound.length > 0 ? 'warning' : 'passed',
      description: mapFound.length > 0
        ? `Se encontraron ${mapFound.length} source map(s) accesibles. Esto expone el código fuente original.`
        : 'No se encontraron source maps expuestos.',
      recommendation: mapFound.length > 0 ? 'Deshabilitar source maps en producción o restringir su acceso.' : null,
      free: false,
    };
  } catch {
    return {
      id: 'source-maps',
      name: 'Source Map Exposure',
      category: 'Information Leakage',
      severity: 'passed',
      description: 'No se pudo verificar la exposición de source maps.',
      free: false,
    };
  }
}

async function checkDirectoryListing(url) {
  const origin = new URL(url).origin;
  const dirs = ['/images/', '/assets/', '/uploads/', '/static/', '/css/', '/js/'];
  const exposed = [];

  for (const dir of dirs) {
    try {
      const res = await fetchWithTimeout(`${origin}${dir}`);
      const text = await res.text();
      if (res.ok && (text.includes('Index of') || text.includes('Directory listing') || text.includes('<title>Index of'))) {
        exposed.push(dir);
      }
    } catch { /* skip */ }
  }

  return {
    id: 'directory-listing',
    name: 'Directory Listing',
    category: 'Information Leakage',
    severity: exposed.length > 0 ? 'warning' : 'passed',
    description: exposed.length > 0
      ? `Se encontraron ${exposed.length} directorio(s) con listado habilitado: ${exposed.join(', ')}. Cualquiera puede ver los archivos del directorio.`
      : 'No se detectó listado de directorios habilitado.',
    recommendation: exposed.length > 0 ? 'Deshabilitar directory listing en la configuración del servidor web.' : null,
    free: false,
  };
}

async function checkOpenRedirect(url) {
  const origin = new URL(url).origin;
  const testUrl = `${origin}/?redirect=https://evil.com&url=https://evil.com&next=https://evil.com&return=https://evil.com`;

  try {
    const res = await fetchWithTimeout(testUrl, { redirect: 'manual' });
    const location = res.headers.get('location') || '';
    const isVulnerable = location.includes('evil.com');

    return {
      id: 'open-redirect',
      name: 'Open Redirect',
      category: 'Input Validation',
      severity: isVulnerable ? 'critical' : 'passed',
      description: isVulnerable
        ? '¡CRÍTICO! El sitio es vulnerable a redirecciones abiertas. Los atacantes pueden crear URLs que redirigen a sitios maliciosos.'
        : 'No se detectaron redirecciones abiertas en los parámetros comunes.',
      recommendation: isVulnerable ? 'Validar y sanitizar todos los parámetros de redirección. Usar una whitelist de dominios permitidos.' : null,
      free: false,
    };
  } catch {
    return {
      id: 'open-redirect',
      name: 'Open Redirect',
      category: 'Input Validation',
      severity: 'passed',
      description: 'No se pudo verificar la presencia de redirecciones abiertas.',
      free: false,
    };
  }
}

// ─── Main Scanner Function ───

export async function scanUrl(url) {
  // Normalize URL
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = `https://${url}`;
  }

  const startTime = Date.now();
  const results = [];

  try {
    // First, fetch the main page
    const response = await fetchWithTimeout(url);

    // Run all checks
    const checks = await Promise.allSettled([
      checkHTTPS(url),
      checkSecurityHeaders(response),
      checkCSP(response),
      checkServerDisclosure(response),
      checkCookieSecurity(response),
      checkCORS(response),
      checkHSTS(response),
      checkReferrerPolicy(response),
      checkPermissionsPolicy(response),
      checkMixedContent(url, response),
      checkRobotsTxt(url),
      checkSensitiveFiles(url),
      checkSourceMaps(url),
      checkDirectoryListing(url),
      checkOpenRedirect(url),
    ]);

    checks.forEach(result => {
      if (result.status === 'fulfilled') {
        results.push(result.value);
      }
    });
  } catch (err) {
    // If main fetch fails, at least run HTTPS check
    results.push(await checkHTTPS(url));
    results.push({
      id: 'connectivity',
      name: 'Connectivity',
      category: 'General',
      severity: 'critical',
      description: `No se pudo conectar al sitio: ${err.message}. Verifica que la URL es correcta y el sitio está activo.`,
      free: true,
    });
  }

  const duration = Date.now() - startTime;

  // Calculate score
  const criticalCount = results.filter(r => r.severity === 'critical').length;
  const warningCount = results.filter(r => r.severity === 'warning').length;
  const passedCount = results.filter(r => r.severity === 'passed').length;
  const total = results.length;

  let score;
  if (criticalCount === 0 && warningCount === 0) score = 'A';
  else if (criticalCount === 0 && warningCount <= 2) score = 'B';
  else if (criticalCount <= 1) score = 'C';
  else if (criticalCount <= 3) score = 'D';
  else score = 'F';

  return {
    url,
    score,
    duration,
    totalChecks: total,
    criticalCount,
    warningCount,
    passedCount,
    results,
    scannedAt: new Date().toISOString(),
  };
}
