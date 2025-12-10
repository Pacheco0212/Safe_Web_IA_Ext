// =========================================================
// Script de funciones para el analisis de URL
// =========================================================

import { SUSPICIOUS_TLDS, URL_SHORTENERS, LOGIN_KEYWORDS, REDIRECT_KEYWORDS } from "./constants.js";

export function safeParseUrl(raw) {
  try {
    return new URL(raw);
  } catch (e) {
    try {
      return new URL("http://" + raw);
    } catch (e2) {
      return null;
    }
  }
}

export function isIpv4(host) {
  // Regex simple equivalente al de Python
  const regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  return regex.test(host || "");
}

export function isIpv6(host) {
  if (!host) return false;
  return host.includes(":");
}

export function hasPunycode(hostname) {
  if (!hostname) return false;
  const labels = hostname.split(".");
  return labels.some(label => label.startsWith("xn--"));
}

// ========= Levenshtein distance ==========
export function levenshtein(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix = [];

  // Inicializar primera columna y primera fila
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          Math.min(
            matrix[i][j - 1] + 1, // insertion
            matrix[i - 1][j] + 1  // deletion
          )
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

export function normalizedDistance(a, b) {
  if (!a || !b) return 1.0;
  const d = levenshtein(a, b);
  return d / Math.max(a.length, b.length, 1);
}

export function keyboardVariantSimilarity(a, b) {
  const clean = (s) => s.toLowerCase().replace(/[^a-z0-9]/g, "");
  let na = clean(a);
  let nb = clean(b);

  if (na === nb) return 0.0;

  // Reemplazar 0 -> o, 1 -> l
  na = na.replace(/0/g, "o").replace(/1/g, "l");
  nb = nb.replace(/0/g, "o").replace(/1/g, "l");

  return normalizedDistance(na, nb);
}

export function tokenAnomalies(hostname) {
  const labels = hostname.split(".");
  const longLabel = labels.some(l => l.length > 25);
  // (l.split("-").length - 1) es equivalente a l.count("-")
  const manyHyphens = labels.some(l => (l.split("-").length - 1) >= 4);
  // Regex para caracteres repetidos 3 o más veces: /(.)\1{3,}/
  const repeatedChars = labels.some(l => /(.)\1{3,}/.test(l));

  return {
    longLabel,
    manyHyphens,
    repeatedChars
  };
}

export function tokensInPathOrQuery(urlObj) {
  const path = urlObj.pathname.toLowerCase();
  const query = urlObj.search.toLowerCase(); // search incluye el '?' y params

  const pathFlag = LOGIN_KEYWORDS.some(k => path.includes(k));
  const queryFlag = LOGIN_KEYWORDS.some(k => query.includes(k));

  return {
    pathFlag,
    queryFlag
  };
}

export function queryParamAnalysis(urlObj) {
  // urlObj.searchParams es un iterable tipo Map
  const keys = Array.from(urlObj.searchParams.keys());
  const found = keys.filter(k => REDIRECT_KEYWORDS.has(k.toLowerCase()));

  return {
    paramsCount: keys.length,
    suspiciousKeys: found
  };
}

export function encodedAnalysis(rawUrl) {
  // Buscar % seguido de 2 hex
  const matches = rawUrl.match(/%[0-9a-fA-F]{2}/g);
  const pct = matches ? matches.length : 0;
  const ratio = pct / Math.max(rawUrl.length, 1);

  return {
    pctCount: pct,
    pctRatio: ratio,
    hasMany: pct >= 4 || ratio > 0.02
  };
}

export function isShortenerHost(host) {
  host = host.toLowerCase();
  if (URL_SHORTENERS.has(host)) return true;
  // Check if it ends with .shortener (e.g. foo.bit.ly)
  for (const s of URL_SHORTENERS) {
    if (host.endsWith("." + s)) return true;
  }
  return false;
}

export function isSuspiciousTld(host) {
  const pieces = host.split(".");
  const tld = pieces.length > 1 ? pieces[pieces.length - 1] : "";
  return SUSPICIOUS_TLDS.has(tld) ? tld : null;
}

export function extractBaseDomain(host) {
  const parts = host.split(".");
  if (parts.length >= 2) {
    return parts[parts.length - 2];
  }
  return host;
}

export function countDomains(hostname) {
  if (!hostname) return 0;
  return hostname.split(".").length;
}