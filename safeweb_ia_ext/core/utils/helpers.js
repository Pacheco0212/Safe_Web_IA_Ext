// =========================================================
// Script de funciones para el analisis de URL
// =========================================================

import { SUSPICIOUS_TLDS, URL_SHORTENERS, LOGIN_KEYWORDS } from "./constants.js";

// Funcion de validacion de URL 
export function safeParseUrl(raw) {
  try {
    return new URL(raw);
  } catch {
     try { 
       return new URL("http://" + raw); 
    } catch { 
      return null; 
    }
  }
}

//Funciones que verifican si el host es una dirección IP en vez de una URL
export function isIPv4(host) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}

export function isIPv6(host) {
  return host.includes(":") && host.startsWith("[") ? true : /:/.test(host) && host.split(":").length >= 3;
}


//Funcion para detecar si la URL cuenta con un nombre de dominio con caracteres especiales (fuera de codificacion ASCII) 
//la codificacion Punycode siempre comienza con xn--
export function hasPunycode(hostname) {
  return hostname.split(".").some(label => label.startsWith("xn--"));
}

//Funcion para contabilizar cuántas operaciones de edición hacen falta para transformar a en b
export function levenshtein(a, b) {
  const la = a.length, lb = b.length;
  if (la === 0) return lb;
  if (lb === 0) return la;
  const dp = Array.from({length: la + 1}, () => new Array(lb + 1).fill(0));
  for (let i = 0; i <= la; i++) dp[i][0] = i;
  for (let j = 0; j <= lb; j++) dp[0][j] = j;
  for (let i = 1; i <= la; i++) {
    for (let j = 1; j <= lb; j++) {
      const cost = a[i-1] === b[j-1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i-1][j] + 1,
        dp[i][j-1] + 1,
        dp[i-1][j-1] + cost
      );
    }
  }
  return dp[la][lb];
}

// Normalizamos dividiendo entre la longitud de la palabra. Resultado entre 0 (idéntico) y 1 (totalmente distinto).
export function normalizedDistance(a,b){ 
  const d = levenshtein(a,b);
  return d / Math.max(1, Math.max(a.length, b.length));
}

// Funciona similar a la distancia de levenshtein pero solo sustituimos 0 por O y 1 por l (faceb00k = facebook). 
export function keyboardVariantSimilarity(a, b) {
  const normalize = s => s.toLowerCase().replace(/[^a-z0-9]/g, "");
  const na = normalize(a), nb = normalize(b);
  if (na === nb) return 0;
  let subA = na.replace(/0/g, "o").replace(/1/g, "l");
  let subB = nb.replace(/0/g, "o").replace(/1/g, "l");
  return normalizedDistance(subA, subB);
}

//Funcion para alguna anomalia de dominio como:
//  Algún fragmento (subdominio) tiene >25 caracteres
// Contiene 4 o más guiones
// Tiene letras repetidas más de 3 veces seguidas
export function tokenAnomalies(hostname) {
  const labels = hostname.split(".");
  let longLabel = labels.find(l => l.length > 25);
  let manyHyphens = labels.some(l => (l.match(/-/g) || []).length >= 4);
  let repeatedChars = labels.some(l => /(.)\1{3,}/.test(l));
  return { longLabel: !!longLabel, manyHyphens, repeatedChars };
}

//Revisa el path y los parámetros en busca de palabras clave 'LOGIN_KEYWORDS'.
export function tokensInPathOrQuery(urlObj) {
  const path = urlObj.pathname.toLowerCase();
  const q = Array.from(urlObj.searchParams.keys()).join(" ").toLowerCase();
  const pathFlag = LOGIN_KEYWORDS.some(k => path.includes(k));
  const queryFlag = LOGIN_KEYWORDS.some(k => q.includes(k));
  return { pathFlag, queryFlag, pathSample: path.slice(0,200), querySample: q.slice(0,200) };
}


//parametros redirecciones
export function queryParamAnalysis(urlObj) {
  const size = Array.from(urlObj.searchParams.keys()).length;
  const suspiciousKeys = ["redirect","url","next","dest","continue","to","u","view","out"];
  let suspiciousFound = [];
  for (const k of urlObj.searchParams.keys()) {
    if (suspiciousKeys.includes(k.toLowerCase())) suspiciousFound.push(k);
  }
  return { paramsCount: size, suspiciousKeys: suspiciousFound };
}

// caracteres codificados
export function encodedAnalysis(rawUrl) {
  const pct = (rawUrl.match(/%[0-9a-fA-F]{2}/g) || []).length;
  const pctRatio = pct / Math.max(1, rawUrl.length);
  return { pctCount: pct, pctRatio, hasMany: pct >= 4 || pctRatio > 0.02 };
}

//Funcion que comprueba si el dominio coincide o termina con alguno de los acortadores de URL_SHORTENERS.
export function isShortenerHost(host) {
  return URL_SHORTENERS.some(s => host === s || host.endsWith("." + s));
}

//Funcion para detecar si TDL es sospechoso
export function isSuspiciousTld(host) {
  const parts = host.toLowerCase().split(".");
  const tld = parts[parts.length - 1];
  return SUSPICIOUS_TLDS.includes(tld) ? tld : null;
}

export function extractBaseDomain(host) {
  const p = host.split(".");
  if (p.length <= 2) return p[0];
  return p[p.length - 2];
}

//Fucinoes para scores entre 0 y 1
export function scoreBool(flag) { return flag ? 1 : 0; }
export function scoreRatio(r) { return Math.min(1, Math.max(0, r)); }