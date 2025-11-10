// ==================================================================
// Módulo: Análisis estructural de URL 


import { COMMON_BRANDS } from "../utils/constants.js";
import {
  safeParseUrl, isIPv4, isIPv6, hasPunycode, normalizedDistance,
  keyboardVariantSimilarity, tokenAnomalies, tokensInPathOrQuery,
  queryParamAnalysis, encodedAnalysis, isShortenerHost,
  isSuspiciousTld, extractBaseDomain
} from "../utils/helpers.js";

async function analyzeStructuralUrl(urlString, options = {}) {
  const debug = !!options.debug;
  const report = {
    url: urlString,
    analisis: [],
    fecha: new Date().toLocaleString()
  };

  // --- Intentar parsear URL ---
  const urlObj = safeParseUrl(urlString);
  if (!urlObj) {
    report.analisis.push("La URL es inválida o no se pudo analizar correctamente.");
    if (debug) console.log(report);
    return report;
  }

  const host = urlObj.hostname.toLowerCase();

  // === [1] Detección de Typosquatting ===
  const baseDomain = extractBaseDomain(host);
  let mejorMarca = null;
  let mejorDistancia = 1;

  for (const brand of COMMON_BRANDS) {
    const ratio1 = normalizedDistance(baseDomain, brand);
    const ratio2 = keyboardVariantSimilarity(baseDomain, brand);
    const minRatio = Math.min(ratio1, ratio2);
    if (minRatio < mejorDistancia) {
      mejorDistancia = minRatio;
      mejorMarca = brand;
    }
  }

  if (1 - mejorDistancia > 0.35) {
    report.analisis.push(`El dominio "${baseDomain}" es muy parecido a la marca "${mejorMarca}", podría intentar suplantarla.`);
  } else {
    report.analisis.push(`El dominio "${baseDomain}" no muestra similitud con marcas conocidas.`);
  }

  // === [2] Reputación del TLD ===
  const tldSospechoso = isSuspiciousTld(host);
  if (tldSospechoso) {
    report.analisis.push(`El dominio utiliza un TLD sospechoso: .${tldSospechoso}.`);
  } else {
    report.analisis.push("El TLD del dominio no se encuentra en listas sospechosas.");
  }

  // === [3] IP literal ===
  const esIP = isIPv4(host) || isIPv6(host);
  report.analisis.push(esIP ? "El dominio es una dirección IP (posible intento de ocultar identidad)." : "El dominio no es una dirección IP.");

  // === [4] Punycode ===
  const contienePuny = hasPunycode(host);
  report.analisis.push(contienePuny ? "El dominio contiene Punycode (xn--), posible intento de imitar caracteres." : "El dominio no contiene Punycode.");

  // === [5] Subdominios y anomalías ===
  const partes = host.split(".");
  const cantidadSubdominios = Math.max(0, partes.length - 2);
  const anomalías = tokenAnomalies(host);

  if (cantidadSubdominios >= 3 || anomalías.longLabel || anomalías.manyHyphens || anomalías.repeatedChars) {
    report.analisis.push(`El dominio tiene ${cantidadSubdominios} subdominios o presenta anomalías (${JSON.stringify(anomalías)}).`);
  } else {
    report.analisis.push(`El dominio tiene ${cantidadSubdominios} subdominios y no muestra anomalías.`);
  }

  // === [6] Tokens en el path o query ===
  const tokens = tokensInPathOrQuery(urlObj);
  if (tokens.pathFlag || tokens.queryFlag) {
    report.analisis.push("La URL contiene palabras como 'login', 'secure' o 'verify' en su ruta o parámetros.");
  } else {
    report.analisis.push("La URL no contiene tokens de inicio de sesión o seguridad.");
  }

  // === [7] Símbolo '@' ===
  const tieneArroba = urlString.includes("@");
  report.analisis.push(tieneArroba ? "La URL contiene el símbolo '@', lo cual puede ser engañoso." : "La URL no contiene el símbolo '@'.");

  // === [8] Longitud de la URL ===
  const longitud = urlString.length;
  if (longitud > 200) {
    report.analisis.push(`La URL es muy larga (${longitud} caracteres).`);
  } else if (longitud > 120) {
    report.analisis.push(`La URL tiene una longitud media (${longitud} caracteres).`);
  } else {
    report.analisis.push(`La URL es corta (${longitud} caracteres).`);
  }

  // === [9] Parámetros en la query ===
  const qp = queryParamAnalysis(urlObj);
  if (qp.paramsCount > 0) {
    report.analisis.push(`La URL contiene ${qp.paramsCount} parámetros${qp.suspiciousKeys.length ? ` (sospechosos: ${qp.suspiciousKeys.join(", ")})` : ""}.`);
  } else {
    report.analisis.push("La URL no contiene parámetros en la query.");
  }

  // === [10] Caracteres codificados ===
  const enc = encodedAnalysis(urlString);
  if (enc.hasMany) {
    report.analisis.push(`La URL contiene muchas secuencias codificadas (${enc.pctCount} apariciones de '%').`);
  } else if (enc.pctCount > 0) {
    report.analisis.push(`La URL contiene algunas codificaciones (%xx).`);
  } else {
    report.analisis.push("La URL no contiene caracteres codificados.");
  }

  // === [11] Acortadores ===
  const esShort = isShortenerHost(host);
  report.analisis.push(esShort ? `El dominio pertenece a un servicio de acortamiento (${host}).` : "El dominio no es un servicio de acortamiento.");

  // === [12] Puerto ===
  const puerto = urlObj.port;
  if (puerto && puerto !== "80" && puerto !== "443") {
    report.analisis.push(`La URL utiliza un puerto no estándar (${puerto}).`);
  } else {
    report.analisis.push("La URL usa un puerto estándar (80 o 443).");
  }

  // === [13] HTTPS ===
  const usaHttps = urlObj.protocol === "https:";
  report.analisis.push(usaHttps ? "La URL usa el protocolo HTTPS." : "La URL no usa HTTPS.");

  // --- Mostrar en consola si debug está activo ---
  if (debug) {
    console.log("=== Análisis estructural de URL ===");
    console.log("URL:", report.url);
    report.analisis.forEach((txt, i) => console.log(`${i + 1}. ${txt}`));
    console.log("===================================");
  }

  return report;
}

export { analyzeStructuralUrl };
