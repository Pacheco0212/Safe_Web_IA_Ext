// ==================================================================
// Módulo: Análisis estructural de URL 


import { COMMON_BRANDS } from "../utils/constants.js";
import {
  safeParseUrl, isIpv4, isIpv6, hasPunycode,
  normalizedDistance, keyboardVariantSimilarity,
  tokenAnomalies, tokensInPathOrQuery,
  queryParamAnalysis, encodedAnalysis, isShortenerHost,
  isSuspiciousTld, extractBaseDomain, countDomains
} from "../utils/helpers.js";

function analyzeStructuralUrl(url, debug = false) {
  if (debug) console.log(`[Structural] Analizando estructura para ${url}...`);

  // ================================
  // Normalizar URL
  // ================================
  let urlToAnalyze = url;
  if (!urlToAnalyze.startsWith("http://") && !urlToAnalyze.startsWith("https://")) {
    urlToAnalyze = "https://" + urlToAnalyze;
  }

  const report = {
    "domainCount": null,
    "similarBrand": null,
    "similarityScore": null,
    "tldSuspicious": false,
    "isIP": false,
    "hasPunycode": false,
    "subdomainCount": 0,
    "anomalies": {},
    "hasLoginTokens": false,
    "hasAtSymbol": false,
    "length": urlToAnalyze.length,
    "paramCount": 0,
    "suspiciousParams": [],
    "hasEncodedChars": false,
    "encodedCount": 0,
    "isShortener": false,
    "customPort": false,
    "usesHttps": false
  };

  // === Parse URL ===
  const urlObj = safeParseUrl(urlToAnalyze);
  if (!urlObj) {
    report["success"] = false;
    return report;
  }

  const host = urlObj.hostname.toLowerCase();
  const baseDomain = extractBaseDomain(host);

  // === Count domain parts ===
  report["domainCount"] = countDomains(host);

  // === Typosquatting detection ===
  let bestBrand = null;
  let bestScore = 1.0;

  for (const brand of COMMON_BRANDS) {
    const s1 = normalizedDistance(baseDomain, brand);
    const s2 = keyboardVariantSimilarity(baseDomain, brand);
    const score = Math.min(s1, s2);
    
    if (score < bestScore) {
      bestBrand = brand;
      bestScore = score;
    }
  }

  // Lógica de scoring (0-1 donde 1 es idéntico)
  // Python: 1 - best_score
  const similarity = 1 - bestScore;
  
  if (similarity > 0.35) {
    report["similarBrand"] = bestBrand;
    report["similarityScore"] = parseFloat(similarity.toFixed(4));
  } else {
    report["similarBrand"] = bestBrand;
    report["similarityScore"] = parseFloat(similarity.toFixed(4));
  }

  // === TLD suspicious ===
  const tld = isSuspiciousTld(host);
  report["tldSuspicious"] = Boolean(tld);

  // === IP detection ===
  report["isIP"] = isIpv4(host) || isIpv6(host);

  // === Punycode ===
  report["hasPunycode"] = hasPunycode(host);

  // === Subdomains + anomalies ===
  const labels = host.split(".");
  report["subdomainCount"] = Math.max(0, labels.length - 2);

  const an = tokenAnomalies(host);
  report["anomalies"] = an;

  // === Tokens in path/query ===
  const tokens = tokensInPathOrQuery(urlObj);
  report["hasLoginTokens"] = tokens["pathFlag"] || tokens["queryFlag"];

  // === '@' symbol ===
  report["hasAtSymbol"] = urlToAnalyze.includes("@");

  // === Query params ===
  const qp = queryParamAnalysis(urlObj);
  report["paramCount"] = qp["paramsCount"];
  report["suspiciousParams"] = qp["suspiciousKeys"];

  // === Encoded chars ===
  const enc = encodedAnalysis(urlToAnalyze);
  report["encodedCount"] = enc["pctCount"];
  report["hasEncodedChars"] = enc["hasMany"];

  // === Shortener ===
  report["isShortener"] = isShortenerHost(host);

  // === Custom port ===
  const port = urlObj.port; 
  // En JS URL API, si el puerto es estándar (80 http o 443 https), port es string vacío ""
  const isStandardPort = port === "" || port === "80" || port === "443";
  report["customPort"] = !isStandardPort;

  // === HTTPS ===
  report["usesHttps"] = urlObj.protocol === "https:";

  if (debug) {
    console.log("\n=== Structural URL Analysis ===");
    for (const [k, v] of Object.entries(report)) {
      console.log(`${k}: ${JSON.stringify(v)}`);
    }
    console.log("=================================\n");
  }

  return report;
}

export { analyzeStructuralUrl };
