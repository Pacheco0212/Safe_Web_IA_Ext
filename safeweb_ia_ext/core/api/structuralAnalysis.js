// ==================================================================
// Module: Structural URL Analysis (raw, no weights or ranking)
// ====================================================================
// Returns a normalized object with:
// - details by criterion (value, score, explanation)
// - detected reasons
// - analysis metadata
// Optional: debug = true prints console.log of the report.
// ===============================================================

import { COMMON_BRANDS } from "../utils/constants.js";
import {
  safeParseUrl, isIPv4, isIPv6, hasPunycode, normalizedDistance,
  keyboardVariantSimilarity, tokenAnomalies, tokensInPathOrQuery,
  queryParamAnalysis, encodedAnalysis, isShortenerHost,
  isSuspiciousTld, extractBaseDomain, scoreBool, scoreRatio
} from "../utils/helpers.js";


async function analyzeStructuralUrl(urlString, options = {}) {
  const debug = !!options.debug;
  const report = {
    url: urlString,
    parsed: null,
    criteria: {},
    reasons: [],
    evaluatedAt: Date.now()
  };

  const urlObj = safeParseUrl(urlString);
  if (!urlObj) {
    report.reasons.push("URL inválida o no parseable.");
    report.criteria.invalid = { value: true, score: 1, explanation: "No se pudo parsear la URL." };
    if (debug) console.log("[StructuralRaw] Report:", report);
    return report;
  }
  report.parsed = {
    protocol: urlObj.protocol,
    host: urlObj.hostname,
    port: urlObj.port || null,
    pathname: urlObj.pathname,
    search: urlObj.search,
    origin: urlObj.origin
  };

  const host = urlObj.hostname.toLowerCase();

  // --- Typosquatting detection ---
  const baseDomain = extractBaseDomain(host);
  let bestBrand = null;
  let bestRatio = 1;
  for (const brand of COMMON_BRANDS) {
    const ratio = normalizedDistance(baseDomain, brand);
    if (ratio < bestRatio) { bestRatio = ratio; bestBrand = brand; }
    const kb = keyboardVariantSimilarity(baseDomain, brand);
    if (kb < bestRatio) { bestRatio = kb; bestBrand = brand; }
  }
  const typosSeverity = Math.max(0, 1 - bestRatio);
  const typosDetected = (typosSeverity > 0.35);
  report.criteria.typosquatting = {
    value: typosDetected,
    score: scoreRatio(typosSeverity),
    explanation: typosDetected 
      ? `Base domain "${baseDomain}" similar to well-known brand "${bestBrand}" (distance ${bestRatio.toFixed(2)}).` 
      : `No significant similarity detected (best match ${bestBrand}, ratio ${bestRatio.toFixed(2)}).`
  };
  if (typosDetected) report.reasons.push(report.criteria.typosquatting.explanation);

  // --- TLD reputation ---
  const suspiciousTld = isSuspiciousTld(host);
  report.criteria.tld_reputation = {
    value: suspiciousTld || null,
    score: scoreBool(suspiciousTld),
    explanation: suspiciousTld ? `TLD "${suspiciousTld}" listed as suspicious.` : "TLD not listed."
  };
  if (suspiciousTld) report.reasons.push(report.criteria.tld_reputation.explanation);

  // --- IP in host ---
  const ipHost = isIPv4(host) || isIPv6(host);
  report.criteria.ip_in_host = {
    value: ipHost,
    score: scoreBool(ipHost),
    explanation: ipHost ? "Host is a literal IP" : "Host is not an IP."
  };
  if (ipHost) report.reasons.push(report.criteria.ip_in_host.explanation);

  // --- Punycode ---
  const puny = hasPunycode(host);
  report.criteria.punycode = {
    value: puny,
    score: scoreBool(puny),
    explanation: puny ? "Contains puyncode (xn--)" : "Does not contain punycode."
  };
  if (puny) report.reasons.push(report.criteria.punycode.explanation);

  // --- Subdomain structure ---
  const parts = host.split(".");
  const subdomainCount = Math.max(0, parts.length - 2);
  const anomalies = tokenAnomalies(host);
  report.criteria.subdomain_structure = {
    value: { subdomainCount, anomalies },
    score: subdomainCount >= 3 || anomalies.longLabel || anomalies.manyHyphens || anomalies.repeatedChars ? 1 : subdomainCount >= 1 ? 0.3 : 0,
    explanation: `Subdomains: ${subdomainCount}, anomalías: ${JSON.stringify(anomalies)}`
  };

  // --- Path tokens ---
  const tokens = tokensInPathOrQuery(urlObj);
  report.criteria.path_login_tokens = {
    value: { pathFlag: tokens.pathFlag, queryFlag: tokens.queryFlag },
    score: scoreBool(tokens.pathFlag || tokens.queryFlag),
    explanation: (tokens.pathFlag || tokens.queryFlag) ? "Path/query with login/secure tokens." : "No suspicious tokens in path/query."
  };

  // --- @ symbol ---
  const hasAt = urlString.includes("@");
  report.criteria.at_symbol = {
    value: hasAt,
    score: scoreBool(hasAt),
    explanation: hasAt ? "The URL contains '@'." : "Does not contain '@'."
  };

  // --- URL length ---
  const urlLen = urlString.length;
  report.criteria.url_length = {
    value: urlLen,
    score: urlLen >= 200 ? 1 : urlLen >= 120 ? 0.6 : urlLen >= 80 ? 0.3 : 0,
    explanation: `URL Length = ${urlLen} characters.`
  };

  // --- Query params ---
  const qp = queryParamAnalysis(urlObj);
  report.criteria.query_params = {
    value: qp,
    score: qp.paramsCount >= 10 ? 1 : qp.paramsCount >= 4 ? 0.5 : 0,
    explanation: qp.suspiciousKeys.length ? `Suspicious parameters: ${qp.suspiciousKeys.join(", ")}` : `Amount: ${qp.paramsCount}`
  };

  // --- Encoded chars ---
  const enc = encodedAnalysis(urlString);
  report.criteria.encoded_chars = {
    value: enc,
    score: enc.hasMany ? 1 : enc.pctCount >= 2 ? 0.6 : 0,
    explanation: enc.hasMany ? `Multiple encoded sequences (${enc.pctCount}).` : "Normal encoding."
  };

  // --- Shortener ---
  const shortener = isShortenerHost(host);
  report.criteria.shortener = {
    value: shortener,
    score: scoreBool(shortener),
    explanation: shortener ? `Host is shortener (${host}).` : "No known shortener."
  };

  // --- Port ---
  const port = urlObj.port;
  const portSuspicious = port && port !== "80" && port !== "443";
  report.criteria.port = {
    value: port || null,
    score: scoreBool(portSuspicious),
    explanation: portSuspicious ? `Non-standard port: ${port}.` : "Standard or missing port."
  };

  // --- HTTPS ---
  const usesHttps = urlObj.protocol === "https:";
  report.criteria.https = {
    value: usesHttps,
    score: usesHttps ? 0 : 1,
    explanation: usesHttps ? "Use HTTPS." : "Does not use HTTPS."
  };

  if (debug) console.log("[StructuralRaw] Report:", report);
  return report;
}

export { analyzeStructuralUrl };
