/**
 * SERVICE WORKER (MV3)
 * --------------------
 * Orquesta el flujo: recibe capturas desde url_capture.js,
 * normaliza/deduplica, persiste en chrome.storage.local,
 * actualiza el badge y notifica al popup.
 */

console.log("SW loaded");

// Importar módulos
import { initCapture } from "./url_capture.js";
import { analyzeUrl } from "./analyzer.js";
import { initApiKeys, getCaptures, saveCaptures, findExistingAnalysis } from "./utils/storage_utils.js";

const MAX_ITEMS = 100;
let lastUrl = null;

// ===== Llaves API =====
const API_KEYS = {
  virustotal: "5ee5c754a74d080e76ec0da50b0e7ff1af3cfde7ce9f9e81661dca1caa31c663",
  safebrowsing: "AIzaSyBde4KzBgQjmig7cO-vuhtGJjtxQB4BxQU",
  whois: "at_hQ6ft7WIXvr7Xhh8h3KXjPTHZWF7a",
  whoisfreaks: "5548cb282ae44a8590f13ad0c87fa287"
};

// ===== Initialize API keys =====
chrome.runtime.onInstalled.addListener(() => initApiKeys(API_KEYS));

// ===== URL Normalization =====
function normalizeUrl(u) {
  try {
    const url = new URL(u);
    return url.origin;
  } catch {
    return null;
  }
}

// ===== Save and analyze URL =====
async function save(entry) {
  // console.log("La URL a analizar es:", entry.url);
  // console.log("La URL completa es:", entry.fullUrl);

  const existing = await findExistingAnalysis(entry.url);
  let enrichedEntry;

  if (existing && existing.analysis) {
    // console.log(`[Service Worker] Reusing previous analysis for: ${entry.url}`);
    enrichedEntry = { ...entry, analysis: existing.analysis, reused: true };
  } else {
    // console.log(`[Service Worker] Analyzing new URL: ${entry.url}`);
    const analysis = await analyzeUrl(entry.url);
    enrichedEntry = { ...entry, analysis, reused: false };
  }

  const captures = await getCaptures();
  const arr = [enrichedEntry, ...captures.filter(it => it.url !== entry.url)];
  const out = arr.slice(0, MAX_ITEMS);

  await saveCaptures(out);

  chrome.action.setBadgeBackgroundColor({ color: "#444" });
  chrome.action.setBadgeText({ text: String(Math.min(out.length, 99)) });

  chrome.runtime.sendMessage({ type: "NEW_CAPTURE", payload: enrichedEntry }).catch(() => {});
}

// ===== Events capture =====
const { captureActiveNow } = initCapture(async ({ url, fullUrl, tabId, title }) => {
  const norm = normalizeUrl(url);
  if (!norm || norm === lastUrl) return;

  lastUrl = norm;
  await save({ url: norm, fullUrl, title, ts: Date.now() });
});

chrome.runtime.onInstalled.addListener(captureActiveNow);
chrome.runtime.onStartup.addListener(captureActiveNow);
