/**
 * SERVICE WORKER (MV3)
 * --------------------
 * Orquesta el flujo: recibe capturas desde url_capture.js,
 * normaliza/deduplica, persiste en chrome.storage.local,
 * actualiza el badge y notifica al popup.
 *
 * OJO: Los listeners deben registrarse en tiempo de carga del SW,
 * para que Chrome pueda "despertarlo" con eventos.
 */


// Import URL capture module
import { initCapture } from "./url_capture.js";
// Import Analyzer module
import { analyzeUrl } from "./analyzer.js";

const STORAGE_KEY = "captures";
const MAX_ITEMS = 100;
let lastUrl = null;

// Normaliza una URL para evitar diferencias por #hash, etc. 
function normalizeUrl(u) {
  try { 
    const url = new URL(u); 
    url.hash = ""; 
    return url.toString(); }
  
    catch { 
        return null; 
    }
}

//Guarda la captura 
async function save(entry) {
  const analysis = await analyzeUrl(entry.url);
  const enrichedEntry = { ...entry, analysis }; // Add analysis results to the object

  const { [STORAGE_KEY]: list = [] } = await chrome.storage.local.get(STORAGE_KEY);
  const arr = [enrichedEntry, ...list];
 
  const out = [];
  for (const it of arr) {
    if (!out.length || out[out.length - 1].url !== it.url) out.push(it);
    if (out.length >= MAX_ITEMS) break;
  }
  await chrome.storage.local.set({ [STORAGE_KEY]: out });
  // Badge con el conteo
  chrome.action.setBadgeBackgroundColor({ color: "#444" });
  chrome.action.setBadgeText({ text: String(Math.min(out.length, 99)) });
  // Avisar al popup (si está abierto)
  chrome.runtime.sendMessage({ type: "NEW_CAPTURE", payload: entry }).catch(() => {});
}

// Registra la captura; esto corre al cargar el SW
const { captureActiveNow } = initCapture(async ({ url, tabId, title }) => {
  const norm = normalizeUrl(url);
  if (!norm || norm === lastUrl) return;
  lastUrl = norm;

  await save({ url: norm, title, ts: Date.now() }); // Here we sent the url to be analyzed and saved
});

// Captura la pestaña activa al instalar/arrancar
chrome.runtime.onInstalled.addListener(captureActiveNow);
chrome.runtime.onStartup.addListener(captureActiveNow);
