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


console.log('SW loaded')
// Import URL capture module
import { initCapture } from "./url_capture.js";
// Import Analyzer module
import { analyzeUrl } from "./analyzer.js";
console.log('Cargue los modulos')

const STORAGE_KEY = "captures";
const MAX_ITEMS = 100;
let lastUrl = null;

const API_KEYS = {
  virustotal: "5ee5c754a74d080e76ec0da50b0e7ff1af3cfde7ce9f9e81661dca1caa31c663",
  safebrowsing: "AIzaSyBde4KzBgQjmig7cO-vuhtGJjtxQB4BxQU",
  whois: "at_hQ6ft7WIXvr7Xhh8h3KXjPTHZWF7a",
  whoisfreaks: "5548cb282ae44a8590f13ad0c87fa287"
};

// ========= Saving API keys in local storage =========
chrome.runtime.onInstalled.addListener(async () => {
  await chrome.storage.local.set({ api_keys: API_KEYS });
  // console.log("API Keys almacenadas en chrome.storage.local");
});

// Auxiliar function to get all API keys
export async function getApiKeys() {
  const { api_keys } = await chrome.storage.local.get("api_keys");
  return api_keys || {};
}

// ========= URLs normalization =========
// Funcion para normalizar una URL para evitar diferencias por #hash, etc. 
function normalizeUrl(u) {
  try { 

    const url = new URL(u); 
    return url.origin; 

  }catch { 
    return null; 
    }
}

// ========= Save and analyze each capture =========

//Funcion para guardar la url en el STORAGE 
async function save(entry) {

  console.log('La URL a analizar es:', entry.url)
  console.log('La URL completa es:', entry.fullUrl)

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

  // Badge update
  chrome.action.setBadgeBackgroundColor({ color: "#444" });
  chrome.action.setBadgeText({ text: String(Math.min(out.length, 99)) });

  // Notify popup if open
  chrome.runtime.sendMessage({ type: "NEW_CAPTURE", payload: entry }).catch(() => {});
}

// ========= Log the capture ========= 
const { captureActiveNow } = initCapture(async ({ url, tabId, title }) => {



// Registra la captura; esto corre al cargar el SW
const { captureActiveNow } = initCapture(async ({ url, fullUrl, tabId, title }) => {
  const norm = normalizeUrl(url);
  if (!norm || norm === lastUrl) 
    return;

  lastUrl = norm;
  await save({ url: norm, fullUrl, title, ts: Date.now() }); // Here we sent the url to be analyzed and saved
});

// ========= Capture events =========

// Captura la pestaña activa al instalar/arrancar
chrome.runtime.onInstalled.addListener(captureActiveNow);
chrome.runtime.onStartup.addListener(captureActiveNow);
