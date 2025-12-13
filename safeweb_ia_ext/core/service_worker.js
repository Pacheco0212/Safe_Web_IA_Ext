/**
 * SERVICE WORKER (MV3) - CON SOPORTE PARA SWITCHES DE ON/OFF
 */

console.log("SW loaded");

import { initCapture } from "./url_capture.js";
import { analyzeUrl } from "./analyzer.js";
import { initApiKeys, getCaptures, saveCaptures, findExistingAnalysis, getSettings, initSettings } from "./utils/storage_utils.js";

const MAX_ITEMS = 100;
let lastUrl = null;
let lastBubbleLog = {};
let creatingOffscreenPromise = null;
const tabsProcessing = new Set();

const API_KEYS = {
  safebrowsing: "AIzaSyBde4KzBgQjmig7cO-vuhtGJjtxQB4BxQU",
  whoisfreaks: "fb98ade12e6a40408dbe96bfc4f70091"
};

// Inicializamos Keys y también los Settings por defecto
chrome.runtime.onInstalled.addListener(() => {
    initApiKeys(API_KEYS);
    initSettings(); // <--- [NUEVO] Crea { protection: true, bubbles: true }
});

function normalizeUrl(u) {
  try {
    const url = new URL(u);
    return url.origin;
  } catch {
    return null;
  }
}

async function sendMessageWithRetry(tabId, message, retries = 5, delay = 500) {
    for (let i = 0; i < retries; i++) {
        try {
            await chrome.tabs.sendMessage(tabId, message);
            return; 
        } catch (err) {
            if (i < retries - 1) await new Promise(r => setTimeout(r, delay));
        }
    }
}

// ===== Save and analyze URL =====
async function save(entry) {
  // 1. LEER CONFIGURACIÓN
  const settings = await getSettings();

  // [LOGICA SWITCH 1] Si el modo protección está APAGADO, nos detenemos aquí.
  if (!settings.protection) {
      console.log("Protección desactivada por el usuario. Omitiendo análisis.");
      return; 
  }

  // --- Resto de lógica de Cerrojo y Debounce ---
  if (entry.tabId && tabsProcessing.has(entry.tabId)) return;

  const now = Date.now();
  const last = lastBubbleLog[entry.tabId];
  if (last && last.url === entry.url && (now - last.ts) < 2000) return;

  if (entry.tabId) tabsProcessing.add(entry.tabId);

  try {
      // ... Lógica de análisis normal ...
      const existing = await findExistingAnalysis(entry.url);
      let enrichedEntry;

      if (existing && existing.analysis) {
        enrichedEntry = { ...entry, analysis: existing.analysis, reused: true };
      } else {
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

      // [LOGICA SWITCH 2] Solo enviamos la burbuja si el usuario quiere "Alertas visibles"
      if (settings.bubbles) { 
          if (entry.tabId && enrichedEntry.analysis) {
              lastBubbleLog[entry.tabId] = { url: entry.url, ts: Date.now() };

              await sendMessageWithRetry(entry.tabId, {
                  action: "SHOW_RESULT_BUBBLE",
                  data: enrichedEntry.analysis
              });
          }
      } else {
          console.log("💬 Burbujas desactivadas por configuración.");
      }

  } catch (error) {
      console.error("Error en save:", error);
  } finally {
      if (entry.tabId) tabsProcessing.delete(entry.tabId);
  }
}

async function ensureOffscreen() {
    if (creatingOffscreenPromise) { await creatingOffscreenPromise; return; }
    const exists = await chrome.offscreen.hasDocument();
    if (exists) return;
    creatingOffscreenPromise = chrome.offscreen.createDocument({
        url: chrome.runtime.getURL("ai/offscreen.html"),
        reasons: ["WORKERS"],
        justification: "Run TensorFlow inference using WASM"
    });
    await creatingOffscreenPromise;
    creatingOffscreenPromise = null;
}

const { captureActiveNow } = initCapture(async ({ url, fullUrl, tabId, title }) => {
  const norm = normalizeUrl(url);
  if (!norm) return;
  lastUrl = norm;
  await save({ url: norm, fullUrl, title, tabId, ts: Date.now() });
});

(async () => {
    try { await ensureOffscreen(); await captureActiveNow(); } catch (e) {}
})();

chrome.runtime.onInstalled.addListener(() => { ensureOffscreen(); captureActiveNow(); });
chrome.runtime.onStartup.addListener(() => { ensureOffscreen(); captureActiveNow(); });
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === "create_offscreen") {
        ensureOffscreen().then(() => sendResponse({ ok: true }));
        return true;
    }
});