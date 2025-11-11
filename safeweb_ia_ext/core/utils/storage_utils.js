/**
 * storage_utils.js
 * ----------------
* Utility functions to handle chrome.storage.local
* and API keys or capture data.
 */

const STORAGE_KEY = "captures";
const API_KEY_STORAGE = "api_keys";

// ===== Initialize API keys only if they do not exist =====
export async function initApiKeys(defaultKeys) {
  const { api_keys } = await chrome.storage.local.get(API_KEY_STORAGE);
  if (!api_keys) {
    await chrome.storage.local.set({ [API_KEY_STORAGE]: defaultKeys });
    console.log("API Keys almacenadas en chrome.storage.local");
  }
}

// ===== Get all API keys =====
export async function getApiKeys() {
  const { api_keys } = await chrome.storage.local.get(API_KEY_STORAGE);
  return api_keys || {};
}

// ===== Save a new captures =====
export async function saveCaptures(list) {
  await chrome.storage.local.set({ [STORAGE_KEY]: list });
}

// ===== Get all the captures =====
export async function getCaptures() {
  const { [STORAGE_KEY]: captures = [] } = await chrome.storage.local.get(STORAGE_KEY);
  return captures;
}

// ===== Search for a specific URL in captures =====
export async function findExistingAnalysis(url) {
  const captures = await getCaptures();
  return captures.find(item => item.url === url) || null;
}

// ===== Save individual analysis report =====
export async function saveIndividualReport(report) {
  const captures = await getCaptures();

  // Evitar duplicados por URL
  const filtered = captures.filter(r => r.url !== report.url);
  filtered.push(report);

  await saveCaptures(filtered);
  console.log(`[Storage] Reporte guardado en captures para: ${report.url}`);
}

// ===== Create a unified global report =====
export async function createGlobalReport() {
  const captures = await getCaptures();
  if (!captures.length) return null;

  const unified = {
    totalReports: captures.length,
    generatedAt: Date.now(),
    data: captures
  };

  console.log("[Storage] Reporte global creado:", unified);
  return unified;
}
