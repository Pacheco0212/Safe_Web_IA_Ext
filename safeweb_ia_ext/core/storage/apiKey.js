// core/storage/apiKey.js

// Guarda una API key con una etiqueta (ej. "VIRUSTOTAL", "GOOGLE_SAFE_BROWSING")
export async function setApiKey(service, key) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.set({ [service]: key }, () => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve(true);
      }
    });
  });
}

// Obtiene la API key de un servicio
export async function getApiKey(service) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get([service], (result) => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
        return;
      }
      resolve(result[service] || null);
    });
  });
}


// Elimina la API key de un servicio
export async function removeApiKey(service) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.remove(service, () => {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve(true);
      }
    });
  });
}
