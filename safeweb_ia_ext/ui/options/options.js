document.getElementById("saveKey").addEventListener("click", () => {
  const key = document.getElementById("safeKey").value;

  if (!key) {
    alert("Debes ingresar una API Key.");
    return;
  }

  chrome.storage.local.set({ safeBrowsingApiKey: key }, () => {
    alert("API Key de Google Safe Browsing guardada correctamente.");
  });
});
