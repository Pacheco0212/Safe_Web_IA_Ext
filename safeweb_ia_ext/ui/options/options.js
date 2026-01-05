import { 
    getSettings, 
    getApiKeys, 
    saveCaptures 
} from "../../core/utils/storage_utils.js";

document.addEventListener('DOMContentLoaded', async () => {

    // --- 1. CONFIGURACIÓN GENERAL ---
    const settings = await getSettings();
    const optProt = document.getElementById('opt-protection');
    const optBubbles = document.getElementById('opt-bubbles');

    if (optProt) optProt.checked = settings.protection;
    if (optBubbles) optBubbles.checked = settings.bubbles;

    const saveGeneral = () => {
        const newSettings = {
            protection: optProt.checked,
            bubbles: optBubbles.checked
        };
        chrome.storage.local.set({ settings: newSettings }, () => {
            showToast("Configuración general actualizada", "success");
            
            if (!newSettings.protection) {
                chrome.action.setBadgeText({ text: "OFF" });
            } else {
                chrome.action.setBadgeText({ text: "" });
            }
        });
    };

    if (optProt) optProt.addEventListener('change', saveGeneral);
    if (optBubbles) optBubbles.addEventListener('change', saveGeneral);


    // --- 2. API KEYS CON VERIFICACIÓN REAL ---
    const keys = await getApiKeys();
    const inputWhois = document.getElementById('api-whois');
    const inputSb = document.getElementById('api-sb');
    const btnSaveKeys = document.getElementById('btn-save-keys');

    if (inputWhois) inputWhois.value = keys.whoisfreaks || '';
    if (inputSb) inputSb.value = keys.safebrowsing || '';

    if (btnSaveKeys) {
        btnSaveKeys.addEventListener('click', async () => {
            const wfVal = inputWhois.value.trim();
            const sbVal = inputSb.value.trim();

            // 1. Validación Local (Vacío/Longitud)
            if (!wfVal || !sbVal) {
                showToast("Error: Campos vacíos.", "error");
                return;
            }
            if (wfVal.length < 20 || sbVal.length < 20) {
                showToast("Error: Formato de llave inválido (muy corta).", "error");
                return;
            }

            // 2. Validación Remota (Ping a los servidores)
            // Cambiamos el estado del botón para dar feedback
            const originalText = btnSaveKeys.textContent;
            btnSaveKeys.textContent = "Verificando conexión...";
            btnSaveKeys.disabled = true;
            btnSaveKeys.style.opacity = "0.7";

            try {
                // Ejecutamos la prueba de fuego
                await verifyKeys(wfVal, sbVal);
                
                // SI LLEGAMOS AQUÍ, LAS LLAVES SON VÁLIDAS
                const newKeys = { ...keys };
                newKeys.whoisfreaks = wfVal;
                newKeys.safebrowsing = sbVal;

                chrome.storage.local.set({ api_keys: newKeys }, () => {
                    showToast("¡Conexión exitosa! Llaves guardadas.", "success");
                });

            } catch (error) {
                // SI FALLA ALGUNA, MOSTRAMOS EL ERROR
                console.error(error);
                showToast(error.message, "error");
            } finally {
                // Restauramos el botón pase lo que pase
                btnSaveKeys.textContent = originalText;
                btnSaveKeys.disabled = false;
                btnSaveKeys.style.opacity = "1";
            }
        });
    }

    // --- 3. BORRAR HISTORIAL ---
    const btnClear = document.getElementById('btn-clear-history');
    if (btnClear) {
        btnClear.addEventListener('click', () => {
            if (confirm("¿Borrar todo el historial?")) {
                saveCaptures([]).then(() => {
                    showToast("Historial eliminado", "success");
                    chrome.action.setBadgeText({ text: "" });
                });
            }
        });
    }
});

/**
 * Función que hace peticiones reales a las APIs para ver si responden 200 OK.
 * Lanza un error si la llave es rechazada.
 */
async function verifyKeys(whoisKey, sbKey) {
    
    // A. Verificar WhoisFreaks
    // CORRECCIÓN: El parámetro 'whois' debe ser 'live' y el dominio va en 'domainName'
    try {
        const whoisUrl = `https://api.whoisfreaks.com/v1.0/whois?apiKey=${whoisKey}&whois=live&domainName=google.com`;
        
        const whoisResp = await fetch(whoisUrl, { method: 'GET' });

        if (!whoisResp.ok) {
            // Manejo de errores específicos
            if (whoisResp.status === 401) throw new Error("Llave WhoisFreaks inválida (401).");
            if (whoisResp.status === 402) throw new Error("Llave WhoisFreaks sin créditos (402).");
            if (whoisResp.status === 403) throw new Error("Llave WhoisFreaks expirada o bloqueada (403).");
            if (whoisResp.status === 404) throw new Error("Error de conexión con WhoisFreaks (Endpoint no encontrado).");
            
            throw new Error(`Error WhoisFreaks: ${whoisResp.status}`);
        }
    } catch (err) {
        throw new Error(err.message.includes("WhoisFreaks") ? err.message : "No se pudo conectar con WhoisFreaks.");
    }

    // B. Verificar Google Safe Browsing
    try {
        const sbUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${sbKey}`;
        const sbBody = {
            client: { clientId: "tesis-app", clientVersion: "1.0" },
            threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url: "http://google.com" }]
            }
        };

        const sbResp = await fetch(sbUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(sbBody)
        });

        if (!sbResp.ok) {
            if (sbResp.status === 400) throw new Error("Llave SafeBrowsing mal formada (400).");
            if (sbResp.status === 403) throw new Error("Llave SafeBrowsing rechazada (403).");
            throw new Error(`Error SafeBrowsing: ${sbResp.status}`);
        }
    } catch (err) {
        throw new Error(err.message.includes("SafeBrowsing") ? err.message : "No se pudo conectar con Google SafeBrowsing.");
    }

    // Si ambas pasan
    return true;
}

// Helper Toast
function showToast(msg, type = 'success') {
    const toast = document.getElementById('toast');
    if (type === 'error') {
        toast.textContent = "❌ " + msg;
        toast.style.backgroundColor = "#d32f2f";
    } else {
        toast.textContent = "✅ " + msg;
        toast.style.backgroundColor = "#333";
    }
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 4000);
}