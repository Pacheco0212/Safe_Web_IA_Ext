import { 
    getSettings, 
    getApiKeys, 
    saveCaptures 
} from "../../core/utils/storage_utils.js";

document.addEventListener('DOMContentLoaded', async () => {

    // --- 1. CARGAR CONFIGURACIÓN GENERAL ---
    const settings = await getSettings();
    const optProt = document.getElementById('opt-protection');
    const optBubbles = document.getElementById('opt-bubbles');

    if (optProt) optProt.checked = settings.protection;
    if (optBubbles) optBubbles.checked = settings.bubbles;

    // Función de auto-guardado para switches
    const saveGeneral = () => {
        const newSettings = {
            protection: optProt.checked,
            bubbles: optBubbles.checked
        };
        chrome.storage.local.set({ settings: newSettings }, () => {
            showToast("Configuración general actualizada");
            
            // Actualizar Badge si se apaga
            if (!newSettings.protection) {
                chrome.action.setBadgeText({ text: "OFF" });
            } else {
                chrome.action.setBadgeText({ text: "" });
            }
        });
    };

    optProt.addEventListener('change', saveGeneral);
    optBubbles.addEventListener('change', saveGeneral);


    // --- 2. CARGAR Y GUARDAR API KEYS ---
    // Esto es muy útil para no tener que editar el código si cambian las llaves
    const keys = await getApiKeys();
    const inputWhois = document.getElementById('api-whois');
    const inputSb = document.getElementById('api-sb');

    if (inputWhois) inputWhois.value = keys.whoisfreaks || '';
    if (inputSb) inputSb.value = keys.safebrowsing || '';

    document.getElementById('btn-save-keys').addEventListener('click', () => {
        const newKeys = { ...keys }; // Mantener otras llaves si existen
        newKeys.whoisfreaks = inputWhois.value.trim();
        newKeys.safebrowsing = inputSb.value.trim();

        chrome.storage.local.set({ api_keys: newKeys }, () => {
            showToast("Llaves API guardadas correctamente");
        });
    });


    // --- 3. BORRAR HISTORIAL ---
    document.getElementById('btn-clear-history').addEventListener('click', () => {
        if (confirm("¿Estás seguro de que quieres borrar todo el historial de análisis? Esta acción no se puede deshacer.")) {
            // Guardamos un array vacío
            saveCaptures([]).then(() => {
                showToast("Historial eliminado");
                // Opcional: reiniciar contador del badge
                chrome.action.setBadgeText({ text: "" });
            });
        }
    });

});

// Función auxiliar para mostrar mensajito flotante
function showToast(msg) {
    const toast = document.getElementById('toast');
    toast.textContent = "✅ " + msg;
    toast.classList.add('show');
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}