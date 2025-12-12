import { getCaptures, getSettings } from "../../core/utils/storage_utils.js";

document.addEventListener('DOMContentLoaded', async () => {
    
    // --- 1. CARGAR CONTADOR (HISTORIAL) ---
    try {
        const captures = await getCaptures();
        const countElement = document.getElementById('scan-count');
        if (countElement) {
            // Mostramos el total de URLs únicas analizadas
            countElement.textContent = captures.length;
        }
    } catch (error) {
        console.error("Error cargando historial:", error);
        const countElement = document.getElementById('scan-count');
        if (countElement) countElement.textContent = "0";
    }

    // --- 2. CARGAR ESTADO DE LOS SWITCHES (CRÍTICO) ---
    // Aquí es donde arreglamos que se "reinicien" solos.
    try {
        const settings = await getSettings(); // Leemos de storage_utils
        
        const toggleProt = document.getElementById('toggle-protection');
        const toggleBubbles = document.getElementById('toggle-bubbles');
        
        // Ajustamos el switch visualmente según lo guardado
        if (toggleProt) toggleProt.checked = settings.protection;
        if (toggleBubbles) toggleBubbles.checked = settings.bubbles;

    } catch (error) {
        console.error("Error cargando configuración:", error);
    }

    // --- 3. GUARDAR CAMBIOS AL HACER CLICK ---
    const saveSettings = () => {
        const toggleProt = document.getElementById('toggle-protection');
        const toggleBubbles = document.getElementById('toggle-bubbles');

        const newSettings = {
            protection: toggleProt ? toggleProt.checked : true,
            bubbles: toggleBubbles ? toggleBubbles.checked : true
        };
        
        // Guardamos en la memoria local
        chrome.storage.local.set({ settings: newSettings }, () => {
            console.log("Configuración guardada:", newSettings);
            
            // Opcional: Cambiar badge visualmente
            if (!newSettings.protection) {
                 chrome.action.setBadgeText({ text: "OFF" });
                 chrome.action.setBadgeBackgroundColor({ color: "#999" });
            } else {
                 chrome.action.setBadgeText({ text: "" });
            }
        });
    };

    // Listeners para detectar clicks
    const tProt = document.getElementById('toggle-protection');
    const tBubb = document.getElementById('toggle-bubbles');

    if (tProt) tProt.addEventListener('change', saveSettings);
    if (tBubb) tBubb.addEventListener('change', saveSettings);

    // --- 4. BOTÓN DE HISTORIAL ---
    const btnHistory = document.getElementById('btn-open-history');
    if (btnHistory) {
        btnHistory.addEventListener('click', () => {
            chrome.tabs.create({ url: 'ui/history/history.html' });
        });
    }
});