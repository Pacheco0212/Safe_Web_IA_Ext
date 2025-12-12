// ui/bubble_injector.js

console.log("✅ CONTENT SCRIPT CARGADO: bubble_injector listo");

// Escuchar mensajes desde el Service Worker
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log("MENSAJE RECIBIDO:", request);
    if (request.action === "SHOW_RESULT_BUBBLE") {
        createOrUpdateBubble(request.data);
    }
});

function createOrUpdateBubble(data) {
    // 1. Si ya existe, la borramos para volver a crearla (evita duplicados)
    const existing = document.getElementById("safeweb-bubble-container");
    if (existing) existing.remove();

    // 2. Crear el contenedor principal
    const bubble = document.createElement("div");
    bubble.id = "safeweb-bubble-container";

    // 3. Determinar colores según el veredicto
    // data.themeColor viene de tu analyzer.js (ej: #388e3c, #d32f2f)
    const bgColor = data.ai_analysis.themeColor || "#808080";
    const verdict = data.ai_analysis.verdict; // SAFE, SUSPICIOUS, DANGEROUS
    const probability = (data.ai_analysis.probability || 0).toFixed(3) * 100;

    // 4. HTML Interno
    bubble.innerHTML = `
        <div id="safeweb-header" style="background-color: ${bgColor};">
            <span>🛡️ Análisis IA: ${verdict}</span>
            <span id="safeweb-close">✕</span>
        </div>
        <div id="safeweb-body">
            <p>${data.ai_analysis.message}</p>
        </div>
    `;

    // 5. Agregar al cuerpo de la página
    document.body.appendChild(bubble);

    // 6. Funcionalidad del botón cerrar
    document.getElementById("safeweb-close").onclick = () => {
        bubble.remove();
    };

    // (Opcional) Auto-ocultar si es SEGURO después de 5 segundos
    if (verdict === "SEGURO") {
        setTimeout(() => {
            if(document.body.contains(bubble)) bubble.remove();
        }, 5000);
    }
}