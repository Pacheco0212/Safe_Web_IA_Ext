// ========================================================
// OFFSCREEN — IA Phishing Detector (Chrome MV3)
// Versión Final: Normalización Manual + Modelo Limpio
// ========================================================

let model = null;
let normData = null; // Aquí guardaremos mean y std
let isReady = false;

async function init() {
    if (isReady) return;

    console.log("[Offscreen] Inicializando IA (v10)...");

    // 1. Configuración WASM
    tf.env().set("WASM_HAS_SIMD_SUPPORT", false);
    tf.env().set("WASM_HAS_MULTITHREAD_SUPPORT", false);
    tf.wasm.setWasmPaths(chrome.runtime.getURL("ai/"));
    await tf.setBackend("wasm");

    // 2. Cargar datos de Normalización (JSON)
    // Esto evita los errores de capas desconocidas
    try {
        const normUrl = chrome.runtime.getURL("ai/Modelo_JS_v13/normalization.json");
        const response = await fetch(normUrl);
        normData = await response.json();
        console.log("[Offscreen] Datos de normalización cargados OK");
    } catch (err) {
        console.error("[Offscreen] Error cargando normalization.json:", err);
        throw err;
    }

    // 3. Cargar Modelo
    const modelUrl = chrome.runtime.getURL("ai/Modelo_JS_v13/model.json");
    try {
        model = await tf.loadLayersModel(modelUrl);
        console.log("[Offscreen] Modelo v10 cargado OK (Sin conflictos de nombres)");
    } catch(err) {
        console.error("Error cargando modelo:", err);
    }

    isReady = true;
}

// Función auxiliar matemática
function normalizeInput(features) {
    if (!normData) throw new Error("Datos de normalización no cargados");
    
    // Fórmula: (Valor - Media) / Desviación
    // map devuelve un nuevo array
    return features.map((val, index) => {
        const mean = normData.mean[index] || 0;
        const std = normData.std[index] || 1; 
        // Evitar división por cero si std es 0 (muy raro, pero posible)
        const safeStd = std === 0 ? 1 : std; 
        return (val - mean) / safeStd;
    });
}

async function runPrediction(features) {
    try {
        await init();

        if (!Array.isArray(features) || features.length !== 27) {
            console.warn(`[Offscreen] Features inválidas. Recibidas: ${features?.length}`);
            return { error: "Dimensiones incorrectas" };
        }

        // 1. Normalizar Manualmente en JS
        const normalizedFeatures = normalizeInput(features);

        // 2. Crear Tensor y Predecir
        const tensor = tf.tensor([normalizedFeatures], [1, 27], "float32");
        const out = model.predict(tensor);
        const prob = (await out.data())[0];

        // Limpieza
        tensor.dispose();
        out.dispose();

        return { probability: prob };

    } catch (err) {
        console.error("[Offscreen] Prediction error:", err);
        return { error: err.message };
    }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === "analyze_url_ai") {
        runPrediction(msg.inputs)
            .then(sendResponse)
            .catch(err => sendResponse({ error: err.message }));
        return true;
    }
});