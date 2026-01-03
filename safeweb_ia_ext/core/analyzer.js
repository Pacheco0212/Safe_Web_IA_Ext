// ===============================================================
// Module: Analyzer Core (CORREGIDO)
// ===============================================================

import { analyzeStructuralUrl } from "./api/structuralAnalysis.js";
import { scanSsl } from "./api/ssl.js";
import { analyzeWithGoogleSafeBrowsing } from "./api/safebrowsing.js";
import { analyzeWhoisFreaks } from "./api/whoisfreaks.js";
import { saveIndividualReport } from "./utils/storage_utils.js";
import { extractFeaturesForModel } from "./utils/feature_extractor.js";

async function ensureOffscreenDocument() {
    await chrome.runtime.sendMessage({ action: "create_offscreen" });
}

async function analyzeUrl(url, options = { debug: false, debugAnalyzer: true }) {
    console.log("[Analyzer] Analyzing URL:", url);
    const host = (new URL(url)).hostname;

    // 1. Recolección de datos
    const [structuralResult, sslResult, safebrowsing, whoisfreaks] = await Promise.allSettled([
        Promise.resolve(analyzeStructuralUrl(url, options.debug)),
        scanSsl(host, false, options.debug),
        analyzeWithGoogleSafeBrowsing(url, options.debug),
        analyzeWhoisFreaks(host, options.debug)
    ]);

    const structData = structuralResult.status === "fulfilled" ? structuralResult.value : {};
    const sslData = sslResult.status === "fulfilled" ? sslResult.value : {};
    const whoisData = whoisfreaks.status === "fulfilled" ? whoisfreaks.value : {};
    const sbData = safebrowsing.status === "fulfilled" ? safebrowsing.value : {};

    if (options.debugAnalyzer) {
        console.log("[Analyzer] Data collected:", { structData, sslData, sbData, whoisData });
    }

    // 2. Preparar features
    const features = extractFeaturesForModel(url, structData, sslData, whoisData, sbData);

    // 3. IA via Offscreen
    let aiProbability = 0;
    let aiVerdict = "UNKNOWN"; // SAFE, SUSPICIOUS, DANGEROUS
    let aiConfidence = 0;      // Porcentaje 0-100
    let aiMessage = "Análisis pendiente";
    let aiColor = "#808080";   // Gris por defecto
    let aiError = null;

    try {
        await ensureOffscreenDocument();

        const response = await chrome.runtime.sendMessage({
            action: 'analyze_url_ai',
            inputs: features
        });

        if (!response) throw new Error("Respuesta IA vacía");
        if (response.error) throw new Error(response.error);

        aiProbability = response.probability;
        // --- LÓGICA DE SEMÁFORO (Thresholds) ---
        // 0.0 -> Phishing (Clase 0)
        // 1.0 -> Legítimo (Clase 1)
        
        aiProbability = response.probability; // Valor crudo (ej: 0.9674)

        if (aiProbability < 0.40) {
            // RANGO ROJO: PELIGROSO
            aiVerdict = "PELIGROSO";
            aiColor = "#d32f2f"; // Rojo Material Design
            aiMessage = "¡SITIO PELIGROSO! NO INTRODUZCAS INFORMACIÓN PERSONAL.";

        } else if (aiProbability >= 0.40 && aiProbability < 0.75) {
            // RANGO AMARILLO: SOSPECHOSO (Zona de duda)
            aiVerdict = "SOSPECHOSO";
            aiColor = "#f5d400ff"; // Amarillo Material Design
            aiMessage = "Sitio Sospechoso. Evita introducir información personal.";

        } else {
            // RANGO VERDE: SEGURO (Mayor a 0.75)
            aiVerdict = "SEGURO";
            aiColor = "#388e3c"; // Verde Material Design
            aiMessage = "Sitio Seguro. Navegación verificada.";
        }

        console.log(`[Analyzer] IA Verdict: ${aiVerdict} ProbRaw: ${aiProbability.toFixed(4)}`);
    } 
    catch (err) {
        console.error("[Analyzer] AI ERROR:", err);
        aiError = err.message;
    }

    // 4. Reporte Final
    const finalReport = {
        url,
        analyzedAt: Date.now(),
        ai_analysis: {
            verdict: aiVerdict,       // "SAFE", "SUSPICIOUS", "DANGEROUS"
            probability: aiProbability, // Valor crudo para debug
            message: aiMessage,       // Mensaje para el usuario
            themeColor: aiColor,      // Color para el borde/icono del popup
            is_safe: aiVerdict === "SAFE", // Booleano simple para lógica rápida
            error: aiError
        },
        // Datos crudos por si el usuario quiere ver "Detalles avanzados"
        details: {
            structural: structData,
            ssl: sslData,
            safebrowsing: sbData,
            whois: whoisData
        }
    };

    await saveIndividualReport(finalReport);
    return finalReport;
}

export { analyzeUrl };