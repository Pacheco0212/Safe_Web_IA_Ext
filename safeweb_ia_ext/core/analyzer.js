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
    let aiPrediction = "UNKNOWN";
    let aiProbability = 0;
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
        aiPrediction = aiProbability > 0.5 ? "LEGITIMATE" : "MALICIOUS";

        console.log(`[Analyzer] IA: ${aiPrediction} (${(aiProbability * 100).toFixed(2)}%)`);
    } 
    catch (err) {
        console.error("[Analyzer] AI ERROR:", err);
        aiError = err.message;
    }

    // 4. Reporte Final
    const finalReport = {
        url,
        ai_analysis: {
            verdict: aiPrediction,
            probability: aiProbability,
            is_safe: aiProbability < 0.5,
            error: aiError
        },
        structuralAnalysis: structData,
        sslAnalysis: sslData,
        safebrowsing: sbData,
        whoisfreaks: whoisData,
        analyzedAt: Date.now()
    };

    await saveIndividualReport(finalReport);
    return finalReport;
}

export { analyzeUrl };