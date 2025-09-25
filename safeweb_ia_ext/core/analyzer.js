// ===============================================================
// Module: Analyzer Core
// ===============================================================
// Description: Core functions for analyzing URLs using various services.

import { scanWithVirusTotal } from "./api/virustotal.js";
import { analyzeStructuralUrl } from "./api/structuralAnalysis.js";

async function analyzeUrl(url, options = { debug: false }) {
    console.log("[Analyzer] Analyzing URL:", url);

    const [vtResult, structuralResult] = await Promise.allSettled([
        scanWithVirusTotal(url),
        Promise.resolve(analyzeStructuralUrl(url, options))
    ]);

    console.log("[Analyzer] [VirusTotal] Analysis results:", vtResult);
    console.log("[Analyzer] [Structural] Analysis results:", structuralResult);

    return {
        virustotal:
            vtResult.status === "fulfilled" ? vtResult.value : { error: vtResult.reason },
        structuralAnalysis:
            structuralResult.status === "fulfilled" ? structuralResult.value : { error: structuralResult.reason },
        analyzedAt: 
            Date.now()
    };
}

export { analyzeUrl };