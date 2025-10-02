// ===============================================================
// Module: Analyzer Core
// ===============================================================
// Description: Core functions for analyzing URLs using various services.

import { scanWithVirusTotal } from "./api/virustotal.js";
import { analyzeStructuralUrl } from "./api/structuralAnalysis.js";
import { analyzeHostWithSSLLabs } from "./api/ssllabs.js";
import { analyzeWithGoogleSafeBrowsing } from "./api/safebrowsing.js";

async function analyzeUrl(url, options = { debug: false }) {
    console.log("[Analyzer] Analyzing URL:", url);

    const host = (new URL(url)).hostname;

    const [vtResult, structuralResult, ssllabs, safebrowsing] = await Promise.allSettled([
        scanWithVirusTotal(url),
        Promise.resolve(analyzeStructuralUrl(url, options)),
        analyzeHostWithSSLLabs(host, { starNew: false, fromCache: true, debug: false }),
        analyzeWithGoogleSafeBrowsing(url)
    ]);

    // console.log("[Analyzer] [VirusTotal] Analysis results:", vtResult);
    // console.log("[Analyzer] [Structural] Analysis results:", structuralResult);
    // console.log("[Analyzer] [SSL Labs] Analysis results:", ssllabs);
    console.log("[Analyzer] [Google Safe Browsing] Analysis results:", safebrowsing);

    return {
        virustotal:
            vtResult.status === "fulfilled" ? vtResult.value : { error: vtResult.reason },
        structuralAnalysis:
            structuralResult.status === "fulfilled" ? structuralResult.value : { error: structuralResult.reason },
        ssllabs:
            ssllabs.status === "fulfilled" ? ssllabs.value : { error: ssllabs.reason },
        safebrowsing:
            safebrowsing.status === "fulfilled" ? safebrowsing.value : { error: safebrowsing.reason },
        analyzedAt:
            Date.now()
    };
}

export { analyzeUrl };