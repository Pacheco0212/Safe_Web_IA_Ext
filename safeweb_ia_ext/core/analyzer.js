// ===============================================================
// Module: Analyzer Core
// ===============================================================
// Description: Core functions for analyzing URLs using various services.

import { scanWithVirusTotal } from "./api/virustotal.js";
import { analyzeStructuralUrl } from "./api/structuralAnalysis.js";
import { analyzeHostWithSSLLabs } from "./api/ssllabs.js";
import { analyzeWithGoogleSafeBrowsing } from "./api/safebrowsing.js";
import { analyzeWhois } from "./api/whois.js";
import { analyzeWhoisFreaks } from "./api/whoisfreaks.js";

async function analyzeUrl(url, options = { debug: false, debugAnalyzer: true }) {
    console.log("[Analyzer] Analyzing URL:", url);

    const host = (new URL(url)).hostname;

    const [vtResult, structuralResult, ssllabs, safebrowsing, whoisfreaks] = await Promise.allSettled([
        scanWithVirusTotal(url, options.debug),
        Promise.resolve(analyzeStructuralUrl(url, options.debug)),
        analyzeHostWithSSLLabs(host, options.debug),
        analyzeWithGoogleSafeBrowsing(url, options.debug),
        // analyzeWhois(host),
        analyzeWhoisFreaks(host, options.debug)
    ]);

    if (options.debugAnalyzer) {
        console.log("[Analyzer] [VirusTotal] Analysis results:", vtResult);
        console.log("[Analyzer] [Structural] Analysis results:", structuralResult);
        console.log("[Analyzer] [SSL Labs] Analysis results:", ssllabs);
        console.log("[Analyzer] [Google Safe Browsing] Analysis results:", safebrowsing);
        // console.log("[Analyzer] [Whois API] Analysis results:", whois);
        console.log("[Analyzer] [Whois API] Analysis results:", whoisfreaks);
    }

    return {
        virustotal:
            vtResult.status === "fulfilled" ? vtResult.value : { error: vtResult.reason },
        structuralAnalysis:
            structuralResult.status === "fulfilled" ? structuralResult.value : { error: structuralResult.reason },
        ssllabs:
            ssllabs.status === "fulfilled" ? ssllabs.value : { error: ssllabs.reason },
        safebrowsing:
            safebrowsing.status === "fulfilled" ? safebrowsing.value : { error: safebrowsing.reason },
        // whois:
            // whois.status === "fulfilled" ? whois.value : { error: whois.reason },
        whoisfreaks:
            whoisfreaks.status === "fulfilled" ? whoisfreaks.value : { error: whoisfreaks.reason },
        analyzedAt:
            Date.now()
    };
}

export { analyzeUrl };