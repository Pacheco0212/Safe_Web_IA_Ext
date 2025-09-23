// ===============================================================
// Module: Analyzer Core
// ===============================================================
// Description: Core functions for analyzing URLs using various services.

import { scanWithVirusTotal } from "./api/virustotal.js";

async function analyzeUrl(url) {
    const vtResult = await scanWithVirusTotal(url);
    return {
        virustotal: vtResult
    };
}

export { analyzeUrl };