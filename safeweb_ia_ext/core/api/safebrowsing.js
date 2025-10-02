// core/api/safebrowsing.js
// import { getApiKey } from "../storage/apiKey.js";

const GOOGLE_SAFEBROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find";
const SAFEBROWSING_API_KEY = "";

async function analyzeWithGoogleSafeBrowsing(url) {
//   const apiKey = await getApiKey("GOOGLE_SAFE_BROWSING");
//   if (!apiKey) {
//     console.error("[Google Safe Browsing] No API Key found.");
//     return {
//       source: "Google Safe Browsing",
//       url,
//       success: false,
//       error: "API Key not configured"
//     };
//   }

  try {
    const body = {
      client: {
        clientId: "chrome-extension-scan",
        clientVersion: "1.0.0"
      },
      threatInfo: {
        threatTypes: [
          "MALWARE",
          "SOCIAL_ENGINEERING",
          "UNWANTED_SOFTWARE",
          "POTENTIALLY_HARMFUL_APPLICATION"
        ],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    };

    const response = await fetch(`${GOOGLE_SAFEBROWSING_URL}?key=${SAFEBROWSING_API_KEY}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      const txt = await response.text();
      throw new Error(`Google Safe Browsing request failed: ${response.status} ${response.statusText} ${txt}`);
    }

    const data = await response.json();

    // Standardized report
    const report = {
      source: "Google Safe Browsing",
      url,
      success: true,
      malicious: !!data.matches,
      timestamp: new Date().toISOString(),
      raw: data // All raw Google JSON is retained
    };

    // Extract important details from each threat (if any)
    if (data.matches) {
      report.threats = data.matches.map(match => ({
        threatType: match.threatType,
        platformType: match.platformType,
        entryType: match.threatEntryType,
        url: match.threat.url,
        metadata: match.threatEntryMetadata || {}
      }));
    }

    return report;

  } catch (error) {
    console.error("[Google Safe Browsing] Error:", error);
    return {
      source: "Google Safe Browsing",
      url,
      success: false,
      error: error.message
    };
  }
}

export { analyzeWithGoogleSafeBrowsing }