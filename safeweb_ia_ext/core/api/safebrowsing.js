// ===============================================================
// Module: Google Safe Browsing API client
// ===============================================================
// Description:
//  This module provides a function to query the Google Safe 
// Browsing blacklist API
// ===============================================================

import { getApiKeys } from "../utils/storage_utils.js";

const GOOGLE_SAFEBROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find";
// const SAFEBROWSING_API_KEY = "AIzaSyBde4KzBgQjmig7cO-vuhtGJjtxQB4BxQU";

export async function analyzeWithGoogleSafeBrowsing(url, debug) {
  const { safebrowsing } = await getApiKeys();

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

    const response = await fetch(`${GOOGLE_SAFEBROWSING_URL}?key=${safebrowsing}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });

    if (!response.ok) {
      const txt = await response.text();
      throw new Error(`Google Safe Browsing request failed: ${response.status} ${response.statusText} ${txt}`);
    }

    const data = await response.json();
    if (debug) console.log("[Google Safe Browsing] Raw data:", data);

    // Extract matches
    const matches = data.matches || [];

    const report = {
      source: "Google Safe Browsing",
      url,
      success: true,
      malicious: matches.length > 0,
      threatCount: matches.length,
      timestamp: new Date().toISOString(),
      confidence: matches.length > 0 ? 1.0 : 0.0, // Useful for ML models
      status: matches.length > 0 ? "Detected" : "Clean",
      threats: matches.map(match => ({
        threatType: match.threatType,
        platformType: match.platformType,
        entryType: match.threatEntryType,
        detectedUrl: match.threat?.url || url,
        metadata: match.threatEntryMetadata || {}
      })),
      raw: data
    };

    return report;

  } catch (error) {
    console.error("[Google Safe Browsing] Error:", error);
    return {
      source: "Google Safe Browsing",
      url,
      success: false,
      malicious: false,
      error: error.message,
      timestamp: new Date().toISOString()
    };
  }
}
