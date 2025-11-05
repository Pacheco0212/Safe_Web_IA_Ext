// ===============================================================
// Module: VirusTotal API Client
// ===============================================================
// Description: Functions to interact with the VirusTotal API.

import { getApiKeys } from "../utils/storage_utils.js";

// const VIRUSTOTAL_API_KEY = "5ee5c754a74d080e76ec0da50b0e7ff1af3cfde7ce9f9e81661dca1caa31c663";
const VIRUSTOTAL_SCAN_URL = "https://www.virustotal.com/api/v3/urls";


function encodeUrlId(url) {
  return btoa(url)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function scanWithVirusTotal(url, debug) {
  const { virustotal } = await getApiKeys();

    try {
        const response = await fetch(VIRUSTOTAL_SCAN_URL, {
            method: "POST",
            headers: {
                "x-apikey": virustotal,
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: `url=${encodeURIComponent(url)}`,
        });

        if (!response.ok) {
            throw new Error(`Error: ${response.status} ${response.statusText}`);
        }

        const result = await response.json();
        // if(debug) console.log("[VirusTotal] Scan result:", result);

        const urlId = encodeUrlId(url);
        // if(debug) console.log("[VirusTotal] URL Id:", urlId);
        
        return await getVirusTotalReport(urlId, debug);

    } catch (error) {
        console.error("Error parsing URL with VirusTotal:", error);
        return { error: error.message };
    }
}

async function getVirusTotalReport(analysisId, debug) {
  const { virustotal } = await getApiKeys();
  
  try {
    const response = await fetch(`${VIRUSTOTAL_SCAN_URL}/${analysisId}`, {
        method: "GET",
        headers: {
            "x-apikey": virustotal
        }
    });

    if (!response.ok) {
      throw new Error(`Error: ${response.status} ${response.statusText}`);
    }

    const report = await response.json();
    if(debug) console.log("[VirusTotal] Full report:", report);

    return normalizeVirusTotalReport(report, report.data.id);

  } catch (error) {
    console.error("Error getting VirusTotal report:", error);
    return { error: error.message };
  }
}

function normalizeVirusTotalReport(report, url) {
  try {
    const attrs = report.data.attributes;
    const results = attrs.last_analysis_results || {};

    // Extract engines that detected the URL as malicious or suspicious
    const detections = Object.entries(results)
      .filter(([_, r]) => r.category === "malicious" || r.category === "suspicious")
      .map(([engine]) => engine);

    return {
      url,
      id: report.data.id,
      reputation: attrs.reputation ?? 0,
      categories: attrs.categories || {},
      tags: attrs.tags || [],
      stats: {
        malicious: attrs.last_analysis_stats.malicious,
        suspicious: attrs.last_analysis_stats.suspicious,
        harmless: attrs.last_analysis_stats.harmless,
        undetected: attrs.last_analysis_stats.undetected,
      },
      detections, // List of engines that detected the URL as malicious or suspicious
      metadata: {
        last_analysis_date: attrs.last_analysis_date,
        first_submission_date: attrs.first_submission_date,
        times_submitted: attrs.times_submitted,
      },
      votes: {
        harmless: attrs.total_votes?.harmless ?? 0,
        malicious: attrs.total_votes?.malicious ?? 0,
      }
    };

  } catch (e) {
    console.error("[VirusTotal] Error normalizing:", e);
    return { error: "The report could not be processed." };
  }
}

export { scanWithVirusTotal };