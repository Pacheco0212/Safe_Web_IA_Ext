// ===============================================================
// Module: VirusTotal API Client
// ===============================================================
// Description: Functions to interact with the VirusTotal API.

const VIRUSTOTAL_API_KEY = "5ee5c754a74d080e76ec0da50b0e7ff1af3cfde7ce9f9e81661dca1caa31c663";
const VIRUSTOTAL_SCAN_URL = "https://www.virustotal.com/api/v3/urls";

function encodeUrlId(url) {
  return btoa(url)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function scanWithVirusTotal(url) {
    try {
        const response = await fetch(VIRUSTOTAL_SCAN_URL, {
            method: "POST",
            headers: {
                "x-apikey": VIRUSTOTAL_API_KEY,
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: `url=${encodeURIComponent(url)}`,
        });

        if (!response.ok) {
            throw new Error(`Error: ${response.status} ${response.statusText}`);
        }

        const result = await response.json();
        // console.log("URL:", url + " [VirusTotal] Scan result:", result);

        const urlId = encodeUrlId(url);
        // console.log("URL:", url + " [VirusTotal] URL Id:", urlId);
        
        return await getVirusTotalReport(urlId);

    } catch (error) {
        console.error("Error parsing URL with VirusTotal:", error);
        return { error: error.message };
    }
}

async function getVirusTotalReport(analysisId) {
  try {
    const response = await fetch(`${VIRUSTOTAL_SCAN_URL}/${analysisId}`, {
        method: "GET",
        headers: {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
    });

    if (!response.ok) {
      throw new Error(`Error: ${response.status} ${response.statusText}`);
    }

    const report = await response.json();
    // console.log("[VirusTotal] Full report:", report);

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

    // Extraer motores que marcaron como malicioso o sospechoso
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
      detections, // lista de motores que detectaron
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