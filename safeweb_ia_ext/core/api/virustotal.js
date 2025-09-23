// ===============================================================
// Module: VirusTotal API Client
// ===============================================================
// Description: Functions to interact with the VirusTotal API.

const VIRUSTOTAL_API_KEY = "";
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
        
        console.log("URL:", url);
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
    console.log("[VirusTotal] Full report:", report);

    return normalizeVirusTotalReport(report, report.data.id);

  } catch (error) {
    console.error("Error getting VirusTotal report:", error);
    return { error: error.message };
  }
}

function normalizeVirusTotalReport(report, url) {
  try {
    const attrs = report.data.attributes;

    return {
      url,
      reputation: attrs.reputation ?? 0,
      last_analysis_date: attrs.last_analysis_date,
      stats: {
        malicious: attrs.last_analysis_stats.malicious,
        suspicious: attrs.last_analysis_stats.suspicious,
        harmless: attrs.last_analysis_stats.harmless,
        undetected: attrs.last_analysis_stats.undetected,
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