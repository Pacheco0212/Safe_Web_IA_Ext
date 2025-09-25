// ===============================================================
// Module: SSL Labs API Client
// ===============================================================
// Description: Functions to interact with the SSL Labs API for HTTPS/SSL analysis.
// Docs: https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs.md
// ===============================================================

const SSLLABS_API_URL = "https://api.ssllabs.com/api/v3/analyze";

async function analyzeHostWithSSLLabs(host) {
  try {
    console.log(`[SSL Labs] Starting analysis for host: ${host}`);

    // 1) Try cache first
    const cached = await fetch(`${SSLLABS_API_URL}?host=${host}&fromCache=on`);
    if (!cached.ok) {
      throw new Error(`Cache fetch failed: ${cached.status} ${cached.statusText}`);
    }

    const cachedResult = await cached.json();
    if (cachedResult.status === "READY") {
      console.log("[SSL Labs] Found cached result:", cachedResult);
      return normalizeSSLLabsReport(cachedResult);
    }

    console.log("[SSL Labs] No valid cached result, starting new analysis...");

    // 2) If there is no cache, start a new scan
    const fresh = await fetch(`${SSLLABS_API_URL}?host=${host}&startNew=on&all=done`);
    if (!fresh.ok) {
      throw new Error(`Fresh analysis failed: ${fresh.status} ${fresh.statusText}`);
    }

    const freshResult = await fresh.json();

    if (freshResult.status === "READY") {
      console.log("[SSL Labs] New analysis ready immediately:", freshResult);
      return normalizeSSLLabsReport(freshResult);
    } else {
      console.log("[SSL Labs] Analysis in progress, result will take time...");
      // Do not block flow: return "pending" status
      return { host, status: "PENDING", message: "Analysis started, results not ready yet." };
    }

  } catch (error) {
    console.error("[SSL Labs] Error:", error);
    return { error: `SSL Labs analyze request failed: ${error.message}` };
  }
}


function normalizeSSLLabsReport(report) {
  try {
    const endpoint = report.endpoints?.[0]; // We take the first endpoint (typical in simple domains)
    return {
      host: report.host,
      status: report.status,
      grade: endpoint?.grade ?? "N/A",
      hasWarnings: endpoint?.hasWarnings ?? false,
      isExceptional: endpoint?.isExceptional ?? false,
      progress: endpoint?.progress ?? 0,
      details: {
        protocol: endpoint?.details?.protocols?.map(p => `${p.name} ${p.version}`) ?? [],
        certificates: {
          issuer: endpoint?.details?.cert?.issuerLabel ?? "Unknown",
          notAfter: endpoint?.details?.cert?.notAfter ?? null,
          sigAlg: endpoint?.details?.cert?.sigAlg ?? "Unknown",
        },
      },
    };
  } catch (e) {
    console.error("[SSL Labs] Error normalizing:", e);
    return { error: "The SSL Labs report could not be processed." };
  }
}

export { analyzeHostWithSSLLabs };
