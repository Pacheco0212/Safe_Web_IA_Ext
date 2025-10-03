// ===============================================================
// Module: Whois API client
// ===============================================================
// Description:
// 
// ===============================================================
  
const WHOIS_API_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService";
const WHOIS_API_KEY = "";

export async function analyzeWhois(domain) {

  const url = `${WHOIS_API_URL}?apiKey=${WHOIS_API_KEY}&domainName=${encodeURIComponent(domain)}&outputFormat=JSON`;

  try {
    const response = await fetch(url);

    if (!response.ok) {
      const txt = await response.text();
      throw new Error(`[Whois] HTTP ${response.status} ${response.statusText}: ${txt}`);
    }

    const data = await response.json();

    if (data.ErrorMessage) {
      throw new Error(`[Whois] API Error: ${data.ErrorMessage.msg}`);
    }

    // We extract key fields
    const record = data.WhoisRecord || {};
    const registryData = record.registryData || {};
    const registrant = registryData.registrant || {};
    const audit = record.audit || {};

    // We calculate the domain age if there is a creation date
    let domainAgeDays = null;
    if (registryData.createdDate) {
      domainAgeDays = Math.floor((Date.now() - new Date(registryData.createdDate)) / (1000 * 60 * 60 * 24));
    }

    const report = {
      provider: "WhoisXMLAPI",
      domain,
      success: true,
      createdDate: registryData.createdDate || null,
      updatedDate: registryData.updatedDate || null,
      expiresDate: registryData.expiresDate || null,
      registrarName: registryData.registrarName || null,
      registrantOrganization: registrant.organization || null,
      registrantCountry: registrant.country || null,
      registrantEmail: registrant.email || null,
      domainAgeDays,
      // Useful field for ML: if the domain expires very soon it may be suspicious
      daysUntilExpiration: registryData.expiresDate
        ? Math.floor((new Date(registryData.expiresDate) - Date.now()) / (1000 * 60 * 60 * 24))
        : null,
      raw: record
    };

    return report;

  } catch (err) {
    console.error("[Whois] Error:", err);
    return {
      provider: "WhoisXMLAPI",
      domain,
      success: false,
      error: err.message
    };
  }
}

