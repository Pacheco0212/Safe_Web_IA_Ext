// ===============================================================
// Module: Whois API client (WhoisFreaks)
// ===============================================================
// Description:
//  This module provides a function to analyze domain WHOIS information
// ===============================================================

import { getApiKeys } from "../service_worker.js";

// const WHOIS_FREAKS_API_KEY = "5548cb282ae44a8590f13ad0c87fa287";
const WHOIS_FREAKS_API_URL = "https://api.whoisfreaks.com/v1.0/whois";

export async function analyzeWhoisFreaks(domain, debug) {
  const { whoisfreaks } = await getApiKeys();
  const url = `${WHOIS_FREAKS_API_URL}?apiKey=${whoisfreaks}&whois=live&domainName=${encodeURIComponent(domain)}`;

  try {
    const response = await fetch(url);
    if (!response.ok) {
      const txt = await response.text();
      throw new Error(`[WhoisFreaks] HTTP ${response.status} ${response.statusText}: ${txt}`);
    }

    const data = await response.json();
    if(debug) console.log("[WhoisFreaks] Raw data:", data);
    if (data.error) throw new Error(`[WhoisFreaks] API Error: ${data.error}`);

    // Helper para fechas seguras
    const parseDate = (dateStr) => {
      if (!dateStr) return null;
      const parsed = Date.parse(dateStr);
      return isNaN(parsed) ? null : new Date(parsed);
    };

    // Los nombres reales de las propiedades
    const created = parseDate(data.create_date);
    const updated = parseDate(data.update_date);
    const expires = parseDate(data.expiry_date);

    const registrarName = data.domain_registrar.registrar_name || null;
    const registrant = data.registrant_contact || {};

    // Cálculo correcto de edad y expiración
    const domainAgeDays = created
      ? Math.floor((Date.now() - created.getTime()) / (1000 * 60 * 60 * 24))
      : null;

    const daysUntilExpiration = expires
      ? Math.floor((expires.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
      : null;

    const report = {
      provider: "WhoisFreaks",
      domain,
      success: true,
      createdDate: created ? created.toISOString() : null,
      updatedDate: updated ? updated.toISOString() : null,
      expiresDate: expires ? expires.toISOString() : null,
      registrarName,
      registrantOrganization:
        registrant.company || null,
      domainAgeDays,
      daysUntilExpiration,
      raw: data
    };

    return report;

  } catch (err) {
    console.error("[WhoisFreaks] Error:", err);
    return {
      provider: "WhoisFreaks",
      domain,
      success: false,
      error: err.message
    };
  }
}