// ===============================================================
// Module: Feature Extractor (ADAPTADO PARA RED NEURONAL)
// ===============================================================

function extractFeaturesForModel(url, structural, ssl, whoisfreaks, safebrowsing) {
    // 1. Referencias seguras (Manejo de nulos)
    const s = structural || {};
    const sl = ssl || {};
    
    // Lógica para detectar si whoisfreaks viene anidado o directo
    const who = (whoisfreaks && whoisfreaks.whois) ? whoisfreaks.whois : (whoisfreaks || {});
    const sb = safebrowsing || {};

    // 2. Helpers para conversión numérica (IMPORTANTE: Deben coincidir con Python)
    
    // Convierte fechas a Timestamp (segundos). Si no existe, devuelve 0 (como tu fillna(0) de Python)
    const parseDate = (dateStr) => {
        if (!dateStr) return 0;
        const ts = Math.floor(new Date(dateStr).getTime() / 1000);
        return isNaN(ts) ? 0 : ts;
    };
    
    // Convierte booleanos a 1 o 0
    const toInt = (val) => val ? 1 : 0;
    
    // Obtiene longitud de array seguro
    const getLen = (arr) => Array.isArray(arr) ? arr.length : 0;

    // 3. ARRAY ORDENADO EXACTAMENTE COMO EN PYTHON
    // La Red Neuronal es ciega a los nombres, solo le importa la posición.
    // Orden basado en tu lista: ['struct_domainCount', 'struct_similarityScore', ...]

    const featuresArray = [
        // --- Structural ---
        s.domainCount || 0,                 // struct_domainCount
        s.similarityScore || 0.0,           // struct_similarityScore
        toInt(s.isIP),                      // struct_isIP
        toInt(s.hasPunycode),               // struct_hasPunycode
        s.subdomainCount || 0,              // struct_subdomainCount
        toInt(s.hasLoginTokens),            // struct_hasLoginTokens
        toInt(s.hasAtSymbol),               // struct_hasAtSymbol
        s.length || url.length,             // struct_length (Fallback al largo de URL si falla struct)
        s.paramCount || 0,                  // struct_paramCount
        toInt(s.hasEncodedChars),           // struct_hasEncodedChars
        s.encodedCount || 0,                // struct_encodedCount
        toInt(s.isShortener),               // struct_isShortener
        toInt(s.customPort),                // struct_customPort
        toInt(s.usesHttps),                 // struct_usesHttps
        getLen(s.suspiciousParams),         // struct_suspiciousParams_count

        // --- SSL ---
        parseDate(sl.valid_from),           // ssl_valid_from_ts
        parseDate(sl.valid_to),             // ssl_valid_to_ts
        sl.certAgeDays || 0,                // ssl_certAgeDays
        sl.daysUntilExpiration || 0,        // ssl_daysUntilExpiration

        // --- Safe Browsing ---
        toInt(sb.malicious),                // sb_malicious
        sb.threatCount || 0,                // sb_threatCount
        getLen(sb.threats),                 // sb_threats_count

        // --- Whois ---
        parseDate(who.created),             // whois_created_ts
        parseDate(who.updated),             // whois_updated_ts
        parseDate(who.expires),             // whois_expires_ts
        who.domain_age_days || 0,           // whois_domain_age_days
        who.days_until_expiration || 0      // whois_days_until_expiration
    ];

    // Devolvemos el Array, no el Objeto
    return featuresArray;
}

export { extractFeaturesForModel };