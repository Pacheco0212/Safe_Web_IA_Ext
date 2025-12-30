
import { getApiKeys } from "../utils/storage_utils.js";

const WHOISFREAKS_URL = "https://api.whoisfreaks.com/v1.0/ssl/live";

// ===========================================================
// 1. Helpers de Fechas
// ===========================================================

/**
 * Intenta convertir varios formatos de fecha a un objeto Date de JS.
 * Retorna null si falla.
 */
function parseSafeDate(dateStr) {
    if (!dateStr) return null;

    // Limpieza básica: Eliminar " UTC" si existe
    let cleanStr = dateStr.replace(" UTC", "").trim();

    // Intento 1: Constructor estándar de JS (maneja ISO y muchos formatos comunes)
    let dateObj = new Date(cleanStr);
    
    // Si es inválido (NaN), intentamos arreglar el formato "YYYY-M-D" a "YYYY-MM-DD"
    if (isNaN(dateObj.getTime())) {
        // Regex para detectar fechas tipo 2025-9-3 y convertirlas a 2025-09-03
        // Esto replica la lógica de zfill de Python
        const parts = cleanStr.split(" ");
        const datePart = parts[0];
        const timePart = parts.length > 1 ? parts[1] : "00:00:00";

        const ymd = datePart.split("-");
        if (ymd.length === 3) {
            const y = ymd[0];
            const m = ymd[1].padStart(2, '0');
            const d = ymd[2].padStart(2, '0');
            
            // Reintentar con formato ISO estricto
            dateObj = new Date(`${y}-${m}-${d}T${timePart}Z`);
        }
    }

    // Verificar de nuevo
    if (!isNaN(dateObj.getTime())) {
        return dateObj;
    }

    return null;
}

/**
 * Calcula la diferencia en días entre dos fechas.
 */
function getDaysDifference(date1, date2) {
    if (!date1 || !date2) return null;
    const diffTime = date2 - date1; 
    // Convertir milisegundos a días (1000ms * 60s * 60m * 24h)
    return Math.floor(diffTime / (1000 * 60 * 60 * 24));
}

// ===========================================================
// 2. Consulta API
// ===========================================================

async function getSslInfo(domain) {
    /* Consulta la API de WhoisFreaks y devuelve el JSON completo. */
    const { whoisfreaks } = await getApiKeys();

    if (!whoisfreaks) {
        return { error: "No se encontró la API Key de WhoisFreaks" };
    }

    const params = new URLSearchParams({
        apiKey: whoisfreaks,
        domainName: domain
    });

    try {
        // Timeout simulado con AbortController (20 segundos)
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 20000);

        const response = await fetch(`${WHOISFREAKS_URL}?${params.toString()}`, {
            method: 'GET',
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        return await response.json();

    } catch (error) {
        const errorMsg = error.name === 'AbortError' ? 'Timeout excedido' : error.message;
        return { error: `Error al consultar WhoisFreaks: ${errorMsg}` };
    }
}

function normalizeSslReport(fullJson, domain) {
    /* Convierte el JSON de WhoisFreaks a un reporte conciso. */
    try {
        // sslCertificates SIEMPRE es una lista en la respuesta exitosa
        const certs = fullJson.sslCertificates || [];

        // Usar el primer certificado si existe
        const cert = (Array.isArray(certs) && certs.length > 0) ? certs[0] : {};

        // ----- Parseo de fechas -----
        const validFromStr = cert.validityStartDate;
        const validToStr = cert.validityEndDate;

        const created = parseSafeDate(validFromStr);
        const expires = parseSafeDate(validToStr);
        const now = new Date();

        // ----- Edad del certificado -----
        // certAgeDays: (Hoy - Creado)
        const certAgeDays = created ? getDaysDifference(created, now) : null;
        
        // daysUntilExpiration: (Expira - Hoy)
        const daysUntilExpiration = expires ? getDaysDifference(now, expires) : null;

        // Uso de Optional Chaining (?.) para evitar errores si faltan campos
        const concise = {
            domain: domain,
            authenticationType: cert.authenticationType,
            subject_org: cert.subject?.organization,
            issuer_org: cert.issuer?.organization,
            subjectKeyIdentifier: cert.extensions?.subjectKeyIdentifier,
            authorityKeyIdentifier: cert.extensions?.authorityKeyIdentifier,
            valid_from: validFromStr,
            valid_to: validToStr,
            certAgeDays: certAgeDays,
            daysUntilExpiration: daysUntilExpiration,
            signature_algorithm: cert.signatureAlgorithm
        };

        return concise;

    } catch (e) {
        return { error: `Error normalizando reporte SSL: ${e.message}` };
    }
}

// ===========================================================
// 3. Función principal
// ===========================================================

async function scanSsl(domain, save = true, debug = false) {
    /* Obtiene el reporte SSL completo y el conciso. */

    const fullReport = await getSslInfo(domain);

    if (debug) {
        console.log("\n[SSL] Reporte COMPLETO WHOISFREAKS:\n", JSON.stringify(fullReport, null, 4));
    }

    // Normalizar
    const concise = normalizeSslReport(fullReport, domain);

    return concise;
}

export { scanSsl, getSslInfo, normalizeSslReport };