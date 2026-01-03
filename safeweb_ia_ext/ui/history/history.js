import { getCaptures } from "../../core/utils/storage_utils.js";

document.addEventListener('DOMContentLoaded', async () => {
    const captures = await getCaptures();
    const tbody = document.querySelector('#history-table tbody');

    // Limpiar tabla
    tbody.innerHTML = '';

    // Ordenar: más reciente primero
    captures.sort((a, b) => b.ts - a.ts);

    captures.forEach((entry, index) => { 
        
        // --- 1. EXTRACCIÓN ROBUSTA DE DATOS ---
        const analysis = entry.analysis || {};
        const ai = analysis.ai_analysis || {};
        const details = analysis.details || analysis; 
        
        const ssl = details.ssl || details.sslAnalysis || details.sslData || {};
        const struct = details.structural || details.structuralAnalysis || details.structData || {};
        const whois = details.whois || details.whoisfreaks || details.whoisData || {}; 
        const sb = details.safebrowsing || details.sbData || {};

        // --- 2. DATOS PRINCIPALES ---
        const date = new Date(entry.ts).toLocaleString();
        const verdict = ai.verdict || 'PENDING';
        const probability = ai.probability || 0;
        const percentage = (probability * 100).toFixed(2);

        // Clases para colores
        let badgeClass = 'badge-safe';
        if (['PELIGROSO', 'DANGEROUS', 'MALICIOUS'].includes(verdict)) {
            badgeClass = 'badge-dangerous';
        } else if (['SOSPECHOSO', 'SUSPICIOUS'].includes(verdict)) {
            badgeClass = 'badge-suspicious';
        }

        // --- 3. FILA PRINCIPAL (VISIBLE) ---
        const rowMain = document.createElement('tr');
        rowMain.className = 'main-row';
        rowMain.innerHTML = `
            <td>${date}</td>
            <td class="url-col" title="${entry.url}">
                <a href="${entry.url}" target="_blank" style="text-decoration:none; color:#333;">
                    ${entry.url}
                </a>
            </td>
            <td><span class="badge ${badgeClass}">${verdict}</span></td>
            <td>${percentage}%</td>
            <td style="text-align: center;">
                <button class="btn-toggle" id="btn-${index}" title="Ver vector de características">+</button>
            </td>
        `;

        // --- 4. PREPARACIÓN DE VALORES ---
        const bool = (val) => val ? '<span style="color:#d32f2f; font-weight:bold;">SÍ</span>' : '<span style="color:#2e7d32;">No</span>';
        const bool2 = (val) => val ? '<span style="color:#2e7d32; font-weight:bold;">SÍ</span>' : '<span style="color:#d32f2f;">No</span>';
        
        const validFrom = ssl.valid_from ? new Date(ssl.valid_from).toLocaleDateString() : '-';
        const validTo = ssl.valid_to ? new Date(ssl.valid_to).toLocaleDateString() : '-';
        const createdDate = whois.created ? new Date(whois.created).toLocaleDateString() : '-';
        const expiresDate = whois.expires ? new Date(whois.expires).toLocaleDateString() : '-';
        const updatedDate = whois.updated ? new Date(whois.updated).toLocaleDateString() : '-';

        const suspiciousParamsCount = Array.isArray(struct.suspiciousParams) ? struct.suspiciousParams.length : 0;
        const threatsCount = Array.isArray(sb.threats) ? sb.threats.length : (sb.threatCount || 0);

        // --- 5. FILA DE DETALLES (DISTRIBUCIÓN EQUILIBRADA) ---
        const rowDetails = document.createElement('tr');
        rowDetails.className = 'details-row';
        rowDetails.id = `detail-${index}`;
        
        rowDetails.innerHTML = `
            <td colspan="5">
                <div class="details-container">
                    
                    <div class="detail-box">
                        <h4>🏗️ Métricas de URL</h4>
                        <div class="detail-item"><span class="detail-label">Longitud URL:</span> <span class="detail-val">${struct.length || 0} chars</span></div>
                        <div class="detail-item"><span class="detail-label">Subdominios:</span> <span class="detail-val">${struct.subdomainCount || 0}</span></div>
                        <div class="detail-item"><span class="detail-label">Dominios en Path:</span> <span class="detail-val">${struct.domainCount || 0}</span></div>
                        <div class="detail-item"><span class="detail-label">Parámetros:</span> <span class="detail-val">${struct.paramCount || 0}</span></div>
                        <div class="detail-item"><span class="detail-label">Params Sospechosos:</span> <span class="detail-val">${suspiciousParamsCount}</span></div>
                        <div class="detail-item"><span class="detail-label">Chars Codificados:</span> <span class="detail-val">${struct.encodedCount || 0} (${bool(struct.hasEncodedChars)})</span></div>
                        <div class="detail-item"><span class="detail-label">¿Usa HTTPS?:</span> <span class="detail-val">${bool2(struct.usesHttps)}</span></div>
                    </div>

                    <div class="detail-box">
                        <h4>⚠️ Anomalías Detectadas</h4>
                        <div class="detail-item"><span class="detail-label">¿Es IP?:</span> <span class="detail-val">${bool(struct.isIP)}</span></div>
                        <div class="detail-item"><span class="detail-label">¿Tiene @?:</span> <span class="detail-val">${bool(struct.hasAtSymbol)}</span></div>
                        <div class="detail-item"><span class="detail-label">¿Punycode?:</span> <span class="detail-val">${bool(struct.hasPunycode)}</span></div>
                        <div class="detail-item"><span class="detail-label">¿Tokens Login?:</span> <span class="detail-val">${bool(struct.hasLoginTokens)}</span></div>
                        <div class="detail-item"><span class="detail-label">¿Acortador?:</span> <span class="detail-val">${bool(struct.isShortener)}</span></div>
                        <div class="detail-item"><span class="detail-label">Puerto Raro:</span> <span class="detail-val">${bool(struct.customPort)}</span></div>
                        <div class="detail-item"><span class="detail-label">Similitud Marca:</span> <span class="detail-val">${(struct.similarityScore || 0).toFixed(2)}</span></div>
                    </div>

                    <div class="detail-box">
                        <h4>🔒 Identidad (SSL/Whois)</h4>
                        <div class="detail-item"><span class="detail-label">Emisor SSL:</span> <span class="detail-val">${ssl.issuer_org || 'N/A'}</span></div>
                        <div class="detail-item"><span class="detail-label">Válido desde:</span> <span class="detail-val">${validFrom}</span></div>
                        <div class="detail-item"><span class="detail-label">Válido hasta:</span> <span class="detail-val">${validTo}</span></div>
                        <div class="detail-item"><span class="detail-label">Antigüedad Cert.:</span> <span class="detail-val">${ssl.certAgeDays || 0} días</span></div>
                        <div class="detail-item"><span class="detail-label">Expira SSL en:</span> <span class="detail-val">${ssl.daysUntilExpiration || 0} días</span></div>
                        <div class="detail-item"><span class="detail-label">Registrador:</span> <span class="detail-val">${whois.registrar_name || 'Desconocido'}</span></div>
                        <div class="detail-item"><span class="detail-label">Edad Dominio:</span> <span class="detail-val">${whois.domain_age_days || 0} días</span></div>
                    </div>

                     <div class="detail-box">
                        <h4>🛡️ Dominio y Detección</h4>
                        <div class="detail-item"><span class="detail-label">Creado:</span> <span class="detail-val">${createdDate}</span></div>
                        <div class="detail-item"><span class="detail-label">Actualizado:</span> <span class="detail-val">${updatedDate}</span></div>
                        <div class="detail-item"><span class="detail-label">Expira:</span> <span class="detail-val">${expiresDate}</span></div>
                        <div class="detail-item"><span class="detail-label">Expira Dom. en:</span> <span class="detail-val">${whois.days_until_expiration || 0} días</span></div>
                        <hr style="border-top:1px solid #eee; margin:5px 0;">
                        <div class="detail-item"><span class="detail-label">SafeBrowsing:</span> <span class="detail-val">${bool(sb.malicious)}</span></div>
                        <div class="detail-item"><span class="detail-label">Amenazas (SB):</span> <span class="detail-val">${threatsCount}</span></div>
                        <div class="detail-item"><span class="detail-label"><strong>Probabilidad:</strong></span> <span class="detail-val">${Number(probability).toFixed(6)}</span></div>
                        <div class="detail-item"><span class="detail-label">Modelo:</span> <span class="detail-val">TensorFlow (v13)</span></div>
                    </div>

                </div>
            </td>
        `;

        // --- 6. EVENTO TOGGLE ---
        const btn = rowMain.querySelector(`#btn-${index}`);
        btn.addEventListener('click', () => {
            const isHidden = getComputedStyle(rowDetails).display === 'none';
            if (isHidden) {
                rowDetails.classList.add('show');
                btn.classList.add('open');
                btn.textContent = '×';
            } else {
                rowDetails.classList.remove('show');
                btn.classList.remove('open');
                btn.textContent = '+';
            }
        });

        tbody.appendChild(rowMain);
        tbody.appendChild(rowDetails);
    });
});