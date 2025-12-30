import { getCaptures } from "../../core/utils/storage_utils.js";

document.addEventListener('DOMContentLoaded', async () => {
    const captures = await getCaptures();
    const tbody = document.querySelector('#history-table tbody');

    // Limpiar tabla
    tbody.innerHTML = '';

    // Ordenar: más reciente primero
    captures.sort((a, b) => b.ts - a.ts);

    captures.forEach(entry => {
        const row = document.createElement('tr');
        
        const date = new Date(entry.ts).toLocaleString();
        
        // Datos de la IA (Manejo de errores si no hay análisis)
        const verdict = entry.analysis?.ai_analysis?.verdict || 'PENDING';
        const probability = entry.analysis?.ai_analysis?.probability || '0';
        const percentage = (probability * 100).toFixed(2);

        // Clases para colores
        let badgeClass = 'badge-safe';
        if (verdict === 'PELIGROSO' || verdict === 'DANGEROUS') {
            badgeClass = 'badge-dangerous';
        } else if (verdict === 'SOSPECHOSO' || verdict === 'SUSPICIOUS') {
            badgeClass = 'badge-suspicious';
        }
        row.innerHTML = `
            <td>${date}</td>
            <td class="url-col" title="${entry.url}">
                <a href="${entry.url}" target="_blank" style="text-decoration:none; color:#333;">
                    ${entry.url}
                </a>
            </td>
            <td><span class="badge ${badgeClass}">${verdict}</span></td>
            <td>${percentage}%</td>
        `;
        tbody.appendChild(row);
    });
});