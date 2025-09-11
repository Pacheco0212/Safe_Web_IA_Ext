/**
 Responsabilidad: Leer del storage y mostrar el historial de capturas.
 No registra listeners del navegador (eso es del SW).
 */

const STORAGE_KEY = 'captures';
const listEl = document.getElementById('list');

/** Dibuja la lista en el DOM */
function render(items=[]) {
  listEl.innerHTML = '';
  for (const it of items) {
    const li = document.createElement('li');
    const a = document.createElement('a');
    a.href = it.url; a.textContent = it.title ? `${it.title} — ${it.url}` : it.url; a.target = '_blank';
    const meta = document.createElement('div');
    meta.style.opacity = '0.7';
    meta.textContent = new Date(it.ts).toLocaleString();
    li.appendChild(a); li.appendChild(meta);
    listEl.appendChild(li);
  }
}

/** Borra historial + limpia badge */
async function refresh() {
  const { [STORAGE_KEY]: items = [] } = await chrome.storage.local.get(STORAGE_KEY);
  render(items);
}

document.getElementById('clear').addEventListener('click', async () => {
  await chrome.storage.local.set({ [STORAGE_KEY]: [] });
  render([]);
  chrome.action.setBadgeText({ text: '' });
});

/** Recibe avisos del SW para refrescar en caliente */
chrome.runtime.onMessage.addListener((m) => {
  if (m?.type === 'NEW_CAPTURE') refresh();
});

refresh();
