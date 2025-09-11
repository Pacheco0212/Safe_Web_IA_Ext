
/**
 * MÓDULO: Captura de URL de la pestaña activa (MV3)
 * -----------------------------------------------
 * Responsabilidad: Registrar listeners del navegador y, cada vez que la URL
 * de la pestaña ACTIVA cambie (o cambie la pestaña activa / ventana),
 * invocar un callback con { url, tabId, title }.
 *
 * PERMISOS necesarios declarados en el manifest:
 *   - "tabs" (obligatorio)
 *   - "webNavigation" se usa en el SW, aquí no indispensable)
 */



export function initCapture(onCapture) {

  //Validamos que la url sea http/https. Pero filtramos las que no son capturables como chrome://, file://, edge://, etc.
  function isHttp(u) {
     try { 
        const x = new URL(u); 
        return /^https?:$/.test(x.protocol); 
      
      } catch { 
        return false; 
      }
  }

  //Lee la pestaña por id y, si está activa y su URL es válida, dispara un callback.

  async function handle(tabId) {
    if (!tabId) return;

      try {
        // Se obtiene la pestaña
        const tab = await chrome.tabs.get(tabId);
        if (!tab?.active || !tab.url || !isHttp(tab.url)) return;

        // Dispara el callback hacia el service worker
        onCapture?.({ url: tab.url, tabId, title: tab.title ?? "" });
      } catch (e) {
          // Silenciamos errores típicos: pestaña cerrada entre la consulta y la lectura, etc.
        }
  }

  //Listeners o casos que implican un callback

  // 1) Cambias de pestaña activa dentro de la misma ventana de google.
  chrome.tabs.onActivated.addListener(({ tabId }) => handle(tabId));

  // 2) Cambia la URL en la misma pestaña activa
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (tab?.active && changeInfo.url) handle(tabId);
  });

  // 3) Útil si tienes varias ventanas de Chrome y saltas entre ellas.
  chrome.windows?.onFocusChanged?.addListener(async (windowId) => {
    if (windowId === chrome.windows.WINDOW_ID_NONE) return;
    const [tab] = await chrome.tabs.query({ active: true, windowId });
    if (tab?.id) handle(tab.id);
  });

  // API pública del módulo: función para “forzar” una captura  de la pestaña activa del usuario.
  return {
    async captureActiveNow() {
      const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
      if (tab?.id) await handle(tab.id);
    }
  };
}
