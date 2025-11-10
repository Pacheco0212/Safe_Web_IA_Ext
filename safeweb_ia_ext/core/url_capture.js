
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

  // --- dominios que pueden tener paginas de busqueda ---
  const SEARCH_HOSTS = new Set([
  'google.com','www.google.com',
  'bing.com','www.bing.com',
  'duckduckgo.com','www.duckduckgo.com',
  'search.yahoo.com','yahoo.com'
  ]);


  //Funcion para validar que la url sea http/https. Filtramos urls con incial chrome://, file://, edge://, etc.
  function isHttp(u) {
    try { 
      const x = new URL(u); 
      return x.protocol === 'http:' || x.protocol === 'https:'; 
    } catch { 
      return false; 
    }
  }

  
  //Funcion para detectar si es una pagina de busqueda ("/search?")
  function esPaginaDeBusqueda(u) {
  try {
    const x = new URL(u);

    const h = x.hostname;
    const p = x.pathname;

    if (!SEARCH_HOSTS.has(h)) 
      return false;

    if (h.includes('google')) {
      if (p === '/search' || p === '/url') 
        return true; // SRP y redirector
    }

    if (h.includes('bing')) {
      if (p === '/search' || p === '/s' || p.startsWith('/images/search')) 
        return true;
    }

    if (h.includes('duckduckgo')) {
      if ((p === '/' || p === '/html/') && x.searchParams.has('q')) 
        return true;
    }

    if (h.includes('yahoo')) {
      if (p.startsWith('/search')) 
        return true;
    }

    return false;
  
   } catch {
      return true; 
    } // si no parsea, mejor no capturar
 }


  //Funcion que lee la pestaña por id y, si está activa y su URL es válida, dispara un callback.
  async function handle(tabId) {
    if (!tabId) 
    return;

      try {
          // Se obtiene la pestaña activa con sus respetivas validaciones
          const tab = await chrome.tabs.get(tabId);
          if (!tab?.active || !tab.url || !isHttp(tab.url)) 
            return;

          // Ignora url de resultados de búsqueda/redirecciones de buscadores
          if (esPaginaDeBusqueda(tab.url)) 
          return;

          // URL completa y dominio principal
          const fullUrl = tab.url;
          const origin  = new URL(tab.url).origin;

          // Dispara el callback hacia el service worker
          onCapture?.({ url: origin, fullUrl, tabId, title: tab.title ?? "" });
          } catch (e) {
          // Silenciamos errores típicos: pestaña cerrada entre la consulta y la lectura, etc.
          }
  }


  //Listeners o casos que implican un callback (funcion handle)
  
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
