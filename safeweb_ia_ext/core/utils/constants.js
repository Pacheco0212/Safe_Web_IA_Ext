export const SUSPICIOUS_TLDS = new Set([
  // Phishing
  "gq", "cf", "tk", "lol", "party", "autos", "live", "support", "monster", "top",
  "cyou", "cfd", "buzz", "rest", "ga", "quest", "site", "club", "biz", "pw", "ru",
  "su", "help", "xin", "bond",
  // Malware
  "pics", "today", "life", "online", "space", "link", "click", "icu", "xyz",
  // Spam
  "tokyo", "ws", "best", "wiki", "cn", "media", "ng", "cc", "beauty",
  "loan", "ml", "work", "country", "zip", "cricket", "kim", "info", "win",
  "date", "review", "science", "men", "surf", "cam", "mov", "nexus", "foo",
  "phd", "prof", "dad", "esq", "press", "stream", "download", "host"
]);

export const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly",
  "adf.ly", "cutt.ly", "rb.gy", "shorte.st", "rebrand.ly", "shorturl.at",
  "tiny.cc", "soo.gd", "short.cm", "v.gd", "qr.ae", "x.co", "po.st",
  "yourls.org", "lnkd.in", "db.tt", "1drv.ms", "s.id", "chilp.it"
]);

export const LOGIN_KEYWORDS = [
  // Login / cuenta
  "login", "log-in", "log_in",
  "signin", "sign-in", "sign_in",
  "signup", "sign-up", "sign_up",
  "account", "myaccount", "mi-cuenta", "mi_cuenta", "micuenta",
  "profile", "user", "usuario",
  // Verificación / seguridad
  "verify", "verification", "verified",
  "secure", "security", "2fa", "mfa", "otp",
  "auth", "authentication", "authorize",
  "verificar", "verificacion", "seguro", "seguridad",
  // Contraseñas / accesos
  "password", "passwd", "passcode", "reset-password",
  "resetpassword", "forgot-password", "forgotpassword",
  "change-password", "changepassword",
  "contrasena", "contraseña", "restablecer-contrasena",
  "restablecer_contrasena", "cambiar-contrasena",
  // Suspensiones / alertas / urgencia
  "alert", "warning", "urgent", "suspend", "suspended",
  "locked", "lock", "blocked", "restriction", "restricted",
  "suspendido", "bloqueado", "bloqueada", "bloqueo",
  "actualizar-ahora", "actualiza-tu-cuenta",
  // Actualización de datos / pagos
  "update", "update-info", "update-payment", "updatebilling",
  "billing", "payment", "pago", "pagos", "metodo-pago",
  "factura", "invoice", "billing-info", "billing-update",
  // Banca / dinero
  "bank", "banking", "onlinebanking",
  "banco", "banca-en-linea", "banca_linea",
  "transfer", "wire", "deposit", "withdraw",
  "loan", "credit", "credito", "tarjeta",
  "wallet", "cryptowallet", "crypto", "metamask",
  // Documentos / firmas / trámites
  "document", "documents", "docu", "docusign",
  "signature", "sign-document", "firmar", "firma",
  "contrato", "contract", "novedad", "notif", "notification",
  // Confirmación / continuación
  "confirm", "confirmation", "confirm-email",
  "confirmaccount", "confirmar", "confirmacion",
  "continue", "next", "proceed", "continuar",
  // Accesos frecuentes a servicios cloud
  "portal", "sso", "single-sign-on",
  "office365", "o365", "onedrive", "sharepoint",
  "workspace", "webmail", "correo", "correo-web"
];

export const COMMON_BRANDS = [
  // Big Tech / buscadores / correo
  "google", "gmail", "youtube", "android", "apple", "icloud",
  "microsoft", "office", "outlook", "live", "hotmail",
  "yahoo", "aol", "protonmail", "zoho",
  // Redes sociales / mensajería
  "facebook", "instagram", "whatsapp", "messenger", "tiktok",
  "snapchat", "x", "twitter", "reddit", "pinterest",
  "discord", "telegram", "wechat", "line",
  // Productividad / nube / colab
  "zoom", "slack", "dropbox", "box", "onedrive", "sharepoint",
  "teams", "skype", "webex", "gotomeeting", "notion",
  "asana", "trello", "jira",
  // E-commerce global
  "amazon", "alibaba", "aliexpress", "ebay", "rakuten", "shopify",
  "etsy", "walmart", "costco", "bestbuy",
  // E-commerce / servicios en México y Latam
  "mercadolibre", "mercadopago", "amazonmexico", "amazon.com.mx",
  "coppel", "liverpool", "elektra", "soriana", "chedraui",
  "bodegaaurrera",
  // Bancos y pagos globales
  "paypal", "stripe", "visa", "mastercard", "americanexpress",
  "skrill", "revolut", "wise", "cashapp",
  // Bancos México / España / Latam
  "bbva", "bbvabancomer", "santander", "banorte", "banamex",
  "citibanamex", "hsbc", "scotiabank", "inbursa",
  "bancoazteca", "hsbcmx",
  // Bancos Estados Unidos / internacionales
  "bankofamerica", "wellsfargo", "chase", "citibank",
  "capitalone", "pnc", "usbank", "barclays", "natwest",
  "lloyds", "rbc", "tdbank",
  // Gobierno / impuestos / salud
  "irs", "socialsecurity", "ssa", "gob", "gobmx",
  "imss", "sat", "segurosocial", "segob",
  // Servicios cloud / dev
  "github", "gitlab", "bitbucket", "git",
  "aws", "amazonaws", "azure", "cloudflare", "digitalocean",
  "heroku", "vercel", "netlify", "firebase",
  // Streaming / entretenimiento
  "netflix", "disneyplus", "disney", "hbo", "hbomax",
  "primevideo", "spotify", "deezer", "twitch",
  // Cripto / exchanges
  "binance", "coinbase", "kraken", "bitso", "bitfinex",
  "bitmex", "okx", "bybit", "metamask", "trustwallet",
  // Otros
  "wikipedia", "chatgpt", "openai", "wordpress", "blogspot",
  "medium", "canva", "adobe", "docusign", "salesforce",
  "zendesk", "godaddy", "namecheap"
];

export const REDIRECT_KEYWORDS = new Set([
  "redirect", "redir", "redir_url", "redirect_url",
  "redirect_uri", "returnUrl", "returnurl", "return_url",
  "next", "next_url", "nexturl",
  "url", "u",
  "dest", "destination", "dest_url", "destination_url",
  "target", "target_url",
  "out", "goto", "go",
  "callback", "cb",
  "view", "link",
  "to",
  "forward",
  // variantes comunes
  "rurl", "return_to", "return_to_url",
  "continue", "cont",
  "return", "redir_to", "redirect_to"
]);