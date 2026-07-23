// Service Worker minimo de KERPLUS.
// Objetivo unico: que la app sea instalable como PWA real (requisito de
// PWABuilder para generar el APK) y que la pantalla de login cargue aunque
// no haya señal por un instante. NUNCA cachea /api/* -- los datos del
// negocio (contratos, comisiones, nomina, etc.) siempre deben venir
// frescos del servidor, jamas de una copia vieja guardada en el celular.
const CACHE = 'kerplus-shell-v1';
const SHELL = ['/', '/manifest.json', '/img/icon-192.png', '/img/icon-512.png'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((nombres) =>
      Promise.all(nombres.filter((n) => n !== CACHE).map((n) => caches.delete(n)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Nunca interceptar la API: los datos del sistema siempre deben ser en vivo.
  if (url.pathname.startsWith('/api/')) return;

  // Solo GET tiene sentido cachear/servir desde cache.
  if (event.request.method !== 'GET') return;

  event.respondWith(
    fetch(event.request)
      .then((resp) => {
        const copia = resp.clone();
        caches.open(CACHE).then((cache) => cache.put(event.request, copia));
        return resp;
      })
      .catch(() => caches.match(event.request).then((r) => r || caches.match('/')))
  );
});
