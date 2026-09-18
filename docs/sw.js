/* Service Worker des Vuln-Trainers – Offline-Betrieb.
   Beim Installieren werden App-Shell und die drei Datendateien vorab gecacht.
   Danach gilt Stale-While-Revalidate: sofort aus dem Cache antworten (startet
   auch ohne Netz), im Hintergrund die frische Version holen und für den
   nächsten Start ablegen. Ein Deploy ist also ab dem zweiten Öffnen sichtbar.
   CACHE nur hochzählen, wenn sich die PRECACHE-Liste ändert.
   Der Worker fasst localStorage nicht an – der Lernfortschritt bleibt unberührt. */
const CACHE = 'vt-v2';
const PRECACHE = [
  './', 'index.html', 'style.css', 'cvss31.js', 'sr.js', 'app.js', 'manifest.json',
  'icons/icon-192.png', 'icons/icon-512.png', 'icons/icon-maskable-512.png', 'icons/apple-touch-icon.png',
  'data/cves.json', 'data/classes.json', 'data/meta.json',
];

self.addEventListener('install', (e) => {
  // no-cache: jede Datei beim Server revalidieren. Sonst kann addAll veraltete Kopien
  // aus dem HTTP-Cache mischen (neue app.js + alte sr.js). Unveränderte Dateien kosten nur ein 304.
  e.waitUntil(caches.open(CACHE)
    .then((c) => c.addAll(PRECACHE.map((u) => new Request(u, { cache: 'no-cache' }))))
    .then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith('vt-') && k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;   // externe Referenz-Links nicht anfassen

  e.respondWith((async () => {
    const cache = await caches.open(CACHE);
    let cached = await cache.match(req, { ignoreSearch: true });
    if (!cached && req.mode === 'navigate') cached = await cache.match('index.html');

    const refresh = fetch(url.href, { cache: 'no-cache', credentials: 'same-origin' })
      .then(async (res) => {
        if (res && res.ok) {
          const same = cached && res.headers.get('etag') && res.headers.get('etag') === cached.headers.get('etag');
          if (!same) await cache.put(req, res.clone());
        }
        return res;
      })
      .catch(() => undefined);

    if (cached) { e.waitUntil(refresh); return cached; }
    const res = await refresh;
    return res || new Response('Offline und noch nicht im Cache.', {
      status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    });
  })());
});
