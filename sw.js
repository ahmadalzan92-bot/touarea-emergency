/* خدمة العمل دون اتصال + التحديث السحابي — طوارئ 2026
   لتفعيل تحديث جديد: غيّر CACHE_VERSION وversion.json وAPP_VERSION داخل Test_V22.html */
const CACHE_VERSION = 'touarea-2026.10.09.13';
const RUNTIME = CACHE_VERSION + '-runtime';

const CORE_ASSETS = [
  './',
  './Test_V22.html',
  './version.json',
  './manifest.webmanifest',
  './logo-web.png'
];

const CDN_ASSETS = [
  'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.rtl.min.css',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css',
  'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js',
  'https://cdn.jsdelivr.net/npm/xlsx-js-style@1.2.0/dist/xlsx.bundle.js',
  'https://fonts.googleapis.com/css2?family=Cairo:wght@400;500;600;700;800&display=swap',
  'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css',
  'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js'
];

const SKIP_HOSTS = ['workers.dev', 'arcgisonline.com', 'openstreetmap.org'];

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_VERSION);
    await Promise.all(CORE_ASSETS.map(async (url) => {
      try {
        const res = await fetch(new Request(url, { cache: 'reload', credentials: 'same-origin' }));
        if (res && res.ok) await cache.put(url, res.clone());
      } catch (e) { /* تجاهل */ }
    }));
    await Promise.all(CDN_ASSETS.map(async (url) => {
      try {
        const res = await fetch(url, { mode: 'no-cors', cache: 'reload' });
        if (res) await cache.put(url, res.clone());
      } catch (e) { /* تجاهل */ }
    }));
    /* عند وجود نسخة عاملة سابقة (تحديث) نُفعّل الجديدة فوراً بعد اكتمال التخزين */
    if (self.registration && self.registration.active) { await self.skipWaiting(); }
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(
      keys.filter((k) => k !== CACHE_VERSION && k !== RUNTIME).map((k) => caches.delete(k))
    );
    await self.clients.claim();
  })());
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

function skipHost(hostname) {
  return SKIP_HOSTS.some((h) => hostname === h || hostname.endsWith('.' + h) || hostname.indexOf(h) > -1);
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  let url;
  try { url = new URL(req.url); } catch (e) { return; }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return;
  if (skipHost(url.hostname)) return;

  const isHtml = req.mode === 'navigate' ||
    (req.headers.get('accept') || '').indexOf('text/html') > -1 ||
    url.pathname.endsWith('.html');

  if (url.origin === self.location.origin && isHtml) {
    /* الصفحات: الشبكة أولاً (لجلب أحدث نسخة) مع الرجوع للكاش عند عدم الاتصال */
    event.respondWith((async () => {
      try {
        const fresh = await fetch(new Request(req, { cache: 'no-store' }));
        if (fresh && fresh.ok) {
          const cache = await caches.open(CACHE_VERSION);
          cache.put(req, fresh.clone()).catch(() => {});
          return fresh;
        }
        throw new Error('bad status');
      } catch (e) {
        const hit = await caches.match(req, { ignoreSearch: true }) ||
          await caches.match('./Test_V22.html');
        return hit || Response.error();
      }
    })());
    return;
  }

  /* كاش أولاً مع تحديث في الخلفية */
  event.respondWith((async () => {
    const cache = await caches.open(CACHE_VERSION);
    const hit = await caches.match(req);
    const network = fetch(req).then((res) => {
      try {
        if (res && (res.ok || res.type === 'opaque')) cache.put(req, res.clone());
      } catch (e) { /* تجاهل */ }
      return res;
    }).catch(() => hit);
    return hit || network;
  })());
});
