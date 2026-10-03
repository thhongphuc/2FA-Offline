// Service worker: cache toàn bộ asset để chạy khi mất mạng.
// Không fetch bất cứ thứ gì từ bên ngoài.
var CACHE = '2fa-offline-v4';
var ASSETS = [
  './',
  './index.html',
  './css/style.css',
  './js/i18n.js',
  './js/base32.js',
  './js/sha.js',
  './js/totp.js',
  './js/parser.js',
  './js/crypto.js',
  './js/storage.js',
  './js/app.js',
  './icons/icon.svg',
  './manifest.webmanifest'
];

self.addEventListener('install', function (ev) {
  ev.waitUntil(
    caches.open(CACHE).then(function (cache) { return cache.addAll(ASSETS); })
      .then(function () { return self.skipWaiting(); })
  );
});

self.addEventListener('activate', function (ev) {
  ev.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.map(function (k) {
        return k === CACHE ? null : caches.delete(k);
      }));
    }).then(function () { return self.clients.claim(); })
  );
});

// Stale-while-revalidate: trả bản cache ngay (nên offline vẫn chạy),
// đồng thời tải bản mới về cache cho lần mở sau.
// Nếu dùng cache-first thuần thì mọi sửa đổi file sẽ không bao giờ tới được người dùng.
self.addEventListener('fetch', function (ev) {
  var req = ev.request;
  if (req.method !== 'GET') return;
  if (new URL(req.url).origin !== self.location.origin) return;

  ev.respondWith(
    caches.open(CACHE).then(function (cache) {
      return cache.match(req).then(function (hit) {
        var network = fetch(req).then(function (res) {
          if (res && res.ok) cache.put(req, res.clone());
          return res;
        }).catch(function () {
          return hit || cache.match('./index.html');
        });
        return hit || network;
      });
    })
  );
});
