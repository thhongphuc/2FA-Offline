// Sinh mã TOTP (RFC 6238) hoàn toàn tại trình duyệt.
(function (global) {
  'use strict';

  var subtle = (global.crypto && global.crypto.subtle) || null;
  var subtleBroken = false; // bật lên nếu subtle tồn tại nhưng ném lỗi lúc chạy

  // Chuyển counter (số nguyên 64-bit) thành 8 byte big-endian.
  function counterToBytes(counter) {
    var out = new Uint8Array(8);
    var c = counter;
    for (var i = 7; i >= 0; i--) {
      out[i] = c % 256;
      c = Math.floor(c / 256);
    }
    return out;
  }

  function hmacFallback(algorithm, key, msg) {
    if (algorithm === 'SHA-1') return global.SHA.hmacSha1(key, msg);
    if (algorithm === 'SHA-256') return global.SHA.hmacSha256(key, msg);
    throw new Error(
      algorithm + ' cần Web Crypto. Hãy chạy trang qua http://localhost thay vì mở file trực tiếp.'
    );
  }

  function hmacSign(algorithm, key, msg) {
    if (subtle && !subtleBroken) {
      return subtle
        .importKey('raw', key, { name: 'HMAC', hash: { name: algorithm } }, false, ['sign'])
        .then(function (cryptoKey) {
          return subtle.sign('HMAC', cryptoKey, msg);
        })
        .then(function (sig) {
          return new Uint8Array(sig);
        })
        .catch(function () {
          subtleBroken = true;
          return hmacFallback(algorithm, key, msg);
        });
    }
    return Promise.resolve().then(function () {
      return hmacFallback(algorithm, key, msg);
    });
  }

  // Trả về { code, next, remaining, period, counter }
  function generate(account, nowMs) {
    var period = account.period || 30;
    var digits = account.digits || 6;
    var algorithm = account.algorithm || 'SHA-1';
    var now = (nowMs == null ? Date.now() : nowMs) / 1000;
    var counter = Math.floor(now / period);
    var remaining = period - (now % period);

    var key;
    try {
      key = global.Base32.decode(account.secret);
    } catch (err) {
      return Promise.reject(err);
    }

    return Promise.all([
      hmacSign(algorithm, key, counterToBytes(counter)),
      hmacSign(algorithm, key, counterToBytes(counter + 1))
    ]).then(function (results) {
      return {
        code: truncate(results[0], digits),
        next: truncate(results[1], digits),
        remaining: remaining,
        period: period,
        counter: counter
      };
    });
  }

  // Dynamic truncation theo RFC 4226.
  function truncate(hs, digits) {
    var offset = hs[hs.length - 1] & 0x0f;
    var bin =
      ((hs[offset] & 0x7f) << 24) |
      ((hs[offset + 1] & 0xff) << 16) |
      ((hs[offset + 2] & 0xff) << 8) |
      (hs[offset + 3] & 0xff);
    var mod = Math.pow(10, digits);
    var code = String(bin % mod);
    while (code.length < digits) code = '0' + code;
    return code;
  }

  global.TOTP = { generate: generate };
})(window);
