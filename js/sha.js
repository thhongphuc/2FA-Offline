// SHA-1 / SHA-256 + HMAC thuần JavaScript.
// Đây là đường dự phòng khi crypto.subtle không dùng được
// (ví dụ mở trực tiếp bằng file:// trên một số trình duyệt).
(function (global) {
  'use strict';

  function pad(bytes) {
    var ml = bytes.length;
    var total = ((((ml + 8) >> 6) + 1) << 6);
    var buf = new Uint8Array(total);
    buf.set(bytes);
    buf[ml] = 0x80;
    var dv = new DataView(buf.buffer);
    var bitLen = ml * 8;
    dv.setUint32(total - 8, Math.floor(bitLen / 4294967296));
    dv.setUint32(total - 4, bitLen >>> 0);
    return buf;
  }

  function sha1(bytes) {
    var buf = pad(bytes);
    var dv = new DataView(buf.buffer);
    var h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    var w = new Int32Array(80);

    for (var i = 0; i < buf.length; i += 64) {
      var j, n;
      for (j = 0; j < 16; j++) w[j] = dv.getInt32(i + j * 4);
      for (j = 16; j < 80; j++) {
        n = w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16];
        w[j] = (n << 1) | (n >>> 31);
      }
      var a = h0, b = h1, c = h2, d = h3, e = h4;
      for (j = 0; j < 80; j++) {
        var f, k;
        if (j < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
        else if (j < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
        else if (j < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else { f = b ^ c ^ d; k = 0xca62c1d6; }
        var t = (((a << 5) | (a >>> 27)) + f + e + k + w[j]) | 0;
        e = d; d = c; c = (b << 30) | (b >>> 2); b = a; a = t;
      }
      h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0;
      h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
    }

    var out = new Uint8Array(20);
    var odv = new DataView(out.buffer);
    odv.setInt32(0, h0); odv.setInt32(4, h1); odv.setInt32(8, h2);
    odv.setInt32(12, h3); odv.setInt32(16, h4);
    return out;
  }

  var K256 = new Int32Array([
    0x428a2f98 | 0, 0x71374491 | 0, 0xb5c0fbcf | 0, 0xe9b5dba5 | 0,
    0x3956c25b | 0, 0x59f111f1 | 0, 0x923f82a4 | 0, 0xab1c5ed5 | 0,
    0xd807aa98 | 0, 0x12835b01 | 0, 0x243185be | 0, 0x550c7dc3 | 0,
    0x72be5d74 | 0, 0x80deb1fe | 0, 0x9bdc06a7 | 0, 0xc19bf174 | 0,
    0xe49b69c1 | 0, 0xefbe4786 | 0, 0x0fc19dc6 | 0, 0x240ca1cc | 0,
    0x2de92c6f | 0, 0x4a7484aa | 0, 0x5cb0a9dc | 0, 0x76f988da | 0,
    0x983e5152 | 0, 0xa831c66d | 0, 0xb00327c8 | 0, 0xbf597fc7 | 0,
    0xc6e00bf3 | 0, 0xd5a79147 | 0, 0x06ca6351 | 0, 0x14292967 | 0,
    0x27b70a85 | 0, 0x2e1b2138 | 0, 0x4d2c6dfc | 0, 0x53380d13 | 0,
    0x650a7354 | 0, 0x766a0abb | 0, 0x81c2c92e | 0, 0x92722c85 | 0,
    0xa2bfe8a1 | 0, 0xa81a664b | 0, 0xc24b8b70 | 0, 0xc76c51a3 | 0,
    0xd192e819 | 0, 0xd6990624 | 0, 0xf40e3585 | 0, 0x106aa070 | 0,
    0x19a4c116 | 0, 0x1e376c08 | 0, 0x2748774c | 0, 0x34b0bcb5 | 0,
    0x391c0cb3 | 0, 0x4ed8aa4a | 0, 0x5b9cca4f | 0, 0x682e6ff3 | 0,
    0x748f82ee | 0, 0x78a5636f | 0, 0x84c87814 | 0, 0x8cc70208 | 0,
    0x90befffa | 0, 0xa4506ceb | 0, 0xbef9a3f7 | 0, 0xc67178f2 | 0
  ]);

  function sha256(bytes) {
    var buf = pad(bytes);
    var dv = new DataView(buf.buffer);
    var H = new Int32Array([
      0x6a09e667 | 0, 0xbb67ae85 | 0, 0x3c6ef372 | 0, 0xa54ff53a | 0,
      0x510e527f | 0, 0x9b05688c | 0, 0x1f83d9ab | 0, 0x5be0cd19 | 0
    ]);
    var w = new Int32Array(64);

    for (var i = 0; i < buf.length; i += 64) {
      var j;
      for (j = 0; j < 16; j++) w[j] = dv.getInt32(i + j * 4);
      for (j = 16; j < 64; j++) {
        var x = w[j - 15], y = w[j - 2];
        var s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        var s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3];
      var e = H[4], f = H[5], g = H[6], h = H[7];
      for (j = 0; j < 64; j++) {
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K256[j] + w[j]) | 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0;
        d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }

    var out = new Uint8Array(32);
    var odv = new DataView(out.buffer);
    for (var k = 0; k < 8; k++) odv.setInt32(k * 4, H[k]);
    return out;
  }

  function concat(a, b) {
    var out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  // HMAC theo RFC 2104, block size 64 byte cho cả SHA-1 lẫn SHA-256.
  function hmac(hashFn, key, message) {
    var BLOCK = 64;
    if (key.length > BLOCK) key = hashFn(key);
    var k = new Uint8Array(BLOCK);
    k.set(key);

    var ipad = new Uint8Array(BLOCK);
    var opad = new Uint8Array(BLOCK);
    for (var i = 0; i < BLOCK; i++) {
      ipad[i] = k[i] ^ 0x36;
      opad[i] = k[i] ^ 0x5c;
    }
    return hashFn(concat(opad, hashFn(concat(ipad, message))));
  }

  global.SHA = {
    sha1: sha1,
    sha256: sha256,
    hmacSha1: function (key, msg) { return hmac(sha1, key, msg); },
    hmacSha256: function (key, msg) { return hmac(sha256, key, msg); }
  };
})(window);
