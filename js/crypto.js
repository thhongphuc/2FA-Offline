// Mã hoá vault bằng AES-GCM, khoá dẫn xuất từ mật khẩu qua PBKDF2.
// Bắt buộc dùng crypto.subtle — PBKDF2 600k vòng viết bằng JS thuần sẽ chậm
// tới mức không dùng được, nên khi không có subtle thì tắt hẳn tính năng
// thay vì hạ thấp tham số bảo mật.
(function (global) {
  'use strict';

  var subtle = (global.crypto && global.crypto.subtle) || null;

  var ITERATIONS = 600000; // theo khuyến nghị OWASP cho PBKDF2-HMAC-SHA256
  var SALT_BYTES = 16;
  var IV_BYTES = 12;       // độ dài chuẩn cho AES-GCM

  function available() {
    return !!(subtle && subtle.deriveKey && subtle.encrypt && global.crypto.getRandomValues);
  }

  function toB64(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return global.btoa(s);
  }

  function fromB64(str) {
    var bin = global.atob(str);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function randomBytes(n) {
    var b = new Uint8Array(n);
    global.crypto.getRandomValues(b);
    return b;
  }

  function utf8(str) { return new TextEncoder().encode(str); }

  // Trả về CryptoKey không cho phép export -> không thể moi khoá ra từ JS.
  function deriveKey(password, saltBytes, iterations) {
    return subtle
      .importKey('raw', utf8(password), { name: 'PBKDF2' }, false, ['deriveKey'])
      .then(function (baseKey) {
        return subtle.deriveKey(
          { name: 'PBKDF2', salt: saltBytes, iterations: iterations, hash: 'SHA-256' },
          baseKey,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt']
        );
      });
  }

  function newKdfParams() {
    return {
      name: 'PBKDF2',
      hash: 'SHA-256',
      iterations: ITERATIONS,
      salt: toB64(randomBytes(SALT_BYTES))
    };
  }

  function deriveFromParams(password, kdf) {
    var iterations = parseInt(kdf && kdf.iterations, 10);
    if (!iterations || iterations < 1000) return Promise.reject(new Error('Tham số KDF không hợp lệ'));
    return deriveKey(password, fromB64(kdf.salt), iterations);
  }

  // IV mới cho MỖI lần ghi. Dùng lại IV với cùng khoá sẽ phá vỡ AES-GCM.
  function encrypt(key, plaintext) {
    var iv = randomBytes(IV_BYTES);
    return subtle
      .encrypt({ name: 'AES-GCM', iv: iv }, key, utf8(plaintext))
      .then(function (buf) {
        return { iv: toB64(iv), ciphertext: toB64(new Uint8Array(buf)) };
      });
  }

  function decrypt(key, ivB64, ciphertextB64) {
    return subtle
      .decrypt({ name: 'AES-GCM', iv: fromB64(ivB64) }, key, fromB64(ciphertextB64))
      .then(function (buf) { return new TextDecoder().decode(buf); });
  }

  global.VaultCrypto = {
    ITERATIONS: ITERATIONS,
    available: available,
    newKdfParams: newKdfParams,
    deriveFromParams: deriveFromParams,
    encrypt: encrypt,
    decrypt: decrypt,
    toB64: toB64,
    fromB64: fromB64
  };
})(window);
