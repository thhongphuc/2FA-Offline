// Lưu trữ vault trong localStorage. Không có mạng, không server.
//
// Hai dạng bản ghi:
//   Thường:   { version, accounts: [...], settings: {...} }
//   Mã hoá:   { version, encrypted: true, kdf: {...}, iv, ciphertext, settings: {...} }
// settings luôn để dạng thường để áp được theme trước khi mở khoá.
(function (global) {
  'use strict';

  var KEY = '2fa.vault.v1';
  var VERSION = 1;

  var DEFAULT_SETTINGS = {
    timeOffset: 0,        // giây, bù lệch đồng hồ máy
    theme: 'dark',
    revealSecrets: false,
    showPasswords: false,
    autoLockMinutes: 5,   // 0 = không tự khoá
    guideDismissed: false,// người mới vào thấy hướng dẫn mở sẵn
    lang: ''              // '' = chưa chọn, sẽ dò theo ngôn ngữ trình duyệt
  };

  function assign(target) {
    for (var i = 1; i < arguments.length; i++) {
      var src = arguments[i];
      if (!src) continue;
      for (var k in src) {
        if (Object.prototype.hasOwnProperty.call(src, k)) target[k] = src[k];
      }
    }
    return target;
  }

  function newId() {
    if (global.crypto && global.crypto.randomUUID) return global.crypto.randomUUID();
    var buf = new Uint8Array(16);
    if (global.crypto && global.crypto.getRandomValues) global.crypto.getRandomValues(buf);
    var hex = '';
    for (var i = 0; i < buf.length; i++) hex += ('0' + buf[i].toString(16)).slice(-2);
    return hex;
  }

  function sanitize(acc) {
    return {
      id: acc.id || newId(),
      // Để rỗng chứ không nhét chuỗi mặc định: nhãn "chưa đặt tên" là việc của
      // tầng hiển thị, nếu ghi cứng vào dữ liệu thì đổi ngôn ngữ sẽ không đổi được.
      label: String(acc.label || ''),
      password: String(acc.password || ''),
      secret: String(acc.secret || ''),
      issuer: String(acc.issuer || ''),
      note: String(acc.note || ''),
      group: String(acc.group || ''),   // rỗng = "Chưa phân nhóm"
      digits: parseInt(acc.digits, 10) || 6,
      period: parseInt(acc.period, 10) || 30,
      algorithm: acc.algorithm || 'SHA-1',
      createdAt: acc.createdAt || Date.now()
    };
  }

  function readRaw() {
    var text;
    try {
      text = global.localStorage.getItem(KEY);
    } catch (err) {
      return null;
    }
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch (err) {
      return null;
    }
  }

  function writeRaw(obj) {
    try {
      global.localStorage.setItem(KEY, JSON.stringify(obj));
      return true;
    } catch (err) {
      return false;
    }
  }

  function clear() {
    try {
      global.localStorage.removeItem(KEY);
      return true;
    } catch (err) {
      return false;
    }
  }

  function readSettings(raw) {
    return assign({}, DEFAULT_SETTINGS, (raw && raw.settings) || {});
  }

  global.Vault = {
    KEY: KEY,
    VERSION: VERSION,
    DEFAULT_SETTINGS: DEFAULT_SETTINGS,
    readRaw: readRaw,
    writeRaw: writeRaw,
    readSettings: readSettings,
    clear: clear,
    sanitize: sanitize,
    newId: newId,
    assign: assign
  };
})(window);
