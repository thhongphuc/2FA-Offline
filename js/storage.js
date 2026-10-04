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
    lockOnHide: false,    // khoá ngay khi tab bị ẩn (chỉ có tác dụng khi đã bật mã hoá)
    clearClipboard: true, // ghi đè clipboard 30 giây sau khi copy mã / secret / mật khẩu
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

  // Dữ liệu có thể đến từ file import do người khác tạo, nên mọi trường số và
  // thuật toán đều phải nằm trong miền hợp lệ — ngoài miền thì về mặc định.
  var ALGOS = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

  function normalizeAlgorithm(raw) {
    var key = String(raw || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    return ALGOS[key] || 'SHA-1';
  }

  function clampInt(raw, min, max, fallback) {
    var n = parseInt(raw, 10);
    if (!isFinite(n) || n < min || n > max) return fallback;
    return n;
  }

  function newId() {
    if (global.crypto && global.crypto.randomUUID) return global.crypto.randomUUID();
    var buf = new Uint8Array(16);
    if (global.crypto && global.crypto.getRandomValues) global.crypto.getRandomValues(buf);
    var hex = '';
    for (var i = 0; i < buf.length; i++) hex += ('0' + buf[i].toString(16)).slice(-2);
    return hex;
  }

  var GROUP_COLORS = 8;

  // Màu của một nhóm = màu của tài khoản ĐẦU TIÊN (theo thứ tự mảng) trong nhóm đó
  // có đặt màu. -1 nếu chưa ai đặt.
  function groupColorIndex(accounts, name) {
    if (!name) return -1;
    for (var i = 0; i < accounts.length; i++) {
      var a = accounts[i];
      if (a.group === name && a.groupColor >= 0) return a.groupColor;
    }
    return -1;
  }

  // Đưa mọi thành viên của mỗi nhóm về cùng một màu (theo quy tắc trên). Cần vì
  // import / gộp nhóm có thể đưa vào các tài khoản mang màu khác nhau.
  function normalizeGroupColors(accounts) {
    var canon = Object.create(null);
    accounts.forEach(function (a) {
      if (a.group && !(a.group in canon) && a.groupColor >= 0) canon[a.group] = a.groupColor;
    });
    accounts.forEach(function (a) {
      a.groupColor = a.group && (a.group in canon) ? canon[a.group] : -1;
    });
    return accounts;
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
      // Màu nhóm người dùng chọn (0–7), -1 = tự động theo tên. Lưu trên từng tài
      // khoản chứ không trong settings: như vậy nó được mã hoá cùng vault và đi
      // theo file backup, tên nhóm không bao giờ nằm dạng văn bản thường.
      groupColor: acc.group ? clampInt(acc.groupColor, 0, GROUP_COLORS - 1, -1) : -1,
      digits: clampInt(acc.digits, 6, 8, 6),
      period: clampInt(acc.period, 1, 300, 30),
      algorithm: normalizeAlgorithm(acc.algorithm),
      createdAt: clampInt(acc.createdAt, 0, 8.64e15, 0) || Date.now()
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
    assign: assign,
    GROUP_COLORS: GROUP_COLORS,
    groupColorIndex: groupColorIndex,
    normalizeGroupColors: normalizeGroupColors
  };
})(window);
