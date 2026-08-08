// Phân tích chuỗi người dùng dán vào.
// Hỗ trợ:
//   email|password|secret          <- định dạng chính
//   email|secret
//   secret
//   otpauth://totp/Issuer:label?secret=...&digits=6&period=30&algorithm=SHA1
(function (global) {
  'use strict';

  var DEFAULTS = { digits: 6, period: 30, algorithm: 'SHA-1' };

  function normalizeAlgorithm(raw) {
    if (!raw) return DEFAULTS.algorithm;
    var a = String(raw).toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (a === 'SHA1') return 'SHA-1';
    if (a === 'SHA256') return 'SHA-256';
    if (a === 'SHA512') return 'SHA-512';
    return DEFAULTS.algorithm;
  }

  function parseOtpauth(uri) {
    var url;
    try {
      url = new URL(uri);
    } catch (err) {
      return { error: 'URI otpauth không hợp lệ' };
    }
    if (url.protocol !== 'otpauth:') return { error: 'URI otpauth không hợp lệ' };
    if (url.host && url.host.toLowerCase() !== 'totp') {
      return { error: 'Chỉ hỗ trợ otpauth://totp (không phải HOTP)' };
    }

    var params = url.searchParams;
    var secret = params.get('secret') || '';
    if (!global.Base32.isValid(secret)) return { error: 'Secret trong URI không hợp lệ' };

    var path = decodeURIComponent(url.pathname.replace(/^\//, ''));
    var issuer = params.get('issuer') || '';
    var label = path;
    if (path.indexOf(':') !== -1) {
      var bits = path.split(':');
      if (!issuer) issuer = bits.shift().trim();
      else bits.shift();
      label = bits.join(':').trim();
    }

    return {
      label: label || issuer || 'Không tên',
      password: '',
      secret: global.Base32.normalize(secret),
      issuer: issuer,
      digits: parseInt(params.get('digits'), 10) || DEFAULTS.digits,
      period: parseInt(params.get('period'), 10) || DEFAULTS.period,
      algorithm: normalizeAlgorithm(params.get('algorithm'))
    };
  }

  // Tách theo '|'. Password có thể chứa '|' nên quy ước:
  // phần đầu = email/nhãn, phần CUỐI = secret, phần giữa gộp lại = password.
  function parseDelimited(line) {
    var parts = line.split(/\s*\|\s*/);

    if (parts.length === 1) {
      var only = parts[0].trim();
      if (!global.Base32.isValid(only)) return { error: 'Không nhận ra secret key hợp lệ' };
      return build('Không tên', '', only);
    }

    var secretIndex = parts.length - 1;
    if (!global.Base32.isValid(parts[secretIndex])) {
      // Dự phòng cho trường hợp đảo thứ tự (email|secret|password).
      // Ngưỡng 16 ký tự để một từ tiếng Việt/Anh viết thường không bị nhầm là Base32.
      secretIndex = -1;
      for (var i = parts.length - 1; i >= 1; i--) {
        if (global.Base32.isValid(parts[i]) && global.Base32.normalize(parts[i]).length >= 16) {
          secretIndex = i;
          break;
        }
      }
      if (secretIndex === -1) {
        return { error: 'Không tìm thấy secret key Base32 hợp lệ trong dòng này' };
      }
    }

    var label = parts[0].trim();
    var middle = parts.slice(1, secretIndex).concat(parts.slice(secretIndex + 1));
    var password = middle.join('|').trim();

    return build(label || 'Không tên', password, parts[secretIndex]);
  }

  function build(label, password, secret) {
    return {
      label: label,
      password: password,
      secret: global.Base32.normalize(secret),
      issuer: '',
      digits: DEFAULTS.digits,
      period: DEFAULTS.period,
      algorithm: DEFAULTS.algorithm
    };
  }

  function parseLine(line) {
    var trimmed = String(line || '').trim();
    if (!trimmed) return null;
    if (/^otpauth:\/\//i.test(trimmed)) return parseOtpauth(trimmed);
    // Chấp nhận tab hoặc dấu phẩy như dấu phân cách thay thế khi không có '|'.
    if (trimmed.indexOf('|') === -1 && /[\t]/.test(trimmed)) {
      trimmed = trimmed.replace(/\t+/g, '|');
    }
    return parseDelimited(trimmed);
  }

  // Trả về { entries: [...], errors: [{ line, message }] }
  function parseText(text) {
    var entries = [];
    var errors = [];
    var lines = String(text || '').split(/\r?\n/);

    for (var i = 0; i < lines.length; i++) {
      var result = parseLine(lines[i]);
      if (!result) continue;
      if (result.error) {
        errors.push({ line: lines[i].trim(), message: result.error });
      } else {
        entries.push(result);
      }
    }
    return { entries: entries, errors: errors };
  }

  global.Parser = { parseLine: parseLine, parseText: parseText, DEFAULTS: DEFAULTS };
})(window);
