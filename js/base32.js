// Base32 (RFC 4648) decoder - dùng cho secret key của TOTP.
(function (global) {
  'use strict';

  var ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  // Chuẩn hoá: bỏ khoảng trắng, gạch ngang, dấu '=' đệm, đưa về chữ hoa.
  function normalize(input) {
    return String(input == null ? '' : input)
      .toUpperCase()
      .replace(/[\s\-_]/g, '')
      .replace(/=+$/, '');
  }

  function isValid(input) {
    var s = normalize(input);
    return s.length >= 8 && /^[A-Z2-7]+$/.test(s);
  }

  function decode(input) {
    var s = normalize(input);
    if (!s) throw new Error('Secret key đang trống');

    var bits = 0;
    var value = 0;
    var index = 0;
    var out = new Uint8Array(Math.floor((s.length * 5) / 8));

    for (var i = 0; i < s.length; i++) {
      var idx = ALPHABET.indexOf(s.charAt(i));
      if (idx === -1) {
        throw new Error('Secret key chứa ký tự không hợp lệ: "' + s.charAt(i) + '"');
      }
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        out[index++] = (value >>> (bits - 8)) & 0xff;
        bits -= 8;
      }
    }

    if (index === 0) throw new Error('Secret key quá ngắn');
    return out.subarray(0, index);
  }

  global.Base32 = { decode: decode, isValid: isValid, normalize: normalize };
})(window);
