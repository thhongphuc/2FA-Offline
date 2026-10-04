// Bộ test không dùng framework. Chạy được ở hai nơi:
//   - Trình duyệt: tests/index.html
//   - Node >= 20:  node tests/run-node.mjs
// File này chỉ đăng ký test và trả kết quả; việc hiển thị do bên chạy lo.
(function (global) {
  'use strict';

  var tests = [];
  function test(name, fn) { tests.push({ name: name, fn: fn }); }

  /* ---------------- Tiện ích kiểm tra ---------------- */

  function fail(msg) { throw new Error(msg); }

  function eq(actual, expected, label) {
    if (actual !== expected) {
      fail((label ? label + ': ' : '') + 'mong đợi ' + JSON.stringify(expected) +
        ', nhận ' + JSON.stringify(actual));
    }
  }

  function ok(cond, label) { if (!cond) fail(label || 'điều kiện sai'); }

  function rejects(promise, label) {
    return promise.then(
      function () { fail((label || 'promise') + ' lẽ ra phải bị từ chối'); },
      function () { /* đúng như mong đợi */ }
    );
  }

  function ascii(s) {
    var out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }

  function fill(byte, n) {
    var out = new Uint8Array(n);
    for (var i = 0; i < n; i++) out[i] = byte;
    return out;
  }

  function hex(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += ('0' + bytes[i].toString(16)).slice(-2);
    return s;
  }

  // Bộ mã hoá Base32 chỉ dùng trong test (app chỉ cần giải mã).
  function base32Encode(bytes) {
    var A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    var out = '', bits = 0, value = 0;
    for (var i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) {
        out += A.charAt((value >>> (bits - 5)) & 31);
        bits -= 5;
      }
    }
    if (bits > 0) out += A.charAt((value << (5 - bits)) & 31);
    return out;
  }

  var hasSubtle = !!(global.crypto && global.crypto.subtle);

  /* ---------------- Base32 (RFC 4648) ---------------- */

  test('Base32: giải mã vector RFC 4648', function () {
    eq(hex(Base32.decode('MZXW6YTBOI')), hex(ascii('foobar')), 'foobar');
    eq(hex(Base32.decode('MZXW6YQ=')), hex(ascii('foob')), 'foob (có padding)');
  });

  test('Base32: chuẩn hoá chữ thường, khoảng trắng, gạch ngang', function () {
    eq(Base32.normalize(' jbsw y3dp-ehpk_3pxp== '), 'JBSWY3DPEHPK3PXP');
  });

  test('Base32: isValid từ chối ký tự lạ và chuỗi quá ngắn', function () {
    ok(Base32.isValid('JBSWY3DPEHPK3PXP'), 'secret chuẩn');
    ok(!Base32.isValid('JBSWY3D'), 'dưới 8 ký tự');
    ok(!Base32.isValid('JBSWY3DP0HPK3PXP'), 'chứa số 0');
    ok(!Base32.isValid('Mk#123abcdef'), 'chứa #');
  });

  /* ---------------- HMAC thuần JS (đường dự phòng) ---------------- */

  test('HMAC-SHA1 thuần JS: RFC 2202 case 1, 2, 6', function () {
    eq(hex(SHA.hmacSha1(fill(0x0b, 20), ascii('Hi There'))),
      'b617318655057264e28bc0b6fb378c8ef146be00', 'case 1');
    eq(hex(SHA.hmacSha1(ascii('Jefe'), ascii('what do ya want for nothing?'))),
      'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79', 'case 2');
    eq(hex(SHA.hmacSha1(fill(0xaa, 80), ascii('Test Using Larger Than Block-Size Key - Hash Key First'))),
      'aa4ae5e15272d00e95705637ce8a3b55ed402112', 'case 6 (khoá dài hơn block)');
  });

  test('HMAC-SHA256 thuần JS: RFC 4231 case 1, 2, 6', function () {
    eq(hex(SHA.hmacSha256(fill(0x0b, 20), ascii('Hi There'))),
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7', 'case 1');
    eq(hex(SHA.hmacSha256(ascii('Jefe'), ascii('what do ya want for nothing?'))),
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843', 'case 2');
    eq(hex(SHA.hmacSha256(fill(0xaa, 131), ascii('Test Using Larger Than Block-Size Key - Hash Key First'))),
      '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54', 'case 6 (khoá dài hơn block)');
  });

  test('HMAC thuần JS khớp Web Crypto với khoá/thông điệp ngẫu nhiên', function () {
    if (!hasSubtle) return 'bỏ qua: không có crypto.subtle';
    var jobs = [];
    [['SHA-1', SHA.hmacSha1], ['SHA-256', SHA.hmacSha256]].forEach(function (pair) {
      [1, 20, 64, 65, 200].forEach(function (keyLen) {
        var key = new Uint8Array(keyLen);
        var msg = new Uint8Array(keyLen * 3 + 1);
        global.crypto.getRandomValues(key);
        global.crypto.getRandomValues(msg);
        jobs.push(global.crypto.subtle
          .importKey('raw', key, { name: 'HMAC', hash: pair[0] }, false, ['sign'])
          .then(function (k) { return global.crypto.subtle.sign('HMAC', k, msg); })
          .then(function (sig) {
            eq(hex(pair[1](key, msg)), hex(new Uint8Array(sig)), pair[0] + ' khoá ' + keyLen + ' byte');
          }));
      });
    });
    return Promise.all(jobs);
  });

  /* ---------------- TOTP (RFC 6238, phụ lục B) ---------------- */

  var RFC6238 = {
    'SHA-1':   { seed: '12345678901234567890' },
    'SHA-256': { seed: '12345678901234567890123456789012' },
    'SHA-512': { seed: '1234567890123456789012345678901234567890123456789012345678901234' }
  };
  var RFC6238_VECTORS = [
    // [thời gian (giây), SHA-1, SHA-256, SHA-512]
    [59,          '94287082', '46119246', '90693936'],
    [1111111109,  '07081804', '68084774', '25091201'],
    [1111111111,  '14050471', '67062674', '99943326'],
    [1234567890,  '89005924', '91819424', '93441116'],
    [2000000000,  '69279037', '90698825', '38618901'],
    [20000000000, '65353130', '77737706', '47863826']
  ];

  test('TOTP: toàn bộ test vector RFC 6238 (SHA-1/256/512, 8 chữ số)', function () {
    var algos = ['SHA-1', 'SHA-256', 'SHA-512'];
    var jobs = [];
    RFC6238_VECTORS.forEach(function (row) {
      algos.forEach(function (algo, i) {
        if (algo === 'SHA-512' && !hasSubtle) return;   // SHA-512 bắt buộc Web Crypto
        var acc = {
          secret: base32Encode(ascii(RFC6238[algo].seed)),
          digits: 8, period: 30, algorithm: algo
        };
        jobs.push(TOTP.generate(acc, row[0] * 1000).then(function (res) {
          eq(res.code, row[i + 1], algo + ' @ T=' + row[0]);
        }));
      });
    });
    return Promise.all(jobs);
  });

  test('TOTP: mã kế tiếp bằng mã của chu kỳ sau, remaining đúng', function () {
    var acc = { secret: 'JBSWY3DPEHPK3PXP', digits: 6, period: 30, algorithm: 'SHA-1' };
    return Promise.all([
      TOTP.generate(acc, 1000 * 1000),
      TOTP.generate(acc, 1030 * 1000)
    ]).then(function (r) {
      eq(r[0].next, r[1].code, 'next');
      eq(r[0].remaining, 20, 'remaining tại T=1000');
      eq(r[0].code.length, 6, 'độ dài mã');
    });
  });

  test('TOTP: secret hỏng bị từ chối', function () {
    return rejects(TOTP.generate({ secret: '0000', digits: 6, period: 30 }, 0), 'secret hỏng');
  });

  /* ---------------- Parser ---------------- */

  test('Parser: email|password|secret', function () {
    var r = Parser.parseLine('abc@icloud.com|Mk#123|jbswy3dpehpk3pxp');
    eq(r.label, 'abc@icloud.com');
    eq(r.password, 'Mk#123');
    eq(r.secret, 'JBSWY3DPEHPK3PXP');
  });

  test('Parser: mật khẩu chứa ký tự | được giữ nguyên', function () {
    var r = Parser.parseLine('a@b.com|p|w#1|x|JBSWY3DPEHPK3PXP');
    eq(r.password, 'p|w#1|x');
    eq(r.secret, 'JBSWY3DPEHPK3PXP');
  });

  test('Parser: email|secret và chỉ secret', function () {
    var r1 = Parser.parseLine('a@b.com|JBSWY3DPEHPK3PXP');
    eq(r1.label, 'a@b.com');
    eq(r1.password, '');
    var r2 = Parser.parseLine('JBSWY3DPEHPK3PXP');
    eq(r2.label, '');
    eq(r2.secret, 'JBSWY3DPEHPK3PXP');
  });

  test('Parser: đảo thứ tự email|secret|password (secret >= 16 ký tự)', function () {
    var r = Parser.parseLine('a@b.com|JBSWY3DPEHPK3PXPJBSWY3DP|Mk#123');
    eq(r.secret, 'JBSWY3DPEHPK3PXPJBSWY3DP');
    eq(r.password, 'Mk#123');
  });

  test('Parser: otpauth URI đọc issuer/digits/period/algorithm', function () {
    var r = Parser.parseLine(
      'otpauth://totp/GitHub:abc?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=SHA256');
    eq(r.issuer, 'GitHub');
    eq(r.label, 'abc');
    eq(r.digits, 8);
    eq(r.period, 60);
    eq(r.algorithm, 'SHA-256');
  });

  test('Parser: từ chối HOTP và dòng rác', function () {
    ok(Parser.parseLine('otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1').error, 'hotp');
    ok(Parser.parseLine('xin chào|bạn khoẻ không').error, 'dòng rác');
    eq(Parser.parseLine('   '), null, 'dòng trống');
  });

  test('Parser: parseText gom dòng hợp lệ và dòng lỗi', function () {
    var r = Parser.parseText('a@b.com|JBSWY3DPEHPK3PXP\r\n\r\nrác rưởi\nJBSWY3DPEHPK3PXQ');
    eq(r.entries.length, 2, 'entries');
    eq(r.errors.length, 1, 'errors');
  });

  /* ---------------- Vault.sanitize ---------------- */

  test('sanitize: kẹp digits/period về miền hợp lệ', function () {
    eq(Vault.sanitize({ secret: 'X', digits: 99 }).digits, 6, 'digits 99');
    eq(Vault.sanitize({ secret: 'X', digits: '8' }).digits, 8, 'digits "8"');
    eq(Vault.sanitize({ secret: 'X', period: -5 }).period, 30, 'period âm');
    eq(Vault.sanitize({ secret: 'X', period: 1e9 }).period, 30, 'period quá lớn');
    eq(Vault.sanitize({ secret: 'X', period: 60 }).period, 60, 'period 60');
  });

  test('sanitize: chỉ nhận SHA-1/256/512, chấp nhận cách viết khác', function () {
    eq(Vault.sanitize({ algorithm: 'MD5' }).algorithm, 'SHA-1', 'MD5');
    eq(Vault.sanitize({ algorithm: 'sha256' }).algorithm, 'SHA-256', 'sha256');
    eq(Vault.sanitize({ algorithm: 'SHA-512' }).algorithm, 'SHA-512', 'SHA-512');
    eq(Vault.sanitize({}).algorithm, 'SHA-1', 'trống');
  });

  test('sanitize: ép kiểu chuỗi, không nhét nhãn mặc định', function () {
    var s = Vault.sanitize({ label: 123, note: null, group: undefined });
    eq(s.label, '123');
    eq(s.note, '');
    eq(s.group, '');
    eq(Vault.sanitize({}).label, '', 'nhãn rỗng');
    ok(typeof Vault.sanitize({}).id === 'string', 'có id');
  });

  test('sanitize: groupColor chỉ 0–7, không nhóm thì -1', function () {
    eq(Vault.sanitize({ group: 'A', groupColor: 3 }).groupColor, 3, 'hợp lệ');
    eq(Vault.sanitize({ group: 'A', groupColor: '5' }).groupColor, 5, 'chuỗi số');
    eq(Vault.sanitize({ group: 'A', groupColor: 9 }).groupColor, -1, 'quá lớn');
    eq(Vault.sanitize({ group: 'A', groupColor: -3 }).groupColor, -1, 'âm');
    eq(Vault.sanitize({ group: 'A' }).groupColor, -1, 'thiếu');
    eq(Vault.sanitize({ group: '', groupColor: 2 }).groupColor, -1, 'không nhóm');
  });

  test('normalizeGroupColors: cả nhóm theo màu của thành viên đầu tiên có màu', function () {
    var list = [
      { group: 'A', groupColor: -1 },
      { group: 'A', groupColor: 4 },
      { group: 'A', groupColor: 6 },   // mâu thuẫn (vd. từ file import) -> theo 4
      { group: 'B', groupColor: -1 },
      { group: '', groupColor: 2 }     // không nhóm -> -1
    ];
    Vault.normalizeGroupColors(list);
    eq(list.map(function (a) { return a.groupColor; }).join(','), '4,4,4,-1,-1');
    eq(Vault.groupColorIndex(list, 'A'), 4, 'nhóm A');
    eq(Vault.groupColorIndex(list, 'B'), -1, 'nhóm B tự động');
    eq(Vault.groupColorIndex(list, ''), -1, 'không nhóm');
  });

  /* ---------------- Mã hoá (AES-GCM + PBKDF2) ---------------- */

  // Test dùng 1.000 vòng cho nhanh; app thật dùng 600.000.
  function fastKdf() {
    var kdf = VaultCrypto.newKdfParams();
    kdf.iterations = 1000;
    return kdf;
  }

  test('Crypto: seal/open khứ hồi, sai mật khẩu bị từ chối', function () {
    if (!VaultCrypto.available()) return 'bỏ qua: không có crypto.subtle';
    return VaultCrypto.seal('đúng-mật-khẩu', 'xin chào 🔐', fastKdf()).then(function (s) {
      return VaultCrypto.open('đúng-mật-khẩu', s).then(function (plain) {
        eq(plain, 'xin chào 🔐');
        return rejects(VaultCrypto.open('sai-mật-khẩu', s), 'sai mật khẩu');
      });
    });
  });

  test('Crypto: mỗi lần seal ra salt và IV khác nhau', function () {
    if (!VaultCrypto.available()) return 'bỏ qua: không có crypto.subtle';
    return Promise.all([
      VaultCrypto.seal('pw', 'x', fastKdf()),
      VaultCrypto.seal('pw', 'x', fastKdf())
    ]).then(function (r) {
      ok(r[0].kdf.salt !== r[1].kdf.salt, 'salt trùng');
      ok(r[0].iv !== r[1].iv, 'IV trùng');
      ok(r[0].ciphertext !== r[1].ciphertext, 'ciphertext trùng');
    });
  });

  test('Crypto: ciphertext bị sửa thì giải mã thất bại', function () {
    if (!VaultCrypto.available()) return 'bỏ qua: không có crypto.subtle';
    return VaultCrypto.seal('pw', 'dữ liệu quan trọng', fastKdf()).then(function (s) {
      var bytes = VaultCrypto.fromB64(s.ciphertext);
      bytes[0] ^= 1;
      var tampered = { kdf: s.kdf, iv: s.iv, ciphertext: VaultCrypto.toB64(bytes) };
      return rejects(VaultCrypto.open('pw', tampered), 'ciphertext bị sửa');
    });
  });

  test('Crypto: từ chối tham số KDF bất thường (quá ít / quá nhiều vòng, salt hỏng)', function () {
    return Promise.all([
      rejects(VaultCrypto.deriveFromParams('pw', { salt: 'AAAA', iterations: 10 }), '10 vòng'),
      rejects(VaultCrypto.deriveFromParams('pw', { salt: 'AAAA', iterations: 1e12 }), '1e12 vòng'),
      rejects(VaultCrypto.deriveFromParams('pw', { salt: '%%%', iterations: 1000 }), 'salt hỏng'),
      rejects(VaultCrypto.deriveFromParams('pw', null), 'kdf null')
    ]);
  });

  test('Backup mã hoá: sealBackup/openBackup khứ hồi giữ nguyên dữ liệu', function () {
    if (!VaultCrypto.available()) return 'bỏ qua: không có crypto.subtle';
    var accounts = [
      Vault.sanitize({ label: 'a@b.com', secret: 'JBSWY3DPEHPK3PXP', group: 'Công việc', note: 'ghi chú' }),
      Vault.sanitize({ label: 'c@d.com', secret: 'JBSWY3DPEHPK3PXQ', digits: 8, algorithm: 'SHA-256' })
    ];
    return VaultCrypto.sealBackup('mật-khẩu-file', accounts, fastKdf()).then(function (file) {
      ok(VaultCrypto.isEncryptedBackup(file), 'nhận diện được định dạng');
      var text = JSON.stringify(file);
      ok(text.indexOf('JBSWY3DPEHPK3PXP') === -1, 'secret lộ trong file');
      ok(text.indexOf('a@b.com') === -1, 'email lộ trong file');
      return VaultCrypto.openBackup('mật-khẩu-file', JSON.parse(text)).then(function (list) {
        eq(JSON.stringify(list), JSON.stringify(accounts), 'dữ liệu khứ hồi');
        return rejects(VaultCrypto.openBackup('sai', file), 'sai mật khẩu file');
      });
    });
  });

  test('Backup mã hoá: isEncryptedBackup không nhận nhầm backup thường', function () {
    ok(!VaultCrypto.isEncryptedBackup({ version: 1, accounts: [] }), 'backup thường');
    ok(!VaultCrypto.isEncryptedBackup([]), 'mảng');
    ok(!VaultCrypto.isEncryptedBackup(null), 'null');
    ok(!VaultCrypto.isEncryptedBackup({ format: '2fa-offline-backup', encrypted: true }), 'thiếu trường');
  });

  /* ---------------- Chạy ---------------- */

  function run() {
    var results = [];
    return tests.reduce(function (chain, tc) {
      return chain.then(function () {
        var started = Date.now();
        return Promise.resolve()
          .then(function () { return tc.fn(); })
          .then(function (note) {
            var skipped = typeof note === 'string';
            results.push({ name: tc.name, ok: true, skipped: skipped, note: skipped ? note : '', ms: Date.now() - started });
          }, function (err) {
            results.push({ name: tc.name, ok: false, error: (err && err.message) || String(err), ms: Date.now() - started });
          });
      });
    }, Promise.resolve()).then(function () { return results; });
  }

  global.TestSuite = { run: run, count: function () { return tests.length; } };
})(typeof window !== 'undefined' ? window : globalThis);
