// Chạy bộ test bằng Node (>= 20, có sẵn globalThis.crypto.subtle):
//   node tests/run-node.mjs
// Nạp nguyên văn các file js/*.js của app vào global scope — không bundler,
// không sửa code — nên thứ được test chính là thứ chạy trên trình duyệt.
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

// Các module app gắn vào `window`.
globalThis.window = globalThis;

const files = [
  'js/base32.js',
  'js/sha.js',
  'js/totp.js',
  'js/parser.js',
  'js/crypto.js',
  'js/storage.js',
  'tests/tests.js'
];
for (const f of files) {
  vm.runInThisContext(readFileSync(join(root, f), 'utf8'), { filename: f });
}

// Kiểm tra phụ: mọi file trong ASSETS của sw.js phải tồn tại. cache.addAll()
// thất bại toàn bộ nếu chỉ một file 404, khiến app mất khả năng chạy offline.
function checkServiceWorkerAssets() {
  const sw = readFileSync(join(root, 'sw.js'), 'utf8');
  const block = sw.match(/var ASSETS = \[([\s\S]*?)\];/);
  if (!block) return { ok: false, error: 'không tìm thấy ASSETS trong sw.js' };
  const assets = [...block[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);
  const missing = assets.filter((a) => a !== './' && !existsSync(join(root, a)));
  return missing.length
    ? { ok: false, error: 'thiếu file: ' + missing.join(', ') }
    : { ok: true, note: assets.length + ' file' };
}

const results = await globalThis.TestSuite.run();
const swCheck = checkServiceWorkerAssets();
results.push({ name: 'sw.js: mọi file trong ASSETS đều tồn tại', ...swCheck, skipped: false });

let passed = 0, failed = 0, skipped = 0;
for (const r of results) {
  if (!r.ok) {
    failed++;
    console.log(`  \x1b[31m✗\x1b[0m ${r.name}\n      ${r.error}`);
  } else if (r.skipped) {
    skipped++;
    console.log(`  \x1b[33m-\x1b[0m ${r.name} (${r.note})`);
  } else {
    passed++;
    console.log(`  \x1b[32m✓\x1b[0m ${r.name}`);
  }
}
console.log(`\n${passed} đạt, ${failed} lỗi, ${skipped} bỏ qua`);
process.exit(failed ? 1 : 0);
