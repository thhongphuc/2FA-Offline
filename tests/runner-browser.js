// Hiển thị kết quả TestSuite trong trình duyệt. Tách khỏi index.html vì CSP
// script-src 'self' chặn script inline.
(function () {
  'use strict';

  var list = document.getElementById('results');
  var summary = document.getElementById('summary');

  document.getElementById('env').textContent =
    'Web Crypto: ' + ((window.crypto && window.crypto.subtle) ? 'có' : 'KHÔNG (một số test sẽ bị bỏ qua)') +
    ' · ' + location.protocol.replace(':', '');

  window.TestSuite.run().then(function (results) {
    var passed = 0, failed = 0, skipped = 0;
    results.forEach(function (r) {
      var li = document.createElement('li');
      var name = document.createElement('span');
      name.textContent = r.name;
      li.appendChild(name);

      var detail = document.createElement('small');
      if (!r.ok) {
        failed++;
        li.className = 'fail';
        detail.textContent = r.error;
      } else if (r.skipped) {
        skipped++;
        li.className = 'skip';
        detail.textContent = r.note;
      } else {
        passed++;
        li.className = 'pass';
        detail.textContent = r.ms + ' ms';
      }
      li.appendChild(detail);
      list.appendChild(li);
    });

    summary.textContent = passed + ' đạt, ' + failed + ' lỗi, ' + skipped + ' bỏ qua';
    summary.className = 'summary ' + (failed ? 'fail' : 'pass');
    // Cho công cụ tự động đọc kết quả.
    window.__TEST_RESULTS__ = { passed: passed, failed: failed, skipped: skipped, results: results };
    document.title = (failed ? '✗ ' : '✓ ') + document.title;
  });
})();
