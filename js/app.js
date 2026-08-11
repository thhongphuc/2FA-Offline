// Điều phối UI: render danh sách, chạy đồng hồ, copy, import/export,
// mã hoá vault, kéo thả sắp xếp.
(function () {
  'use strict';

  var RING_R = 16;
  var RING_C = 2 * Math.PI * RING_R;

  var settings = Vault.assign({}, Vault.DEFAULT_SETTINGS);
  var accounts = [];       // chỉ có dữ liệu khi vault đang mở
  var cards = [];          // các thẻ đang hiển thị, kể cả kết quả nhanh
  var quickEntries = [];   // kết quả từ ô nhập, chưa lưu
  var filter = '';
  // null = xem tất cả; '' = chỉ nhóm "Chưa phân nhóm"; 'X' = nhóm tên X
  var activeGroup = null;
  var selectMode = false;
  var selected = Object.create(null);   // id -> true

  // Trạng thái mã hoá
  var enc = { enabled: false, kdf: null, iv: null, ciphertext: null };
  var cryptoKey = null;    // chỉ nằm trong RAM, không bao giờ ghi xuống đĩa
  var locked = false;
  var writeQueue = Promise.resolve();
  var lastActivity = Date.now();

  var $ = function (id) { return document.getElementById(id); };

  var els = {
    input: $('input'),
    quickList: $('quickList'),
    vaultList: $('vaultList'),
    vaultEmpty: $('vaultEmpty'),
    vaultCount: $('vaultCount'),
    groupBar: $('groupBar'),
    groupList: $('groupList'),
    parseErrors: $('parseErrors'),
    search: $('search'),
    toast: $('toast'),
    guide: $('guide'),
    main: document.querySelector('main'),
    foot: document.querySelector('footer'),
    cryptoNote: $('cryptoNote'),
    busy: $('busy'),
    busyText: $('busyText'),
    lockScreen: $('lockScreen'),
    editDialog: $('editDialog'),
    settingsDialog: $('settingsDialog'),
    pwDialog: $('pwDialog')
  };

  /* ---------------- Tiện ích ---------------- */

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  var toastTimer = null;
  function toast(msg) {
    els.toast.textContent = msg;
    els.toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { els.toast.classList.remove('show'); }, 2400);
  }

  function busy(on, text) {
    els.busyText.textContent = text || 'Đang xử lý…';
    els.busy.hidden = !on;
  }

  // navigator.clipboard không có trên file:// ở nhiều trình duyệt -> có đường lui.
  function copy(text, label) {
    function done() { toast('Đã copy ' + (label || '') + ': ' + text); }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { legacyCopy(text, done); });
    } else {
      legacyCopy(text, done);
    }
  }

  function legacyCopy(text, done) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.cssText = 'position:fixed;top:-1000px;opacity:0';
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (err) { ok = false; }
    document.body.removeChild(ta);
    if (ok) done();
    else toast('Trình duyệt chặn copy — hãy bôi đen và Ctrl+C');
  }

  function nowMs() {
    return Date.now() + (settings.timeOffset || 0) * 1000;
  }

  function maskSecret(secret) {
    if (settings.revealSecrets) return secret;
    return secret.slice(0, 4) + '••••••••' + secret.slice(-4);
  }

  function maskPassword(pw) {
    if (!pw) return '';
    return settings.showPasswords ? pw : '••••••••';
  }

  /* ---------------- Ghi xuống localStorage ---------------- */

  // Khi bật mã hoá, mỗi lần ghi phải chạy qua AES-GCM (bất đồng bộ).
  // Xâu chuỗi các lần ghi để hai thao tác liên tiếp không ghi đè lẫn nhau.
  function persist() {
    if (!enc.enabled) {
      if (!Vault.writeRaw({ version: Vault.VERSION, accounts: accounts, settings: settings })) {
        toast('Không ghi được localStorage (chế độ riêng tư?)');
      }
      return writeQueue;
    }

    if (!cryptoKey) return writeQueue; // đang khoá: không có gì để ghi

    writeQueue = writeQueue
      .then(function () {
        return VaultCrypto.encrypt(cryptoKey, JSON.stringify({ accounts: accounts }));
      })
      .then(function (res) {
        enc.iv = res.iv;
        enc.ciphertext = res.ciphertext;
        var ok = Vault.writeRaw({
          version: Vault.VERSION,
          encrypted: true,
          kdf: enc.kdf,
          iv: enc.iv,
          ciphertext: enc.ciphertext,
          settings: settings
        });
        if (!ok) toast('Không ghi được localStorage (chế độ riêng tư?)');
      })
      .catch(function (err) {
        toast('Lỗi mã hoá khi lưu: ' + (err.message || err));
      });

    return writeQueue;
  }

  // settings luôn ở dạng thường nên ghi được cả khi đang khoá.
  function persistSettings() {
    if (locked) {
      Vault.writeRaw({
        version: Vault.VERSION,
        encrypted: true,
        kdf: enc.kdf,
        iv: enc.iv,
        ciphertext: enc.ciphertext,
        settings: settings
      });
      return;
    }
    persist();
  }

  /* ---------------- Dựng thẻ ---------------- */

  function buildCard(acc, opts) {
    opts = opts || {};
    var el = document.createElement('div');
    el.className = 'acct';
    el.dataset.id = acc.id;

    // Ở chế độ chọn nhiều, ẩn hẳn tay kéo và nút sửa/xoá: cả thẻ trở thành
    // vùng bấm để chọn, giữ hai công dụng cùng lúc sẽ gây bấm nhầm.
    var actions;
    if (!opts.saved) {
      actions = '<button data-act="save" title="Lưu vào danh sách">＋</button>';
    } else if (selectMode) {
      actions = '<span class="acct-check" aria-hidden="true"></span>';
    } else {
      actions =
        '<button class="drag-handle" data-act="drag" draggable="true" title="Kéo để đổi thứ tự">⠿</button>' +
        '<button data-act="edit" title="Sửa">✎</button>' +
        '<button data-act="delete" title="Xoá">🗑</button>';
    }

    el.innerHTML =
      '<div class="acct-top">' +
        '<div class="acct-label" data-act="copy-label" title="Bấm để copy email / nhãn">' +
          esc(acc.label) +
          (acc.issuer ? '<div class="acct-issuer">' + esc(acc.issuer) + '</div>' : '') +
          (acc.group
            ? '<div><span class="acct-group ' + groupColorClass(acc.group) + '">' +
                esc(acc.group) + '</span></div>'
            : '') +
        '</div>' +
        '<div class="acct-menu">' + actions + '</div>' +
      '</div>' +
      '<div class="acct-main">' +
        '<div class="code" data-act="copy" title="Bấm để copy">••••••</div>' +
        '<div class="ring-wrap">' +
          '<svg class="ring" viewBox="0 0 36 36">' +
            '<circle class="ring-bg" cx="18" cy="18" r="' + RING_R + '"></circle>' +
            '<circle class="ring-fg" cx="18" cy="18" r="' + RING_R + '" ' +
              'stroke-dasharray="' + RING_C.toFixed(2) + '" stroke-dashoffset="0"></circle>' +
          '</svg>' +
          '<span class="ring-sec">--</span>' +
        '</div>' +
      '</div>' +
      '<div class="acct-foot">' +
        '<span class="secret-line" data-act="copy-secret" title="Bấm để copy secret">' +
          esc(maskSecret(acc.secret)) + '</span>' +
        '<span class="acct-next">kế tiếp <b>------</b></span>' +
      '</div>' +
      (acc.password
        ? '<div class="acct-foot acct-foot-sub">' +
            '<span class="pw-line" data-act="copy-password" title="Bấm để copy mật khẩu">🔑 ' +
              esc(maskPassword(acc.password)) + '</span>' +
            (acc.note ? '<span>' + esc(acc.note) + '</span>' : '') +
          '</div>'
        : (acc.note
            ? '<div class="acct-foot" style="border:0;padding-top:0"><span>' + esc(acc.note) + '</span></div>'
            : ''));

    var card = {
      acc: acc,
      saved: !!opts.saved,
      el: el,
      codeEl: el.querySelector('.code'),
      ringEl: el.querySelector('.ring-fg'),
      secEl: el.querySelector('.ring-sec'),
      nextEl: el.querySelector('.acct-next b'),
      counter: null,
      pending: false,
      code: null,
      next: null
    };

    if (card.saved && selectMode) {
      el.classList.add('selectable');
      if (selected[acc.id]) el.classList.add('selected');
    }

    el.addEventListener('click', function (ev) {
      // Cả thẻ là vùng bấm để chọn; các thao tác copy tạm ngưng ở chế độ này.
      if (selectMode && card.saved) {
        toggleSelect(card);
        return;
      }
      var target = ev.target.closest('[data-act]');
      if (!target) return;
      onCardAction(target.getAttribute('data-act'), card);
    });

    return card;
  }

  function onCardAction(act, card) {
    var acc = card.acc;
    if (act === 'copy') {
      if (card.code) copy(card.code, 'mã');
      return;
    }
    if (act === 'copy-label') { copy(acc.label, 'email'); return; }
    if (act === 'copy-secret') { copy(acc.secret, 'secret'); return; }
    if (act === 'copy-password') { copy(acc.password, 'mật khẩu'); return; }
    if (act === 'save') { saveAccount(acc); return; }
    if (act === 'edit') { openEdit(acc); return; }
    if (act === 'delete') {
      if (!window.confirm('Xoá "' + acc.label + '" khỏi danh sách?')) return;
      accounts = accounts.filter(function (a) { return a.id !== acc.id; });
      delete selected[acc.id];
      persist();
      rebuildCards();
      toast('Đã xoá');
    }
  }

  /* ---------------- Đồng hồ ---------------- */

  function tick() {
    var t = nowMs();
    for (var i = 0; i < cards.length; i++) updateCard(cards[i], t);
  }

  function updateCard(card, t) {
    var period = card.acc.period || 30;
    var seconds = t / 1000;
    var counter = Math.floor(seconds / period);
    var remaining = period - (seconds % period);

    // Vòng đếm ngược
    card.ringEl.setAttribute('stroke-dashoffset', (RING_C * (1 - remaining / period)).toFixed(2));
    card.secEl.textContent = Math.ceil(remaining);
    card.el.classList.toggle('expiring', remaining <= 5);

    if (card.el.hidden || card.counter === counter || card.pending) return;

    card.pending = true;
    TOTP.generate(card.acc, t).then(function (res) {
      card.pending = false;
      card.counter = res.counter;
      card.code = res.code;
      card.next = res.next;
      card.codeEl.classList.remove('err');
      card.codeEl.textContent = groupDigits(res.code);
      card.nextEl.textContent = res.next;
      card.el.classList.remove('invalid');
    }, function (err) {
      card.pending = false;
      card.counter = counter;
      card.code = null;
      card.codeEl.classList.add('err');
      card.codeEl.textContent = err.message || 'Lỗi sinh mã';
      card.nextEl.textContent = '------';
      card.el.classList.add('invalid');
    });
  }

  // 123456 -> "123 456" cho dễ đọc
  function groupDigits(code) {
    if (code.length === 6) return code.slice(0, 3) + ' ' + code.slice(3);
    if (code.length === 8) return code.slice(0, 4) + ' ' + code.slice(4);
    return code;
  }

  /* ---------------- Render ---------------- */

  function rebuildCards() {
    cards = [];
    els.quickList.innerHTML = '';
    els.vaultList.innerHTML = '';

    quickEntries.forEach(function (acc) {
      var card = buildCard(acc, { saved: false });
      cards.push(card);
      els.quickList.appendChild(card.el);
    });

    accounts.forEach(function (acc) {
      var card = buildCard(acc, { saved: true });
      cards.push(card);
      els.vaultList.appendChild(card.el);
    });

    applyFilter();
    tick();
  }

  // Lọc bằng cách ẩn/hiện, không dựng lại thẻ — nếu không mã sẽ nháy về "••••••"
  // sau mỗi ký tự gõ vào ô tìm kiếm.
  function applyFilter() {
    // Nhóm đang xem có thể biến mất sau khi sửa/xoá tài khoản cuối cùng của nó.
    // Không tự đưa về "Tất cả" thì người dùng kẹt ở màn hình rỗng.
    if (activeGroup !== null && countIn(activeGroup) === 0) activeGroup = null;

    var visible = 0;
    for (var i = 0; i < cards.length; i++) {
      if (!cards[i].saved) continue;
      var show = matchesFilter(cards[i].acc);
      cards[i].el.hidden = !show;
      if (show) visible++;
    }

    els.vaultCount.textContent = accounts.length;
    renderGroupChips();

    if (!accounts.length) {
      els.vaultEmpty.hidden = false;
      els.vaultEmpty.textContent =
        'Chưa có tài khoản nào. Dán vào ô phía trên rồi bấm Lưu vào danh sách.';
    } else if (!visible) {
      els.vaultEmpty.hidden = false;
      els.vaultEmpty.textContent = emptyFilterMessage();
    } else {
      els.vaultEmpty.hidden = true;
    }

    refreshBulkBar();
  }

  function emptyFilterMessage() {
    var where = activeGroup === null ? ''
      : (activeGroup === '' ? ' trong mục "Chưa phân nhóm"' : ' trong nhóm "' + activeGroup + '"');
    if (!filter) return 'Không có tài khoản nào' + where + '.';
    return 'Không có tài khoản nào khớp "' + filter + '"' + where + '.';
  }

  // Nhóm và ô tìm kiếm kết hợp theo kiểu AND.
  function matchesFilter(acc) {
    if (activeGroup !== null && (acc.group || '') !== activeGroup) return false;
    if (!filter) return true;
    var q = filter.toLowerCase();
    var hay = acc.label + ' ' + acc.issuer + ' ' + acc.note + ' ' + (acc.group || '');
    return hay.toLowerCase().indexOf(q) !== -1;
  }

  /* ---------------- Nhóm ---------------- */

  // Danh sách nhóm suy ra từ chính các tài khoản, không lưu registry riêng —
  // nhờ vậy không bao giờ có nhóm mồ côi hay lệch trạng thái.
  function groupNames() {
    var seen = {};
    var names = [];
    accounts.forEach(function (a) {
      var g = a.group || '';
      if (!g || seen[g]) return;
      seen[g] = true;
      names.push(g);
    });
    return names.sort(function (a, b) { return a.localeCompare(b, 'vi'); });
  }

  // Màu suy ra tất định từ tên nhóm nên không cần lưu bảng màu ở đâu — vừa
  // không có trạng thái để lệch, vừa không đẩy tên nhóm ra vùng văn bản thường.
  function groupColorClass(name) {
    if (!name) return '';
    var h = 0;
    for (var i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
    return 'g' + (h % 8);
  }

  function countIn(group) {
    var n = 0;
    for (var i = 0; i < accounts.length; i++) {
      if ((accounts[i].group || '') === group) n++;
    }
    return n;
  }

  function chipHtml(label, count, groupValue, extraClass) {
    var pressed = (activeGroup === groupValue) ? 'true' : 'false';
    var cls = 'chip ' + (extraClass || '') + ' ' + groupColorClass(groupValue);
    return '<button type="button" class="' + cls.trim() + '" aria-pressed="' + pressed +
      '" data-group="' + (groupValue === null ? '__all__' : esc(groupValue)) + '">' +
      '<span class="chip-name">' + esc(label) + '</span>' +
      '<span class="chip-count">' + count + '</span></button>';
  }

  function renderGroupChips() {
    var names = groupNames();
    var ungrouped = countIn('');

    // Không có nhóm nào thì giấu cả thanh chip cho gọn.
    if (!accounts.length || (!names.length && !activeGroup)) {
      els.groupBar.hidden = true;
      els.groupBar.innerHTML = '';
      refreshGroupDatalist(names);
      return;
    }

    var html = chipHtml('Tất cả', accounts.length, null);
    names.forEach(function (g) { html += chipHtml(g, countIn(g), g); });
    if (ungrouped) html += chipHtml('Chưa phân nhóm', ungrouped, '', 'chip-none');

    els.groupBar.innerHTML = html;
    els.groupBar.hidden = false;
    refreshGroupDatalist(names);
  }

  function refreshGroupDatalist(names) {
    els.groupList.innerHTML = (names || groupNames())
      .map(function (g) { return '<option value="' + esc(g) + '"></option>'; })
      .join('');
  }

  /* ---------------- Chọn nhiều ---------------- */

  function selectedIds() {
    return accounts.filter(function (a) { return selected[a.id]; }).map(function (a) { return a.id; });
  }

  function toggleSelect(card) {
    var id = card.acc.id;
    if (selected[id]) delete selected[id];
    else selected[id] = true;
    card.el.classList.toggle('selected', !!selected[id]);
    refreshBulkBar();
  }

  function refreshBulkBar() {
    $('bulkBar').hidden = !selectMode;
    $('groupActions').hidden = selectMode || activeGroup === null || activeGroup === '';
    if (activeGroup) $('gaName').textContent = activeGroup;

    var n = selectedIds().length;
    $('bulkCount').textContent = n;
    ['btnBulkAssign', 'btnBulkUngroup', 'btnBulkDelete'].forEach(function (id) {
      $(id).disabled = n === 0;
    });
    $('btnSelectMode').textContent = selectMode ? 'Xong' : 'Chọn';
  }

  function setSelectMode(on) {
    selectMode = on;
    if (!on) selected = Object.create(null);
    rebuildCards();
    refreshBulkBar();
  }

  // Chỉ tác động lên các thẻ ĐANG HIỆN, để bộ lọc luôn là thứ giới hạn phạm vi.
  function visibleAccounts() {
    return accounts.filter(matchesFilter);
  }

  function applyToSelected(fn, verb) {
    var ids = selectedIds();
    if (!ids.length) return;
    var set = {};
    ids.forEach(function (id) { set[id] = true; });
    accounts.forEach(function (a) { if (set[a.id]) fn(a); });
    persist();
    rebuildCards();
    refreshBulkBar();
    toast(verb.replace('{n}', ids.length));
  }

  $('btnSelectMode').addEventListener('click', function () { setSelectMode(!selectMode); });

  $('btnBulkSelectAll').addEventListener('click', function () {
    visibleAccounts().forEach(function (a) { selected[a.id] = true; });
    rebuildCards();
    refreshBulkBar();
  });

  $('btnBulkClear').addEventListener('click', function () {
    selected = Object.create(null);
    rebuildCards();
    refreshBulkBar();
  });

  $('btnBulkAssign').addEventListener('click', function () {
    var g = $('bulkGroup').value.trim();
    if (!g) { toast('Nhập tên nhóm trước'); return; }
    applyToSelected(function (a) { a.group = g; }, 'Đã chuyển {n} tài khoản sang nhóm "' + g + '"');
    $('bulkGroup').value = '';
  });

  $('btnBulkUngroup').addEventListener('click', function () {
    applyToSelected(function (a) { a.group = ''; }, 'Đã bỏ {n} tài khoản khỏi nhóm');
  });

  $('btnBulkDelete').addEventListener('click', function () {
    var ids = selectedIds();
    if (!ids.length) return;
    if (!window.confirm('Xoá ' + ids.length + ' tài khoản đã chọn? Không thể hoàn tác.')) return;
    var set = {};
    ids.forEach(function (id) { set[id] = true; });
    accounts = accounts.filter(function (a) { return !set[a.id]; });
    selected = Object.create(null);
    persist();
    rebuildCards();
    refreshBulkBar();
    toast('Đã xoá ' + ids.length + ' tài khoản');
  });

  /* ---------------- Đổi tên / xoá nhóm ---------------- */

  // Nhóm suy ra từ dữ liệu nên đổi tên = cập nhật trường group của mọi thành viên.
  $('btnGroupRename').addEventListener('click', function () {
    if (!activeGroup) return;
    var old = activeGroup;
    var name = window.prompt('Tên mới cho nhóm "' + old + '":', old);
    if (name === null) return;
    name = name.trim().slice(0, 40);
    if (!name) { toast('Tên nhóm không được để trống'); return; }
    if (name === old) return;

    var merging = groupNames().indexOf(name) !== -1;
    if (merging && !window.confirm(
      'Nhóm "' + name + '" đã tồn tại. Gộp "' + old + '" vào nhóm đó?')) return;

    var n = 0;
    accounts.forEach(function (a) { if (a.group === old) { a.group = name; n++; } });
    activeGroup = name;
    persist();
    rebuildCards();
    toast((merging ? 'Đã gộp ' : 'Đã đổi tên nhóm, ') + n + ' tài khoản → "' + name + '"');
  });

  // Xoá nhóm KHÔNG xoá tài khoản — chúng chuyển về "Chưa phân nhóm".
  $('btnGroupDelete').addEventListener('click', function () {
    if (!activeGroup) return;
    var g = activeGroup;
    var n = countIn(g);
    if (!window.confirm(
      'Xoá nhóm "' + g + '"?\n\n' +
      n + ' tài khoản trong nhóm sẽ KHÔNG bị xoá, chúng chuyển về "Chưa phân nhóm".')) return;

    accounts.forEach(function (a) { if (a.group === g) a.group = ''; });
    activeGroup = null;
    persist();
    rebuildCards();
    toast('Đã xoá nhóm "' + g + '", ' + n + ' tài khoản về Chưa phân nhóm');
  });

  els.groupBar.addEventListener('click', function (ev) {
    var chip = ev.target.closest('.chip');
    if (!chip) return;
    var raw = chip.getAttribute('data-group');
    activeGroup = (raw === '__all__') ? null : raw;
    applyFilter();
    refreshBulkBar();
  });

  /* ---------------- Kéo thả sắp xếp ---------------- */

  var dragEl = null;

  els.vaultList.addEventListener('dragstart', function (ev) {
    var handle = ev.target.closest('.drag-handle');
    if (!handle) { ev.preventDefault(); return; }
    if (filter || activeGroup !== null) {
      ev.preventDefault();
      toast('Về "Tất cả" và xoá ô tìm kiếm trước khi sắp xếp lại');
      return;
    }
    dragEl = handle.closest('.acct');
    dragEl.classList.add('dragging');
    ev.dataTransfer.effectAllowed = 'move';
    ev.dataTransfer.setData('text/plain', dragEl.dataset.id);
    // Ảnh kéo là cả thẻ chứ không phải mỗi cái tay nắm.
    if (ev.dataTransfer.setDragImage) ev.dataTransfer.setDragImage(dragEl, 20, 20);
  });

  els.vaultList.addEventListener('dragover', function (ev) {
    if (!dragEl) return;
    ev.preventDefault();
    ev.dataTransfer.dropEffect = 'move';
    var over = ev.target.closest('.acct');
    if (!over || over === dragEl) return;
    var rect = over.getBoundingClientRect();
    var after = (ev.clientY - rect.top) > rect.height / 2;
    els.vaultList.insertBefore(dragEl, after ? over.nextSibling : over);
  });

  els.vaultList.addEventListener('drop', function (ev) { ev.preventDefault(); });

  els.vaultList.addEventListener('dragend', function () {
    if (!dragEl) return;
    dragEl.classList.remove('dragging');
    dragEl = null;
    commitOrder();
  });

  // Đọc thứ tự thật từ DOM rồi áp lại vào mảng accounts.
  function commitOrder() {
    var byId = {};
    accounts.forEach(function (a) { byId[a.id] = a; });

    var reordered = [];
    var nodes = els.vaultList.querySelectorAll('.acct');
    for (var i = 0; i < nodes.length; i++) {
      var acc = byId[nodes[i].dataset.id];
      if (acc) { reordered.push(acc); delete byId[acc.id]; }
    }
    // Thẻ đang bị lọc ẩn (nếu có) được giữ lại ở cuối, không mất.
    accounts.forEach(function (a) { if (byId[a.id]) reordered.push(a); });

    accounts = reordered;
    // cards phải khớp thứ tự mới để applyFilter đếm đúng
    cards.sort(function (x, y) {
      if (x.saved !== y.saved) return x.saved ? 1 : -1;
      if (!x.saved) return 0;
      return accounts.indexOf(x.acc) - accounts.indexOf(y.acc);
    });
    persist();
    toast('Đã lưu thứ tự mới');
  }

  /* ---------------- Nhập liệu ---------------- */

  function readInput() {
    var result = Parser.parseText(els.input.value);
    if (result.errors.length) {
      els.parseErrors.hidden = false;
      els.parseErrors.innerHTML =
        '<b>' + result.errors.length + ' dòng không đọc được:</b>' +
        result.errors.slice(0, 8).map(function (e) {
          return '<div>' + esc(e.line.slice(0, 90)) + ' — ' + esc(e.message) + '</div>';
        }).join('');
    } else {
      els.parseErrors.hidden = true;
      els.parseErrors.innerHTML = '';
    }
    return result;
  }

  // Nhóm lấy từ ô "Lưu vào nhóm". Cố ý KHÔNG thêm trường thứ tư vào
  // email|password|secret: quy tắc "phần cuối luôn là secret" chính là thứ cho phép
  // mật khẩu chứa ký tự '|', thêm |nhóm ở cuối sẽ phá vỡ nó.
  function pendingGroup() {
    return $('saveGroup').value.trim();
  }

  function generateFromInput() {
    if (locked) return;
    var result = readInput();
    var g = pendingGroup();
    quickEntries = result.entries.map(function (e) {
      return Vault.sanitize(Vault.assign({ id: Vault.newId(), group: g }, e));
    });
    rebuildCards();
    if (quickEntries.length) toast('Đã tạo mã cho ' + quickEntries.length + ' tài khoản');
    else if (!result.errors.length) toast('Chưa có gì để tạo mã');
  }

  function saveAccount(acc) {
    if (locked) return;
    var dup = accounts.filter(function (a) { return a.secret === acc.secret; })[0];
    if (dup) { toast('Secret này đã có trong danh sách (' + dup.label + ')'); return; }
    accounts.push(Vault.sanitize(Vault.assign({}, acc, { id: Vault.newId() })));
    persist();
    quickEntries = quickEntries.filter(function (a) { return a.secret !== acc.secret; });
    rebuildCards();
    toast('Đã lưu ' + acc.label);
  }

  function saveAllFromInput() {
    if (locked) return;
    var result = readInput();
    var entries = result.entries;
    if (!entries.length) { toast('Không có dòng nào hợp lệ để lưu'); return; }

    var existing = {};
    accounts.forEach(function (a) { existing[a.secret] = true; });

    var g = pendingGroup();
    var added = 0, skipped = 0;
    entries.forEach(function (e) {
      if (existing[e.secret]) { skipped++; return; }
      existing[e.secret] = true;
      accounts.push(Vault.sanitize(Vault.assign({ id: Vault.newId(), group: g }, e)));
      added++;
    });

    persist();
    quickEntries = [];
    els.input.value = '';
    rebuildCards();
    toast('Đã lưu ' + added + ' tài khoản' + (g ? ' vào nhóm "' + g + '"' : '') +
          (skipped ? ' (bỏ qua ' + skipped + ' trùng)' : ''));
  }

  /* ---------------- Dialog sửa ---------------- */

  var editing = null;

  function openEdit(acc) {
    editing = acc;
    $('editTitle').textContent = 'Sửa tài khoản';
    $('fLabel').value = acc.label;
    $('fPassword').value = acc.password || '';
    $('fSecret').value = acc.secret;
    $('fGroup').value = acc.group || '';
    $('fNote').value = acc.note || '';
    $('fDigits').value = String(acc.digits || 6);
    $('fPeriod').value = String(acc.period || 30);
    $('fAlgorithm').value = acc.algorithm || 'SHA-1';
    $('editError').hidden = true;
    els.editDialog.showModal();
  }

  $('editForm').addEventListener('submit', function (ev) {
    if (ev.submitter && ev.submitter.value === 'cancel') return;

    var secret = Base32.normalize($('fSecret').value);
    if (!Base32.isValid(secret)) {
      ev.preventDefault();
      var errEl = $('editError');
      errEl.textContent = 'Secret key không hợp lệ (chỉ gồm A–Z, 2–7, tối thiểu 8 ký tự).';
      errEl.hidden = false;
      return;
    }

    editing.label = $('fLabel').value.trim() || 'Không tên';
    editing.password = $('fPassword').value;
    editing.secret = secret;
    editing.group = $('fGroup').value.trim();
    editing.note = $('fNote').value.trim();
    editing.digits = parseInt($('fDigits').value, 10) || 6;
    editing.period = parseInt($('fPeriod').value, 10) || 30;
    editing.algorithm = $('fAlgorithm').value;

    persist();
    rebuildCards();
    toast('Đã cập nhật');
  });

  /* ---------------- Mã hoá vault ---------------- */

  // Dialog đặt mật khẩu, dùng chung cho "bật mã hoá" và "đổi mật khẩu".
  var pwResolve = null;

  function askPassword(title, intro) {
    $('pwTitle').textContent = title;
    $('pwIntro').textContent = intro || '';
    $('pwNew').value = '';
    $('pwConfirm').value = '';
    $('pwError').hidden = true;
    els.pwDialog.showModal();
    $('pwNew').focus();
    return new Promise(function (resolve) { pwResolve = resolve; });
  }

  $('pwForm').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var pw = $('pwNew').value;
    var confirm2 = $('pwConfirm').value;
    var err = $('pwError');

    if (pw.length < 8) {
      err.textContent = 'Mật khẩu cần ít nhất 8 ký tự.';
      err.hidden = false;
      return;
    }
    if (pw !== confirm2) {
      err.textContent = 'Hai ô mật khẩu không khớp.';
      err.hidden = false;
      return;
    }

    els.pwDialog.close();
    var resolve = pwResolve;
    pwResolve = null;
    if (resolve) resolve(pw);
  });

  $('btnPwCancel').addEventListener('click', function () {
    els.pwDialog.close();
    var resolve = pwResolve;
    pwResolve = null;
    if (resolve) resolve(null);
  });

  els.pwDialog.addEventListener('close', function () {
    var resolve = pwResolve;
    pwResolve = null;
    if (resolve) resolve(null);
  });

  function enableEncryption() {
    if (!VaultCrypto.available()) { toast(cryptoUnavailableMsg()); return; }

    askPassword('Bật mã hoá', 'Toàn bộ secret key sẽ được mã hoá AES-256-GCM trước khi ghi xuống trình duyệt.')
      .then(function (pw) {
        if (!pw) return;
        var kdf = VaultCrypto.newKdfParams();
        busy(true, 'Đang tạo khoá (~1 giây)…');
        return VaultCrypto.deriveFromParams(pw, kdf).then(function (key) {
          cryptoKey = key;
          enc.enabled = true;
          enc.kdf = kdf;
          return persist();
        }).then(function () {
          busy(false);
          refreshEncUi();
          toast('Đã bật mã hoá. Đừng quên mật khẩu này.');
        });
      })
      .catch(function (err) {
        busy(false);
        toast('Không bật được mã hoá: ' + (err.message || err));
      });
  }

  function changePassword() {
    if (!enc.enabled || !cryptoKey) return;
    askPassword('Đổi mật khẩu chính', 'Danh sách sẽ được mã hoá lại bằng mật khẩu mới.')
      .then(function (pw) {
        if (!pw) return;
        var kdf = VaultCrypto.newKdfParams();
        busy(true, 'Đang tạo khoá (~1 giây)…');
        return VaultCrypto.deriveFromParams(pw, kdf).then(function (key) {
          cryptoKey = key;
          enc.kdf = kdf;
          return persist();
        }).then(function () {
          busy(false);
          toast('Đã đổi mật khẩu');
        });
      })
      .catch(function (err) {
        busy(false);
        toast('Không đổi được mật khẩu: ' + (err.message || err));
      });
  }

  function disableEncryption() {
    if (!enc.enabled) return;
    if (!window.confirm(
      'Tắt mã hoá? Secret key sẽ quay lại dạng văn bản thường trong localStorage, ' +
      'ai mở trình duyệt này cũng đọc được.')) return;

    enc.enabled = false;
    enc.kdf = null;
    enc.iv = null;
    enc.ciphertext = null;
    cryptoKey = null;
    persist();
    refreshEncUi();
    toast('Đã tắt mã hoá');
  }

  function cryptoUnavailableMsg() {
    return 'Trình duyệt không cấp Web Crypto ở đây (thường do mở bằng file://). ' +
           'Hãy chạy qua http://localhost để dùng mã hoá.';
  }

  function refreshEncUi() {
    var supported = VaultCrypto.available();
    $('btnEncEnable').disabled = enc.enabled || !supported;
    $('btnEncChange').disabled = !enc.enabled || !cryptoKey;
    $('btnEncDisable').disabled = !enc.enabled || !cryptoKey;
    $('btnLock').hidden = !enc.enabled || locked;

    var status;
    if (!supported && !enc.enabled) status = 'Không khả dụng — ' + cryptoUnavailableMsg();
    else if (enc.enabled) status = 'Đang BẬT. Vault được mã hoá AES-256-GCM, khoá dẫn xuất bằng PBKDF2-SHA256 ' +
      VaultCrypto.ITERATIONS.toLocaleString('vi-VN') + ' vòng.';
    else status = 'Đang TẮT. Secret key nằm dạng văn bản thường trong localStorage.';
    $('encStatus').textContent = status;

    $('footSecurity').innerHTML = enc.enabled
      ? '<b>Bảo mật:</b> vault đang được mã hoá bằng mật khẩu chính. File backup xuất ra vẫn là văn bản thường — cất kỹ.'
      : '<b>Lưu ý bảo mật:</b> secret key được lưu dạng văn bản thường trong <code>localStorage</code> của trình duyệt này. ' +
        'Bật <b>mật khẩu chính</b> trong Cài đặt để mã hoá.';
  }

  /* ---------------- Khoá / mở khoá ---------------- */

  // Control phải tắt hẳn khi vault đang khoá. Lớp phủ .lock chỉ chặn được chuột và
  // bàn phím thật; listener bên dưới vẫn sống và vẫn chạy nếu bị gọi bằng script.
  // Trình duyệt KHÔNG dispatch click lên form control đang disabled — kể cả khi gọi
  // element.click() — nên đây là lớp chặn được cả tương tác lập trình.
  var LOCKABLE_IDS = [
    'input', 'saveGroup', 'btnGenerate', 'btnSaveAll', 'btnClearInput', 'btnFormatHelp',
    'search', 'btnSelectMode', 'btnExportJson', 'btnExportTxt', 'btnImport', 'fileImport',
    'bulkGroup', 'btnBulkAssign', 'btnBulkUngroup', 'btnBulkSelectAll', 'btnBulkClear',
    'btnBulkDelete', 'btnGroupRename', 'btnGroupDelete',
    'btnSettings', 'btnGuide', 'btnTheme'
  ];

  function setAppEnabled(on) {
    for (var i = 0; i < LOCKABLE_IDS.length; i++) {
      var el = $(LOCKABLE_IDS[i]);
      if (el) el.disabled = !on;
    }
    // inert loại cả nhánh DOM khỏi thứ tự Tab và khỏi accessibility tree. Thiếu nó
    // thì người dùng bàn phím vẫn Tab được xuống phần đang bị che, mà disabled không
    // xử lý được cho phần tử không phải form control (link, thẻ tài khoản…).
    // Trình duyệt cũ bỏ qua thuộc tính này vô hại — vẫn còn lớp disabled và lớp guard.
    if (els.main) els.main.inert = !on;
    if (els.foot) els.foot.inert = !on;
  }

  function showLock(message) {
    locked = true;
    els.lockScreen.hidden = false;
    $('lockPw').value = '';
    var err = $('lockErr');
    if (message) { err.textContent = message; err.hidden = false; }
    else err.hidden = true;
    $('btnUnlock').disabled = !VaultCrypto.available();
    setAppEnabled(false);
    setTimeout(function () { $('lockPw').focus(); }, 30);
  }

  function hideLock() {
    locked = false;
    els.lockScreen.hidden = true;
    setAppEnabled(true);
  }

  function lockNow() {
    if (!enc.enabled || locked) return;
    cryptoKey = null;
    accounts = [];
    quickEntries = [];
    els.input.value = '';
    filter = '';
    els.search.value = '';
    activeGroup = null;
    selectMode = false;
    selected = Object.create(null);
    $('saveGroup').value = '';
    $('bulkGroup').value = '';
    rebuildCards();
    if (els.settingsDialog.open) els.settingsDialog.close();
    if (els.editDialog.open) els.editDialog.close();
    showLock();
    refreshEncUi();
  }

  $('lockForm').addEventListener('submit', function (ev) {
    ev.preventDefault();
    if (!VaultCrypto.available()) return;

    var pw = $('lockPw').value;
    if (!pw) return;
    var err = $('lockErr');
    err.hidden = true;
    busy(true, 'Đang giải mã (~1 giây)…');

    VaultCrypto.deriveFromParams(pw, enc.kdf)
      .then(function (key) {
        return VaultCrypto.decrypt(key, enc.iv, enc.ciphertext).then(function (json) {
          var data = JSON.parse(json);
          cryptoKey = key;
          accounts = (data.accounts || []).map(Vault.sanitize);
          busy(false);
          hideLock();
          rebuildCards();
          refreshEncUi();
          markActivity();
          toast('Đã mở khoá — ' + accounts.length + ' tài khoản');
        });
      })
      .catch(function () {
        // AES-GCM tự xác thực: sai mật khẩu là giải mã ném lỗi, không cần lưu hash riêng.
        busy(false);
        err.textContent = 'Sai mật khẩu.';
        err.hidden = false;
        $('lockPw').select();
      });
  });

  $('btnForgot').addEventListener('click', function () {
    window.alert(
      'Không có cách khôi phục.\n\n' +
      'Khoá mã hoá được dẫn xuất trực tiếp từ mật khẩu bạn gõ vào và không được lưu ở ' +
      'bất kỳ đâu — không trên máy bạn, không ở server nào. Không ai mở khoá hộ bạn được, ' +
      'kể cả người làm ra trang này.\n\n' +
      'CÓ file backup .json/.txt đã xuất trước đó:\n' +
      'Bấm "Xoá toàn bộ dữ liệu và bắt đầu lại" ngay dưới, rồi dùng "Nhập file" để khôi phục.\n\n' +
      'KHÔNG có backup:\n' +
      'Secret key đã mất vĩnh viễn. Bạn phải vào từng dịch vụ (Google, Facebook…), ' +
      'đăng nhập bằng mã dự phòng hoặc email, rồi thiết lập lại 2FA từ đầu để lấy secret mới.'
    );
  });

  $('btnLock').addEventListener('click', lockNow);

  /* ---------------- Tự khoá khi không dùng ---------------- */

  function markActivity() { lastActivity = Date.now(); }

  ['mousedown', 'keydown', 'touchstart', 'wheel'].forEach(function (evt) {
    document.addEventListener(evt, markActivity, { passive: true, capture: true });
  });

  setInterval(function () {
    var minutes = parseInt(settings.autoLockMinutes, 10) || 0;
    if (!minutes || !enc.enabled || locked || !cryptoKey) return;
    if (Date.now() - lastActivity >= minutes * 60000) {
      lockNow();
      toast('Đã tự khoá sau ' + minutes + ' phút không dùng');
    }
  }, 5000);

  /* ---------------- Import / Export ---------------- */

  function download(filename, text, mime) {
    var blob = new Blob([text], { type: mime || 'text/plain;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function stamp() {
    var d = new Date();
    function p(n) { return (n < 10 ? '0' : '') + n; }
    return d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '-' + p(d.getHours()) + p(d.getMinutes());
  }

  function exportJson() {
    if (locked) return;
    if (!accounts.length) { toast('Danh sách trống'); return; }
    download('2fa-backup-' + stamp() + '.json',
      JSON.stringify({ version: Vault.VERSION, exportedAt: new Date().toISOString(), accounts: accounts }, null, 2),
      'application/json');
    toast('File backup chứa secret dạng thường — cất kỹ');
  }

  function exportTxt() {
    if (locked) return;
    if (!accounts.length) { toast('Danh sách trống'); return; }
    var lines = accounts.map(function (a) {
      return a.password ? a.label + '|' + a.password + '|' + a.secret : a.label + '|' + a.secret;
    });
    download('2fa-backup-' + stamp() + '.txt', lines.join('\r\n'));
    toast('File backup chứa secret dạng thường — cất kỹ');
  }

  function importFile(file) {
    if (locked) return;
    var reader = new FileReader();
    reader.onload = function () {
      var text = String(reader.result || '');
      var entries = [];

      if (/^\s*[{[]/.test(text)) {
        try {
          var data = JSON.parse(text);
          var list = Array.isArray(data) ? data : (data.accounts || []);
          entries = list.map(function (a) { return Vault.sanitize(a); });
        } catch (err) {
          toast('File JSON hỏng');
          return;
        }
      } else {
        var parsed = Parser.parseText(text);
        entries = parsed.entries.map(function (e) { return Vault.sanitize(Vault.assign({ id: Vault.newId() }, e)); });
        if (parsed.errors.length) toast(parsed.errors.length + ' dòng bị bỏ qua');
      }

      var existing = {};
      accounts.forEach(function (a) { existing[a.secret] = true; });

      var added = 0;
      entries.forEach(function (e) {
        if (!e.secret || existing[e.secret]) return;
        existing[e.secret] = true;
        e.id = Vault.newId();
        accounts.push(e);
        added++;
      });

      persist();
      rebuildCards();
      toast('Đã nhập ' + added + ' tài khoản');
    };
    reader.readAsText(file);
  }

  /* ---------------- Cài đặt ---------------- */

  function applyTheme() {
    document.documentElement.setAttribute('data-theme', settings.theme);
  }

  function openSettings() {
    if (locked) return;
    $('sReveal').checked = !!settings.revealSecrets;
    $('sShowPw').checked = !!settings.showPasswords;
    $('sOffset').value = settings.timeOffset || 0;
    $('sAutoLock').value = String(settings.autoLockMinutes);
    refreshEncUi();
    els.settingsDialog.showModal();
  }

  function readSettingsForm() {
    settings.revealSecrets = $('sReveal').checked;
    settings.showPasswords = $('sShowPw').checked;
    settings.timeOffset = parseInt($('sOffset').value, 10) || 0;
    settings.autoLockMinutes = parseInt($('sAutoLock').value, 10) || 0;
    persistSettings();
    rebuildCards();
  }

  ['sReveal', 'sShowPw', 'sOffset', 'sAutoLock'].forEach(function (id) {
    $(id).addEventListener('change', readSettingsForm);
  });

  $('btnEncEnable').addEventListener('click', enableEncryption);
  $('btnEncChange').addEventListener('click', changePassword);
  $('btnEncDisable').addEventListener('click', disableEncryption);

  function wipeAll() {
    accounts = [];
    quickEntries = [];
    enc = { enabled: false, kdf: null, iv: null, ciphertext: null };
    cryptoKey = null;
    Vault.clear();
    settings = Vault.assign({}, Vault.DEFAULT_SETTINGS);
    els.input.value = '';
    filter = '';
    els.search.value = '';
    activeGroup = null;
    selectMode = false;
    selected = Object.create(null);
    $('saveGroup').value = '';
    $('bulkGroup').value = '';
    hideLock();
    applyTheme();
    applyGuideState();
    rebuildCards();
    refreshEncUi();
    toast('Đã xoá toàn bộ dữ liệu');
  }

  $('btnWipe').addEventListener('click', function () {
    if (!window.confirm('Xoá TOÀN BỘ tài khoản đã lưu? Không thể hoàn tác.')) return;
    if (!window.confirm('Chắc chắn chứ? Hãy xuất backup trước nếu cần.')) return;
    if (els.settingsDialog.open) els.settingsDialog.close();
    wipeAll();
  });

  // Lối thoát duy nhất khi quên mật khẩu: màn khoá che kín trang nên không thể
  // với tới nút Xoá trong Cài đặt.
  $('btnLockWipe').addEventListener('click', function () {
    if (!window.confirm(
      'XOÁ TOÀN BỘ DỮ LIỆU?\n\n' +
      'Danh sách đang mã hoá sẽ bị xoá vĩnh viễn. Nếu bạn KHÔNG có file backup ' +
      '.json/.txt đã xuất trước đó, toàn bộ secret key sẽ mất và không lấy lại được.')) return;
    if (!window.confirm('Xác nhận lần cuối: xoá sạch và bắt đầu lại từ đầu?')) return;
    wipeAll();
  });

  /* ---------------- Gắn sự kiện ---------------- */

  $('btnGenerate').addEventListener('click', generateFromInput);
  $('btnSaveAll').addEventListener('click', saveAllFromInput);
  $('btnClearInput').addEventListener('click', function () {
    els.input.value = '';
    quickEntries = [];
    els.parseErrors.hidden = true;
    rebuildCards();
    els.input.focus();
  });

  /* ---------------- Hướng dẫn sử dụng ---------------- */

  function applyGuideState() {
    var open = !settings.guideDismissed;
    els.guide.hidden = !open;
    $('btnGuide').setAttribute('aria-expanded', String(open));
  }

  function toggleGuide(open) {
    settings.guideDismissed = !open;
    applyGuideState();
    persistSettings();
    if (open) els.guide.scrollIntoView({ block: 'start', behavior: 'smooth' });
  }

  $('btnGuide').addEventListener('click', function () {
    toggleGuide(els.guide.hidden);
  });
  $('btnGuideClose').addEventListener('click', function () { toggleGuide(false); });

  $('btnFormatHelp').addEventListener('click', function () {
    var help = $('formatHelp');
    help.hidden = !help.hidden;
  });

  els.input.addEventListener('keydown', function (ev) {
    if ((ev.ctrlKey || ev.metaKey) && ev.key === 'Enter') generateFromInput();
  });

  els.search.addEventListener('input', function () {
    filter = els.search.value.trim();
    applyFilter();
  });

  $('btnExportJson').addEventListener('click', exportJson);
  $('btnExportTxt').addEventListener('click', exportTxt);
  $('btnImport').addEventListener('click', function () { $('fileImport').click(); });
  $('fileImport').addEventListener('change', function (ev) {
    if (ev.target.files && ev.target.files[0]) importFile(ev.target.files[0]);
    ev.target.value = '';
  });

  $('btnSettings').addEventListener('click', openSettings);
  $('btnTheme').addEventListener('click', function () {
    settings.theme = settings.theme === 'dark' ? 'light' : 'dark';
    applyTheme();
    persistSettings();
  });

  /* ---------------- Khởi động ---------------- */

  (function boot() {
    var raw = Vault.readRaw();
    settings = Vault.readSettings(raw);
    applyTheme();

    if (raw && raw.encrypted) {
      enc.enabled = true;
      enc.kdf = raw.kdf;
      enc.iv = raw.iv;
      enc.ciphertext = raw.ciphertext;
      rebuildCards();
      refreshEncUi();
      showLock(VaultCrypto.available()
        ? null
        : 'Vault đã mã hoá nhưng trình duyệt không cấp Web Crypto ở đây. Hãy mở trang qua http://localhost.');
    } else {
      accounts = ((raw && raw.accounts) || []).map(Vault.sanitize);
      rebuildCards();
      refreshEncUi();
    }

    applyGuideState();
  })();

  setInterval(tick, 200);

  setInterval(function () {
    var el = $('clockNow');
    if (el && els.settingsDialog.open) el.textContent = new Date(nowMs()).toLocaleTimeString('vi-VN');
  }, 1000);

  // Cho người dùng biết đang chạy bằng Web Crypto hay bản dự phòng JS.
  els.cryptoNote.textContent = (window.crypto && window.crypto.subtle)
    ? 'Đang dùng Web Crypto của trình duyệt. Trang này không gửi request nào ra ngoài.'
    : 'Web Crypto không khả dụng (thường do mở bằng file://) — đang dùng bản HMAC thuần JS. SHA-1/SHA-256 vẫn chạy đúng; SHA-512 và mã hoá vault cần chạy qua http://localhost.';

  if ('serviceWorker' in navigator && location.protocol.indexOf('http') === 0) {
    navigator.serviceWorker.register('sw.js').catch(function () { /* bỏ qua */ });
  }
})();
