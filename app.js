/* ARGUS 관리자 사이트 (2026-10-30) - a static page on GitHub Pages. Everything under data/ and img/ is AES-256-GCM encrypted by the
   inspection PC (backend/app/admin_site.py); the key is derived here from the password (PBKDF2-SHA256, salt and rounds from site.json)
   and never leaves the browser. No external scripts, no server: fetch, decrypt, render. */
(() => {
  'use strict';

  const LS_KEY = 'argus-admin-key:';   // the first version kept an exported key here: only cleared now
  const FORMAT_V = 1;                  // data format this page reads (admin_site.FORMAT_V)
  const REMEMBER_DAYS = 30;
  const PAGE = 300;
  const FIND_CAP = 500;
  const VERDICT_KO = { PASS: '양품', NG: '불량', REVIEW: '확인 필요' };
  const WEEK = ['일', '월', '화', '수', '목', '금', '토'];
  const S = { site: null, key: null, index: null, days: new Map(), preset: '7', range: null, filter: 'all', dayq: '', view: null, shown: PAGE,
              overlayUrls: [], lastSynced: null, lastRefresh: 0, detailFrom: null };
  const app = document.getElementById('app');

  // ---------------------------------------------------------------- DOM helpers (text always through textContent)
  function h(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === 'class') e.className = v;
      else if (k === 'text') e.textContent = v;
      else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v === true ? '' : String(v));
    }
    for (const c of kids.flat()) { if (c == null || c === false) continue; e.append(c instanceof Node ? c : document.createTextNode(String(c))); }
    return e;
  }
  const SVGNS = 'http://www.w3.org/2000/svg';
  function sv(tag, attrs, ...kids) {
    const e = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) if (v != null) e.setAttribute(k, String(v));
    for (const c of kids.flat()) if (c != null) e.append(c instanceof Node ? c : document.createTextNode(String(c)));
    return e;
  }
  const $ = (q, root = document) => root.querySelector(q);
  const fmt = (n) => (n ?? 0).toLocaleString('ko-KR');
  function pctTxt(a, b) { if (!b) return '–'; const p = (100 * a) / b; return (p > 0 && p < 10 ? p.toFixed(2) : p.toFixed(1)) + '%'; }
  function badge(v) { return h('span', { class: 'badge ' + (VERDICT_KO[v] ? v : 'none') }, VERDICT_KO[v] || '없음'); }
  function dow(d) { return WEEK[new Date(d + 'T00:00:00Z').getUTCDay()]; }
  function kstToday() { return new Intl.DateTimeFormat('sv-SE', { timeZone: 'Asia/Seoul' }).format(new Date()); }
  function addDays(d, n) { const t = new Date(d + 'T00:00:00Z'); t.setUTCDate(t.getUTCDate() + n); return t.toISOString().slice(0, 10); }
  function hhmm(ts) { return ts ? ts.slice(11, 19) : ''; }
  let toastTimer = null;
  function toast(msg) {
    let t = $('.toast'); if (!t) { t = h('div', { class: 'toast', role: 'status' }); document.body.append(t); }
    t.textContent = msg; clearTimeout(toastTimer); toastTimer = setTimeout(() => t.remove(), 3500);
  }

  // ---------------------------------------------------------------- crypto
  const te = new TextEncoder(), td = new TextDecoder();
  function b64d(s) { const b = atob(s); const u = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); return u; }
  async function deriveKey(pw, extractable) {
    const base = await crypto.subtle.importKey('raw', te.encode(pw.normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64d(S.site.salt), iterations: S.site.iter, hash: 'SHA-256' }, base,
      { name: 'AES-GCM', length: 256 }, extractable, ['decrypt']);
  }
  async function decryptWith(key, buf) { const u = new Uint8Array(buf); return crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12) }, key, u.slice(12)); }
  async function decrypt(buf) { return decryptWith(S.key, buf); }
  async function gunzip(buf) { return new Response(new Blob([buf]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer(); }
  async function fetchBin(path, fresh) {
    const r = await fetch(path, { cache: fresh ? 'no-store' : 'default' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.arrayBuffer();
  }
  async function unpack(buf) {   // b'ARGP' + 4-byte length + gzip, zero-padded to 16 KB (admin_site._encrypt_json)
    let u = new Uint8Array(buf);
    if (u.length >= 8 && u[0] === 0x41 && u[1] === 0x52 && u[2] === 0x47 && u[3] === 0x50) u = u.slice(8, 8 + new DataView(buf).getUint32(4, false));
    return JSON.parse(td.decode(await gunzip(u)));
  }
  async function getJSON(path, fresh) { return unpack(await decrypt(await fetchBin(path, fresh))); }
  async function getImage(path) { return URL.createObjectURL(new Blob([await decrypt(await fetchBin(path))], { type: 'image/jpeg' })); }
  // '이 기기에서 기억하기': the derived key itself as a NON-extractable CryptoKey in IndexedDB (usable here, never readable as bytes), 30 days
  const IDB_SLOT = 'site:' + location.pathname;
  function idbOpen() {
    return new Promise((res, rej) => { const r = indexedDB.open('argus-admin', 1); r.onupgradeneeded = () => r.result.createObjectStore('keys'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
  }
  async function idbDo(mode, fn) {
    const db = await idbOpen();
    return new Promise((res, rej) => {
      const tx = db.transaction('keys', mode), req = fn(tx.objectStore('keys'));
      tx.oncomplete = () => { db.close(); res(req ? req.result : undefined); };
      tx.onerror = tx.onabort = () => { db.close(); rej(tx.error); };
    });
  }
  async function remembered() {
    try { const v = await idbDo('readonly', (st) => st.get(IDB_SLOT)); if (v && v.key && v.salt === S.site.salt && v.exp > Date.now()) return v.key; } catch { /* storage blocked */ }
    return null;
  }
  async function remember(key) {
    try { await idbDo('readwrite', (st) => st.put({ key, salt: S.site.salt, exp: Date.now() + REMEMBER_DAYS * 864e5 }, IDB_SLOT)); return true; } catch { return false; }
  }
  async function forget() {
    try { Object.keys(localStorage).filter((k) => k.startsWith(LS_KEY)).forEach((k) => localStorage.removeItem(k)); } catch { /* storage blocked */ }
    try { await idbDo('readwrite', (st) => st.delete(IDB_SLOT)); } catch { /* storage blocked */ }
  }
  async function fetchSite() { return (await fetch('site.json?t=' + Date.now(), { cache: 'no-store' })).json(); }
  // a key that stops opening the data, or a file that is gone, may mean a new password on the inspection PC: the salt in site.json tells
  async function passwordChanged(ex) {
    if (!(ex && (ex.name === 'OperationError' || /HTTP 404/.test(String(ex.message))))) return false;
    let site; try { site = await fetchSite(); } catch { return false; }
    if (!site || !site.salt || site.salt === S.site.salt) return false;
    S.site = site;
    await forget();
    S.key = null; S.pkey = null; S.index = null; S.days.clear(); closeOverlay();
    renderLogin('검사기에서 사이트 비밀번호가 바뀌었습니다. 새 비밀번호를 입력하세요.');
    return true;
  }
  function errText(ex) { return ex && ex.name === 'OperationError' ? '데이터를 풀지 못했습니다' : (ex && ex.message) || String(ex); }

  // ---------------------------------------------------------------- data
  async function loadIndex() {
    const idx = await getJSON('data/index.bin?t=' + Date.now(), true);
    if (idx.v && idx.v > FORMAT_V) { const e = new Error('사이트가 새 버전으로 바뀌었습니다. 페이지를 새로 고치세요.'); e.name = 'FormatError'; throw e; }
    S.lastRefresh = Date.now();
    if (S.index && S.index.e !== idx.e) S.days.clear();
    S.pkey = null;   // the Google Drive photos' own key (admin_drive.py), delivered inside this encrypted index
    if (idx.pk && idx.gk) { try { S.pkey = await crypto.subtle.importKey('raw', b64d(idx.pk), { name: 'AES-GCM' }, false, ['decrypt']); } catch { S.pkey = null; } }
    S.index = idx;
    S.lastSynced = idx.synced;
  }
  function dayStat(d) { return (S.index.days || []).find((x) => x.d === d); }
  async function loadDay(d) {
    const st = dayStat(d); if (!st) return null;
    const ck = d + '|' + st.h;
    if (S.days.has(ck)) return S.days.get(ck);
    const day = await getJSON('data/days/' + encodeURIComponent(st.f) + '.bin?h=' + encodeURIComponent(st.h || ''), false);
    for (const k of [...S.days.keys()]) if (k.startsWith(d + '|')) S.days.delete(k);
    S.days.set(ck, day);
    return day;
  }
  function presetRange(p) {
    const days = S.index.days || [], today = kstToday();
    const first = days.length ? days[0].d : today, last = days.length ? days[days.length - 1].d : today;
    if (p === 'today') return [today, today];
    if (p === 'yday') return [addDays(today, -1), addDays(today, -1)];
    if (p === '7') return [addDays(today, -6), today];
    if (p === '30') return [addDays(today, -29), today];
    if (p === 'all') return [first, last > today ? last : today];
    return S.range || [addDays(today, -6), today];
  }
  function daysIn(range) { return (S.index.days || []).filter((x) => x.d >= range[0] && x.d <= range[1]); }
  function totals(days) {
    const t = { n: 0, p: 0, ng: 0, rv: 0, inc: 0 };
    for (const d of days) { t.n += d.n; t.p += d.p; t.ng += d.ng; t.rv += d.rv; t.inc += d.inc || 0; }
    return t;
  }

  // ---------------------------------------------------------------- boot / login
  async function boot() {
    if (!window.crypto || !crypto.subtle || typeof DecompressionStream === 'undefined') return fatal('이 브라우저에서는 열 수 없습니다. 최신 Chrome·Safari·Edge 로 여세요.');
    try { S.site = await fetchSite(); } catch { return fatal('사이트 정보를 읽지 못했습니다. 잠시 뒤 다시 여세요.'); }
    if (!S.site || !S.site.salt) return fatal('아직 검사기에서 데이터가 올라오지 않았습니다.');
    const saved = await remembered();
    if (saved) {
      S.key = saved;
      try { await loadIndex(); return start(); } catch (ex) {
        S.key = null;
        if (ex && ex.name === 'FormatError') return fatal(ex.message);
        if (ex && ex.name === 'OperationError') { await forget(); return renderLogin('비밀번호가 바뀌었습니다. 새 비밀번호를 입력하세요.'); }
        return renderLogin('데이터를 불러오지 못했습니다(' + errText(ex) + '). 비밀번호를 입력하거나 잠시 뒤 다시 여세요.');
      }
    }
    renderLogin('');
  }
  function fatal(msg) { app.replaceChildren(h('div', { class: 'login' }, h('div', { class: 'card' }, h('h1', { text: 'ARGUS 검사 기록' }), h('p', { text: msg })))); }
  function renderLogin(err) {
    const pw = h('input', { class: 'input', type: 'password', id: 'pw', autocomplete: 'current-password', required: true, placeholder: '비밀번호', 'aria-label': '비밀번호' });
    const rem = h('input', { type: 'checkbox', id: 'remember' });
    if (!window.indexedDB) rem.disabled = true;
    const go = h('button', { class: 'btn primary', type: 'submit' }, '열기');
    const msg = h('p', { class: 'err', role: 'alert' }, err || '');
    const form = h('form', { class: 'card', novalidate: true }, h('h1', { text: 'ARGUS 검사 기록' }), h('p', { text: '관리자 비밀번호를 입력하세요.' }),
      h('label', { class: 'field' }, pw), h('label', { class: 'check' }, rem, `이 기기에서 ${REMEMBER_DAYS}일 기억하기 (개인 기기에서만)`), go, msg);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!pw.value) { msg.textContent = '비밀번호를 입력하세요.'; return; }
      go.disabled = true; go.replaceChildren(h('span', { class: 'spinner' }), ' 확인 중'); msg.textContent = '';
      try {
        try { S.site = await fetchSite(); } catch { /* keep the one read at start */ }   // a password changed while this page stood open
        S.key = await deriveKey(pw.value, false);
        await loadIndex();
        if (rem.checked && !(await remember(S.key))) toast('이 브라우저에서는 기억할 수 없습니다 (사생활 보호 모드 등)');
        pw.value = '';
        start();
      } catch (ex) {
        S.key = null;
        msg.textContent = ex && ex.name === 'OperationError' ? '비밀번호가 맞지 않습니다.' : '열지 못했습니다: ' + errText(ex);
        go.disabled = false; go.textContent = '열기'; pw.select();
      }
    });
    app.replaceChildren(h('div', { class: 'login' }, form));
    pw.focus();
  }
  function lock() { forget(); S.key = null; S.pkey = null; S.index = null; S.days.clear(); closeOverlay(); history.replaceState(null, '', location.pathname); renderLogin(''); }

  let refreshTimer = null;
  function start() {
    S.range = presetRange(S.preset);
    window.removeEventListener('hashchange', route);
    window.addEventListener('hashchange', route);
    clearInterval(refreshTimer);
    refreshTimer = setInterval(() => { if (document.visibilityState === 'visible' && S.key) refresh(true); }, 5 * 60 * 1000);
    route();
  }
  document.addEventListener('visibilitychange', () => {   // a phone brought back after a while: catch up at once
    if (document.visibilityState === 'visible' && S.key && S.index && Date.now() - S.lastRefresh > 2 * 60 * 1000) refresh(true);
  });
  async function refresh(quiet) {
    const before = S.lastSynced;
    try { await loadIndex(); } catch (ex) {
      if (await passwordChanged(ex)) return;
      if (ex && ex.name === 'FormatError') { toast(ex.message); return; }
      if (!quiet) toast('새로고침 실패: ' + errText(ex));
      return;
    }
    if (!quiet || S.lastSynced !== before) { if (S.preset !== 'custom') S.range = presetRange(S.preset); const keep = S.view; S.view = null; route(keep); }
    if (!quiet) toast(S.lastSynced !== before ? '새 데이터를 받았습니다' : '최신 상태입니다');
  }

  // ---------------------------------------------------------------- shell
  function topBar() {
    const sync = S.index.synced ? S.index.synced.replace('T', ' ').slice(5, 16) : '–';
    return h('header', { class: 'top' }, h('div', { class: 'wrap' },
      h('a', { class: 'brand', href: '#/' }, 'ARGUS 검사 기록', h('small', null, S.index.pc || '')),
      h('div', { class: 'grow' }, h('div', { class: 'sync', title: '검사기가 마지막으로 올린 시각' }, h('span', { class: 'lbl' }, '갱신 '), sync)),
      h('button', { class: 'btn sm', type: 'button', onclick: () => refresh(false) }, '새로고침'),
      h('button', { class: 'btn sm', type: 'button', onclick: lock, title: '이 기기에서 잠그고 기억한 비밀번호도 지웁니다' }, '잠금')));
  }
  function photoNote() {   // which records have a photo here (admin_site.photo_days; PHOTO_ALL = every day; gk = every record on Google Drive)
    if (S.index.gk) return '사진: 불량·확인 필요는 불량 표시 사진, 그 밖은 Google Drive 사진 (검사기에서 보존 기간이 지나 지워진 사진은 없음)';
    const pd = S.index.photo_days;
    if (!pd) return '사진은 올리지 않도록 설정되어 있습니다';
    return pd >= 3650 ? '사진은 불량·확인 필요 기록에 있습니다' : `사진은 최근 ${pd}일(${S.index.photos_from} 부터)의 불량·확인 필요 기록에 있습니다`;
  }
  function foot() {
    return h('footer', null, photoNote() + ' · ' +
      '모든 데이터는 암호화되어 이 기기에서만 풀립니다' + (S.index.build ? ' · ' + S.index.build : ''));
  }
  function route(prev) {
    if (!S.key || !S.index) return;
    const m = location.hash.match(/^#\/day\/(\d{4}-\d{2}-\d{2})(?:\/(\d+))?$/);
    const f = location.hash.match(/^#\/find\/(.+)$/);
    if (m) return showDay(m[1], m[2] ? parseInt(m[2], 10) : null);
    if (f) { let qs; try { qs = decodeURIComponent(f[1]); } catch { qs = f[1]; } return showFind(qs); }
    S.detailFrom = null;
    closeOverlay();
    S.view = { name: 'dash' };
    renderDashboard();
  }

  // ---------------------------------------------------------------- dashboard
  function filterRow(onRange) {
    const chips = [['today', '오늘'], ['yday', '어제'], ['7', '7일'], ['30', '30일'], ['all', '전체']].map(([p, label]) =>
      h('button', { class: 'chip', type: 'button', 'aria-pressed': String(S.preset === p), onclick: () => { S.preset = p; S.range = presetRange(p); onRange(); } }, label));
    const from = h('input', { type: 'date', value: S.range[0], 'aria-label': '시작일' });
    const to = h('input', { type: 'date', value: S.range[1], 'aria-label': '끝일' });
    const setCustom = () => { if (from.value && to.value) { S.preset = 'custom'; S.range = from.value <= to.value ? [from.value, to.value] : [to.value, from.value]; onRange(); } };
    from.addEventListener('change', setCustom); to.addEventListener('change', setCustom);
    const q = h('input', { type: 'search', placeholder: '바코드 찾기 (기간 안)', 'aria-label': '바코드 찾기', enterkeyhint: 'search' });
    q.addEventListener('keydown', (e) => { if (e.key === 'Enter' && q.value.trim()) location.hash = '#/find/' + encodeURIComponent(q.value.trim()); });
    const xl = h('button', { class: 'btn', type: 'button', onclick: (e) => exportRange(S.range, e.currentTarget) }, '엑셀 받기 (기판별)');
    return h('div', { class: 'filters' }, chips, h('span', { class: 'daterange' }, from, '~', to), h('span', { class: 'search' }, q), h('span', { class: 'spacer' }), xl);
  }
  function tile(label, value, sub, dotCls, hero) {
    return h('div', { class: 'tile' + (hero ? ' hero' : '') }, h('div', { class: 'label' }, dotCls ? h('span', { class: 'dot ' + dotCls }) : null, label),
      h('div', { class: 'value' }, value), sub ? h('div', { class: 'sub' }, sub) : null);
  }
  function renderDashboard() {
    const days = daysIn(S.range);
    const t = totals(days);
    const chartBox = h('div', { class: 'chart' });
    const main = h('main', { class: 'wrap' },
      filterRow(renderDashboard),
      h('div', { class: 'kpis' },
        tile('검사 기판', fmt(t.n), `${S.range[0] === S.range[1] ? S.range[0] : S.range[0] + ' ~ ' + S.range[1]}${t.inc ? ' · 앞·뒤 짝 없음 ' + fmt(t.inc) : ''}`, null, true),
        tile('양품', fmt(t.p), pctTxt(t.p, t.n), 'good'),
        tile('불량', fmt(t.ng), pctTxt(t.ng, t.n), 'bad'),
        tile('확인 필요', fmt(t.rv), pctTxt(t.rv, t.n), 'warn'),
        tile('불량률', pctTxt(t.ng, t.n), '불량 ÷ 검사 기판')),
      h('div', { class: 'grid2 section' },
        h('section', { class: 'card' }, h('h2', null, '일별 불량·확인 필요', h('span', { class: 'muted' }, '건수')),
          h('div', { class: 'legend' }, h('span', null, h('i', { class: 'ng' }), '불량'), h('span', null, h('i', { class: 'rv' }), '확인 필요')), chartBox),
        topCard(days)),
      dayTable(days),
      foot());
    app.replaceChildren(topBar(), main);
    drawChart(chartBox, days);
  }
  function topCard(days) {
    const agg = new Map();
    for (const d of days) for (const [c, t, n] of d.top || []) { const k = c + '\u0001' + t; agg.set(k, (agg.get(k) || 0) + n); }
    const rows = [...agg.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
    const max = rows.length ? rows[0][1] : 1;
    const body = rows.length ? h('div', { class: 'tablebox' }, h('table', null,
      h('thead', null, h('tr', null, h('th', null, '부품'), h('th', null, '유형'), h('th', { class: 'r' }, '건수'), h('th', null, ''))),
      h('tbody', null, rows.map(([k, n]) => {
        const [c, t] = k.split('\u0001');
        const bar = h('span', { class: 'mini-bar' }); bar.style.width = Math.max(4, Math.round((60 * n) / max)) + 'px';
        return h('tr', null, h('td', { class: 'mono' }, c), h('td', null, t), h('td', { class: 'r' }, fmt(n)), h('td', { class: 'bar-cell' }, bar));
      })))) : h('div', { class: 'empty' }, '이 기간에 남아 있는 불량·확인 필요 항목이 없습니다');
    return h('section', { class: 'card' }, h('h2', null, '많이 나온 항목', h('span', { class: 'muted' }, '작업자가 지운 것 제외')), body);
  }
  function dayTable(days) {
    const rows = [...days].reverse();
    return h('section', { class: 'card section' }, h('h2', null, '날짜별', h('span', { class: 'muted' }, '눌러서 기판 목록')),
      rows.length ? h('div', { class: 'tablebox' }, h('table', null,
        h('thead', null, h('tr', null, h('th', null, '날짜'), h('th', { class: 'r' }, '검사 기판'), h('th', { class: 'r' }, '양품'), h('th', { class: 'r' }, '불량'),
          h('th', { class: 'r' }, '확인 필요'), h('th', { class: 'r' }, '불량률'), h('th', { class: 'r' }, '짝 없음'))),
        h('tbody', null, rows.map((d) => {
          const tr = h('tr', { class: 'link', tabindex: '0' }, h('td', { class: 'num' }, `${d.d} (${dow(d.d)})`), h('td', { class: 'r' }, fmt(d.n)), h('td', { class: 'r' }, fmt(d.p)),
            h('td', { class: 'r' }, fmt(d.ng)), h('td', { class: 'r' }, fmt(d.rv)), h('td', { class: 'r' }, pctTxt(d.ng, d.n)), h('td', { class: 'r' }, fmt(d.inc || 0)));
          const go = () => { location.hash = '#/day/' + d.d; };
          tr.addEventListener('click', go); tr.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
          return tr;
        })))) : h('div', { class: 'empty' }, '이 기간에는 검사 기록이 없습니다'));
  }

  // ---------------------------------------------------------------- chart: daily NG + 확인 필요, stacked columns (status colours, legend + table twin)
  function niceMax(v) { if (v <= 5) return 5; const p = Math.pow(10, Math.floor(Math.log10(v))); const m = v / p; return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p; }
  function roundTop(x, yTop, w, hgt, r) {
    r = Math.min(r, w / 2, hgt);
    const yb = yTop + hgt;
    return `M${x},${yb}V${yTop + r}Q${x},${yTop} ${x + r},${yTop}H${x + w - r}Q${x + w},${yTop} ${x + w},${yTop + r}V${yb}Z`;
  }
  function drawChart(box, days) {
    box.replaceChildren();
    if (days.length < 2) { box.append(h('div', { class: 'empty' }, days.length ? '기간을 이틀 이상 고르면 일별 추이가 보입니다' : '이 기간에는 검사 기록이 없습니다')); return; }
    const W = Math.max(280, box.clientWidth || 600), H = 230, pl = 36, pr = 6, pt = 10, pb = 26;
    const top = niceMax(Math.max(1, ...days.map((d) => d.ng + d.rv)));
    const ph = H - pt - pb, slot = (W - pl - pr) / days.length, bw = Math.max(2, Math.min(24, slot * 0.62));
    const y = (v) => pt + ph * (1 - v / top);
    const svg = sv('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': '일별 불량·확인 필요 건수 막대 그래프 (아래 날짜별 표에 같은 값)' });
    for (let i = 0; i <= 4; i++) {
      const v = (top * i) / 4, yy = Math.round(y(v)) + 0.5;
      svg.append(sv('line', { class: i ? 'gridline' : 'baseline', x1: pl, x2: W - pr, y1: yy, y2: yy }));
      svg.append(sv('text', { class: 'tick', x: pl - 6, y: yy + 4, 'text-anchor': 'end' }, v >= 1000 ? (v / 1000).toFixed(v % 1000 ? 1 : 0) + 'K' : String(Math.round(v))));
    }
    const every = Math.max(1, Math.ceil(days.length / Math.max(2, Math.floor((W - pl) / 44))));
    const tip = h('div', { class: 'tooltip hidden', role: 'tooltip' });
    days.forEach((d, i) => {
      const x0 = pl + i * slot, x = x0 + (slot - bw) / 2, yb = y(0);
      const g = sv('g', { class: 'col', tabindex: '0', 'aria-label': `${d.d}: 불량 ${d.ng}, 확인 필요 ${d.rv}, 검사 기판 ${d.n}` });
      g.append(sv('rect', { class: 'hitbg', x: x0, y: pt, width: slot, height: ph, rx: 3 }));
      const hng = (d.ng / top) * ph, hrv = (d.rv / top) * ph, gap = d.ng && d.rv ? 2 : 0;
      if (d.ng) g.append(d.rv ? sv('rect', { class: 'seg-ng', x, y: yb - hng, width: bw, height: Math.max(1, hng) }) : sv('path', { class: 'seg-ng', d: roundTop(x, yb - Math.max(1, hng), bw, Math.max(1, hng), 4) }));
      if (d.rv) { const h2 = Math.max(1, hrv); g.append(sv('path', { class: 'seg-rv', d: roundTop(x, yb - hng - gap - h2, bw, h2, 4) })); }
      g.append(sv('rect', { class: 'hit', x: x0, y: pt, width: slot, height: ph + pb }));
      if (i % every === 0) svg.append(sv('text', { class: 'tick', x: x0 + slot / 2, y: H - 8, 'text-anchor': 'middle' }, d.d.slice(5)));
      const show = () => {
        tip.replaceChildren(h('div', { class: 't' }, `${d.d} (${dow(d.d)}) · 검사 ${fmt(d.n)}`),
          h('div', { class: 'r' }, h('i', { class: 'ng' }), h('b', null, fmt(d.ng)), '불량', h('span', { class: 'muted' }, pctTxt(d.ng, d.n))),
          h('div', { class: 'r' }, h('i', { class: 'rv' }), h('b', null, fmt(d.rv)), '확인 필요'));
        tip.classList.remove('hidden');
        const bx = box.getBoundingClientRect().width, scale = bx / W;
        let left = (x0 + slot / 2) * scale + 10;
        if (left + 170 > bx) left = (x0 + slot / 2) * scale - 180;
        tip.style.left = Math.max(0, left) + 'px'; tip.style.top = '8px';
      };
      const hide = () => tip.classList.add('hidden');
      g.addEventListener('pointerenter', show); g.addEventListener('pointerleave', hide); g.addEventListener('focus', show); g.addEventListener('blur', hide);
      g.addEventListener('click', () => { location.hash = '#/day/' + d.d; });
      g.addEventListener('keydown', (e) => { if (e.key === 'Enter') location.hash = '#/day/' + d.d; });
      svg.append(g);
    });
    box.append(svg, tip);
  }
  let resizeTimer = null;
  window.addEventListener('resize', () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => { if (S.view && S.view.name === 'dash') renderDashboard(); }, 200); });

  // ---------------------------------------------------------------- day list
  function unitSummary(u) {
    const p = [];
    if (u.f && u.f.s) p.push('앞: ' + u.f.s);
    if (u.b && u.b.s) p.push('뒤: ' + u.b.s);
    if (u.note) p.push(u.note);
    return p.join(' · ');
  }
  function unitRow(day, u, withDate) {
    const ts = [u.f ? '앞 ' + hhmm(u.f.ts) : null, u.b ? '뒤 ' + hhmm(u.b.ts) : null].filter(Boolean).join(' · ');
    return h('button', { class: 'row', type: 'button', onclick: () => { S.detailFrom = location.hash || '#/'; location.hash = `#/day/${day}/${u.n}`; } },
      h('span', { class: 'n' }, withDate ? day.slice(5) : u.n),
      h('span', { class: 'bc' }, u.bc || '(바코드 없음)'),
      h('span', { class: 'v' }, badge(u.v)),
      h('span', { class: 'ts' }, ts),
      h('span', { class: 'sum' }, unitSummary(u)));
  }
  let dayReq = 0;
  async function showDay(d, n) {
    if (S.view && S.view.name === 'day' && S.view.d === d) {   // same list: only the detail sheet changes, the scroll position stays
      if (n) openDetail(d, S.view.day.units.find((u) => u.n === n)); else { S.detailFrom = null; closeOverlay(); }
      return;
    }
    closeOverlay();
    const my = ++dayReq;
    const main = $('main'); if (main) main.classList.add('loading');
    let day, err = null;
    try { day = await loadDay(d); } catch (ex) {
      err = ex;
      if (await passwordChanged(ex)) return;
      if (/HTTP 404/.test(String(ex && ex.message))) {   // the day changed on the inspection PC since the index was read: read it again once
        try { await loadIndex(); day = await loadDay(d); err = null; } catch (ex2) { err = ex2; }
      }
    }
    if (my !== dayReq || !location.hash.startsWith('#/day/' + d)) return;   // the user went elsewhere while it loaded
    if (err) { toast('불러오지 못했습니다: ' + errText(err)); if (main) main.classList.remove('loading'); return; }
    if (!day) { toast(d + ' 기록이 없습니다'); location.hash = '#/'; return; }
    if (S.filter === 'inc' && !day.units.some((u) => u.note)) S.filter = 'all';   // a filter chip this day does not show
    S.dayq = '';
    S.view = { name: 'day', d, day };
    S.shown = PAGE;
    renderDay();
    if (n) openDetail(d, day.units.find((u) => u.n === n));
  }
  function renderDay() {
    const { d, day } = S.view;
    const units = day.units;
    const cnt = { all: units.length, NG: 0, REVIEW: 0, PASS: 0, inc: 0 };
    for (const u of units) { cnt[u.v] = (cnt[u.v] || 0) + 1; if (u.note) cnt.inc++; }
    const chip = (k, label) => h('button', { class: 'chip', type: 'button', 'aria-pressed': String(S.filter === k), onclick: () => { S.filter = k; S.shown = PAGE; renderDay(); } },
      label, h('span', { class: 'n' }, fmt(cnt[k] || 0)));
    const search = h('input', { type: 'search', placeholder: '바코드', value: S.dayq, 'aria-label': '이 날짜에서 바코드 찾기' });
    search.addEventListener('input', () => { S.dayq = search.value; S.shown = PAGE; renderList(); });
    const listBox = h('div', { class: 'list' });
    const moreBtn = h('button', { class: 'btn more', type: 'button', onclick: () => { S.shown += PAGE; renderList(); } });
    function renderList() {
      const ql = S.dayq.trim().toLowerCase();
      const rows = units.filter((u) => (S.filter === 'all' || (S.filter === 'inc' ? !!u.note : u.v === S.filter)) && (!ql || (u.bc || '').toLowerCase().includes(ql)));
      listBox.replaceChildren(...(rows.length ? rows.slice(0, S.shown).map((u) => unitRow(d, u, false)) : [h('div', { class: 'empty' }, '해당하는 기판이 없습니다')]));
      moreBtn.textContent = `더 보기 (${fmt(rows.length - S.shown)}개 남음)`;
      moreBtn.classList.toggle('hidden', rows.length <= S.shown);
    }
    const st = dayStat(d) || {};
    const main = h('main', { class: 'wrap' },
      h('div', { class: 'pagehead' }, h('a', { class: 'btn sm', href: '#/' }, '← 현황'), h('h1', null, `${d} (${dow(d)})`),
        h('span', { class: 'muted' }, `검사 기판 ${fmt(st.n)} · 불량률 ${pctTxt(st.ng || 0, st.n || 0)}`), h('span', { class: 'spacer' }),
        h('button', { class: 'btn', type: 'button', onclick: (e) => exportRange([d, d], e.currentTarget) }, '이 날짜 엑셀')),
      h('div', { class: 'filters' }, chip('all', '전체'), chip('NG', '불량'), chip('REVIEW', '확인 필요'), chip('PASS', '양품'), cnt.inc ? chip('inc', '짝 없음') : null,
        h('span', { class: 'search' }, search)),
      h('section', { class: 'card section' }, listBox, moreBtn),
      foot());
    app.replaceChildren(topBar(), main);
    renderList();
  }

  // ---------------------------------------------------------------- barcode search over the range
  async function showFind(qs) {
    closeOverlay();
    const range = S.range;
    const days = daysIn(range);
    const box = h('div', { class: 'list' }, h('div', { class: 'empty' }, h('span', { class: 'spinner' }), ` ${days.length}일치 찾는 중…`));
    app.replaceChildren(topBar(), h('main', { class: 'wrap' },
      h('div', { class: 'pagehead' }, h('a', { class: 'btn sm', href: '#/' }, '← 현황'), h('h1', null, '바코드 찾기'), h('span', { class: 'mono' }, qs),
        h('span', { class: 'muted' }, `${range[0]} ~ ${range[1]}`)),
      h('section', { class: 'card section' }, box), foot()));
    S.view = { name: 'find', q: qs };
    const ql = qs.toLowerCase(), hits = [];
    for (const st of [...days].reverse()) {
      let day; try { day = await loadDay(st.d); } catch { continue; }
      for (const u of day.units) if ((u.bc || '').toLowerCase().includes(ql)) hits.push([st.d, u]);
      if (hits.length >= FIND_CAP) break;
    }
    if (!S.view || S.view.name !== 'find' || S.view.q !== qs) return;
    box.replaceChildren(...(hits.length ? hits.slice(0, FIND_CAP).map(([d, u]) => unitRow(d, u, true)) : [h('div', { class: 'empty' }, '이 기간에는 그런 바코드가 없습니다 (위 기간을 넓혀 다시 찾으세요)')]),
      hits.length >= FIND_CAP ? h('div', { class: 'note' }, `최근 것부터 ${fmt(FIND_CAP)}건까지만 보여 줍니다 — 바코드를 더 길게 넣거나 기간을 줄이세요`) : '');
  }

  // ---------------------------------------------------------------- detail sheet
  function closeOverlay() {
    const o = $('.overlay'); if (o) o.remove();
    for (const u of S.overlayUrls) URL.revokeObjectURL(u);
    S.overlayUrls = [];
    document.removeEventListener('keydown', escClose);
  }
  function escClose(e) { if (e.key === 'Escape') closeToList(); }
  function closeToList() {   // opened from a row: step back in the history (the phone's back button then leaves the list, not the sheet)
    if (S.detailFrom != null) { S.detailFrom = null; history.back(); return; }
    if (S.view && S.view.name === 'day') location.replace('#/day/' + S.view.d); else closeOverlay();
  }
  function lazyImg(path, cls, alt) {
    const img = h('img', { class: cls, alt, loading: 'lazy' });
    getImage(path + '?e=' + encodeURIComponent(S.index.e || '')).then((url) => { S.overlayUrls.push(url); img.src = url; })
      .catch(() => { img.replaceWith(h('div', { class: 'note' }, '사진을 불러오지 못했습니다')); });
    return img;
  }
  // a record's plain photo on Google Drive: files.get alt=media with the API key; the Referer is the site's origin (the key is
  // restricted to it - the document's own policy is no-referrer)
  async function getDriveImage(id) {
    const tpl = S.index.gu || 'https://www.googleapis.com/drive/v3/files/{id}?alt=media&key={key}';
    const url = tpl.replace('{id}', encodeURIComponent(id)).replace('{key}', encodeURIComponent(S.index.gk || ''));
    const once = async (cache) => {
      const r = await fetch(url, { cache, referrerPolicy: 'origin' });
      if (!r.ok) { const e = new Error('HTTP ' + r.status); e.status = r.status; throw e; }
      return URL.createObjectURL(new Blob([await decryptWith(S.pkey, await r.arrayBuffer())], { type: 'image/jpeg' }));
    };
    try { return await once('force-cache'); }       // a photo never changes: the browser's copy is fine
    catch { return once('reload'); }                // but never keep a stored error or a broken copy
  }
  function driveErrText(ex) {
    const st = ex && ex.status;
    if (st === 403) return 'Google 이 거부했습니다 (API 키 제한 또는 사용량)';
    if (st === 404) return 'Drive 에 없는 사진입니다';
    if (st === 429 || st >= 500) return 'Google Drive 가 잠시 응답하지 않습니다 — 다시 열어 보세요';
    return errText(ex);
  }
  function lazyDrive(id, cls, alt) {
    const img = h('img', { class: cls, alt, loading: 'lazy' });
    getDriveImage(id).then((url) => { S.overlayUrls.push(url); img.src = url; })
      .catch((ex) => { img.replaceWith(h('div', { class: 'note' }, 'Google Drive 사진을 불러오지 못했습니다: ' + driveErrText(ex))); });
    return img;
  }
  function sideCard(label, sd, v) {
    if (!sd) return h('section', { class: 'card side' }, h('h3', null, label, badge('')), h('div', { class: 'note' }, '이 면의 검사 기록이 없습니다 (짝 없음)'));
    const items = sd.df || [];
    return h('section', { class: 'card side' },
      h('h3', null, label, badge(sd.r), sd.ovr ? h('span', { class: 'muted' }, '작업자 판정') : null),
      h('div', { class: 'meta2' }, [sd.ts, sd.bd].filter(Boolean).join(' · ')),
      sd.ph ? lazyImg(`img/${encodeURIComponent(sd.ph)}_o.bin`, 'photo', label + ' 사진 (불량 위치 표시)')
        : sd.gd && S.pkey ? lazyDrive(sd.gd, 'photo', label + ' 사진') : null,
      items.length ? h('ul', { class: 'defects' }, items.map((d) => h('li', null,
        h('div', { class: 'what' }, h('span', { class: 'badge ' + (d.rv ? 'REVIEW' : 'NG') }, d.t), h('span', { class: 'mono' }, d.c)),
        d.r ? h('div', { class: 'why' }, d.r) : null,
        d.img && sd.ph ? lazyImg(`img/${encodeURIComponent(sd.ph)}_${encodeURIComponent(d.img)}.bin`, '', `${d.c} 골든과 검사 사진 비교`) : null))) : h('div', { class: 'note' }, sd.r === 'PASS' ? '불량 항목 없음' : '남은 불량 항목 없음 (작업자가 지움)'),
      sd.ph || (sd.gd && S.pkey) ? null
        : sd.np ? h('div', { class: 'note' }, '검사기에 이 기록의 사진이 남아 있지 않습니다 (보존 기간이 지나 지워짐)')
        : S.index.gk && !S.pkey ? h('div', { class: 'note' }, 'Google Drive 사진 키를 읽지 못했습니다 — 새로고침 해 보세요')
        : S.index.gk ? h('div', { class: 'note' }, '이 기록의 사진은 아직 Google Drive 에 올라가는 중입니다 — 잠시 뒤 다시 보세요')
        : sd.r && sd.r !== 'PASS' ? h('div', { class: 'note' }, photoNote()) : null);
  }
  function openDetail(d, u) {
    closeOverlay();
    if (!u) return;
    const front = (S.view.day && S.view.day.front) || '앞면', back = (S.view.day && S.view.day.back) || '뒷면';
    const sheet = h('div', { class: 'sheet', role: 'dialog', 'aria-modal': 'true', 'aria-label': (u.bc || '바코드 없음') + ' 상세' },
      h('div', { class: 'head' }, h('h2', null, u.bc || '(바코드 없음)'), badge(u.v), h('span', { class: 'spacer grow' }),
        h('button', { class: 'btn sm', type: 'button', onclick: closeToList }, '닫기')),
      h('div', { class: 'meta' }, `${d} · #${u.n}` + (u.dt != null ? ` · 앞·뒤 시차 ${u.dt}초` : '') + (u.note ? ' · ' + u.note : '')),
      h('div', { class: 'sides2' }, sideCard('앞면 (' + front + ')', u.f, u.v), sideCard('뒷면 (' + back + ')', u.b, u.v)));
    const ov = h('div', { class: 'overlay' }, sheet);
    ov.addEventListener('click', (e) => { if (e.target === ov) closeToList(); });
    document.body.append(ov);
    document.addEventListener('keydown', escClose);
    $('.btn', sheet).focus();
  }

  // ---------------------------------------------------------------- Excel: the '기판별 (앞·뒤)' sheet, 12 columns (the user's format), written here
  const XL_HEAD = ['번호', '개별 바코드', '앞면 사진', '뒷면 사진', '종합 판정', '앞면 판정', '뒷면 판정', '앞면 시각', '뒷면 시각', '시차(초)', '앞면 불량 요약', '뒷면 불량 요약'];
  const XL_W = [7, 22, 34, 34, 10, 10, 10, 19, 19, 8, 44, 44];
  async function exportRange(range, btn) {
    const days = daysIn(range);
    if (!days.length) { toast('이 기간에는 기록이 없습니다'); return; }
    const label = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = '만드는 중…'; }
    try {
      const rows = [];
      let k = 0;
      for (const st of days) {
        const day = await loadDay(st.d);
        for (const u of day.units) {
          k++;
          rows.push([range[0] === range[1] ? u.n : k, u.bc || '', '', '', u.v || '', (u.f && u.f.r) || '', (u.b && u.b.r) || '',
            (u.f && u.f.ts) || '', (u.b && u.b.ts) || '', u.dt == null ? '' : u.dt, (u.f && u.f.s) || '', (u.b && u.b.s) || '']);
        }
      }
      const blob = buildXlsx('기판별 (앞·뒤)', XL_HEAD, XL_W, rows);
      const name = `ARGUS_기판별_${range[0]}${range[0] === range[1] ? '' : '~' + range[1]}.xlsx`;
      const a = h('a', { href: URL.createObjectURL(blob), download: name });
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 60000);
      toast(`${name} · ${fmt(rows.length)}행`);
    } catch (ex) {
      if (await passwordChanged(ex)) return;
      toast('엑셀을 만들지 못했습니다: ' + errText(ex));
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = label; }
    }
  }
  function xesc(s) {
    return String(s).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F￾￿]/g, '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function colName(i) { let s = ''; i++; while (i) { const m = (i - 1) % 26; s = String.fromCharCode(65 + m) + s; i = Math.floor((i - 1) / 26); } return s; }
  function buildXlsx(sheetName, head, widths, rows) {
    const last = colName(head.length - 1), nRows = rows.length + 1;
    const cell = (r, c, v, st) => {
      const ref = colName(c) + r;
      if (v === '' || v == null) return st ? `<c r="${ref}" s="${st}"/>` : '';
      if (typeof v === 'number' && isFinite(v)) return `<c r="${ref}" s="${st}"><v>${v}</v></c>`;
      return `<c r="${ref}" s="${st}" t="inlineStr"><is><t xml:space="preserve">${xesc(v)}</t></is></c>`;
    };
    const vs = (v) => (v === 'PASS' ? 2 : v === 'NG' || v === 'REVIEW' ? 3 : 1);
    let sd = '<row r="1" ht="22" customHeight="1">' + head.map((t, c) => cell(1, c, t, 4)).join('') + '</row>';
    rows.forEach((row, i) => {
      const r = i + 2;
      sd += `<row r="${r}">` + row.map((v, c) => cell(r, c, v, c === 4 ? vs(v) : (c === 10 || c === 11 ? 5 : 1))).join('') + '</row>';
    });
    const cols = widths.map((w, i) => `<col min="${i + 1}" max="${i + 1}" width="${w}" customWidth="1"/>`).join('');
    const sheet = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><dimension ref="A1:${last}${nRows}"/><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><sheetFormatPr defaultRowHeight="15"/><cols>${cols}</cols><sheetData>${sd}</sheetData><autoFilter ref="A1:${last}${nRows}"/></worksheet>`;
    const sn = xesc(sheetName);
    const wb = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="${sn}" sheetId="1" r:id="rId1"/></sheets><definedNames><definedName name="_xlnm._FilterDatabase" localSheetId="0" hidden="1">'${sn}'!$A$1:$${last}$${nRows}</definedName></definedNames></workbook>`;
    const styles = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="4"><font><sz val="10"/><name val="Malgun Gothic"/></font><font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Malgun Gothic"/></font><font><b/><sz val="10"/><color rgb="FF0B6B3A"/><name val="Malgun Gothic"/></font><font><b/><sz val="10"/><color rgb="FFA3261B"/><name val="Malgun Gothic"/></font></fonts><fills count="5"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF1F1F1F"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFDDF3E4"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFBDCD5"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border><border><left style="thin"><color rgb="FFD0D0D0"/></left><right style="thin"><color rgb="FFD0D0D0"/></right><top style="thin"><color rgb="FFD0D0D0"/></top><bottom style="thin"><color rgb="FFD0D0D0"/></bottom><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="6"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="center"/></xf><xf numFmtId="0" fontId="2" fillId="3" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="center"/></xf><xf numFmtId="0" fontId="3" fillId="4" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="center"/></xf><xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>`;
    const files = [
      ['[Content_Types].xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>`],
      ['_rels/.rels', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`],
      ['xl/workbook.xml', wb],
      ['xl/_rels/workbook.xml.rels', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`],
      ['xl/styles.xml', styles],
      ['xl/worksheets/sheet1.xml', sheet],
    ];
    return new Blob([zipStore(files.map(([n, t]) => [n, te.encode(t)]))], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
  }
  let CRC_T = null;
  function crc32(u) {
    if (!CRC_T) { CRC_T = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; CRC_T[n] = c >>> 0; } }
    let c = 0xffffffff; for (let i = 0; i < u.length; i++) c = CRC_T[(c ^ u[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0;
  }
  function zipStore(files) {   // a stored (uncompressed) zip - a valid xlsx container without any library
    const parts = [], central = []; let off = 0;
    for (const [name, data] of files) {
      const nb = te.encode(name), crc = crc32(data);
      const lh = new DataView(new ArrayBuffer(30));
      lh.setUint32(0, 0x04034b50, true); lh.setUint16(4, 20, true); lh.setUint16(6, 0x0800, true); lh.setUint16(8, 0, true);
      lh.setUint16(10, 0, true); lh.setUint16(12, 0x21, true); lh.setUint32(14, crc, true); lh.setUint32(18, data.length, true); lh.setUint32(22, data.length, true);
      lh.setUint16(26, nb.length, true); lh.setUint16(28, 0, true);
      parts.push(new Uint8Array(lh.buffer), nb, data);
      const ch = new DataView(new ArrayBuffer(46));
      ch.setUint32(0, 0x02014b50, true); ch.setUint16(4, 20, true); ch.setUint16(6, 20, true); ch.setUint16(8, 0x0800, true); ch.setUint16(10, 0, true);
      ch.setUint16(12, 0, true); ch.setUint16(14, 0x21, true); ch.setUint32(16, crc, true); ch.setUint32(20, data.length, true); ch.setUint32(24, data.length, true);
      ch.setUint16(28, nb.length, true); ch.setUint16(30, 0, true); ch.setUint16(32, 0, true); ch.setUint16(34, 0, true); ch.setUint16(36, 0, true);
      ch.setUint32(38, 0, true); ch.setUint32(42, off, true);
      central.push(new Uint8Array(ch.buffer), nb);
      off += 30 + nb.length + data.length;
    }
    const cdSize = central.reduce((a, b) => a + b.length, 0);
    const end = new DataView(new ArrayBuffer(22));
    end.setUint32(0, 0x06054b50, true); end.setUint16(8, files.length, true); end.setUint16(10, files.length, true);
    end.setUint32(12, cdSize, true); end.setUint32(16, off, true);
    return new Blob([...parts, ...central, new Uint8Array(end.buffer)]);
  }

  boot();
})();
