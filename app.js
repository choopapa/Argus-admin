/* ARGUS 관리자 사이트 (2026-10-30, 기록 화면 2026-11-02) - a static page on GitHub Pages. Everything under data/ and img/ is AES-256-GCM
   encrypted by the inspection PC (backend/app/admin_site.py); the key is derived here from the password (PBKDF2-SHA256, salt and rounds
   from site.json) and never leaves the browser. No external scripts, no server: fetch, decrypt, render.
   Screens: 현황 (KPIs, daily chart, top findings, days) and 기록 (the program's history tab: filters, table with photos, per-record
   detail with the numbered defect boxes drawn over the photo, zoom view, Excel with photos). */
(() => {
  'use strict';

  const LS_KEY = 'argus-admin-key:';   // the first version kept an exported key here: only cleared now
  const FORMAT_V = 3;                  // data format this page reads (admin_site.FORMAT_V)
  const REMEMBER_DAYS = 30;
  const PAGE = 200;
  const XL_PHOTO_W = 180;              // photo width in the Excel cells (px)
  const XL_PHOTO_WARN = 3000;          // ask first above this many photos
  const XL_PHOTO_MAX = 20000;          // a hard limit (memory, zip entries): above it, a shorter period or the photo-less sheet
  const VERDICT_KO = { PASS: '양품', NG: '불량', REVIEW: '확인 필요' };
  const SOURCE_KO = { rule: '규칙', rules_v2: '규칙 v2', ai: 'AI', model: '학습', manual: '작업자 지정', example: '예시 대조', priority: '중점 검사', 'rule+ai': '규칙 유지' };
  const WEEK = ['일', '월', '화', '수', '목', '금', '토'];
  const S = { site: null, key: null, pkey: null, index: null, days: new Map(), preset: '7', range: null, view: null,
              overlayUrls: [], lastSynced: null, lastRefresh: 0, rq: null, rec: null, shown: PAGE, busy: null, pushedSel: false, bcRaw: null, lbClose: null };
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
  function mdhm(ts) { return ts ? ts.slice(5, 16) : ''; }
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
    if (!r.ok) { const e = new Error('HTTP ' + r.status); e.status = r.status; throw e; }
    return r.arrayBuffer();
  }
  async function unpack(buf) {   // b'ARGP' + 4-byte length + gzip, zero-padded to 16 KB (admin_site._encrypt_json)
    let u = new Uint8Array(buf);
    if (u.length >= 8 && u[0] === 0x41 && u[1] === 0x52 && u[2] === 0x47 && u[3] === 0x50) u = u.slice(8, 8 + new DataView(buf).getUint32(4, false));
    return JSON.parse(td.decode(await gunzip(u)));
  }
  async function getJSON(path, fresh) { return unpack(await decrypt(await fetchBin(path, fresh))); }
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
    S.key = null; S.pkey = null; S.index = null; S.days.clear(); closeOverlays();
    renderLogin('검사기에서 사이트 비밀번호가 바뀌었습니다. 새 비밀번호를 입력하세요.');
    return true;
  }
  function errText(ex) { return ex && ex.name === 'OperationError' ? '데이터를 풀지 못했습니다' : (ex && ex.message) || String(ex); }

  // ---------------------------------------------------------------- photos: the site's NG / 확인 필요 photo (img/), every record's small photo
  // (thumbs/ bundles) and every other record's big photo from the inspection PC itself (admin_site.pc_photo, through its tunnel address)
  async function blobFromSite(path) { return new Blob([await decrypt(await fetchBin(path))], { type: 'image/jpeg' }); }
  async function blobFromPc(kind, tok) {
    const base = S.index && S.index.pcu;
    if (!base) throw new Error('검사기 주소가 설정되지 않았습니다');
    let r;
    for (let attempt = 0; ; attempt++) {
      try { r = await fetch(`${base}/p/${kind}/${encodeURIComponent(tok)}.bin`, { mode: 'cors', credentials: 'omit', cache: 'default', referrerPolicy: 'no-referrer' }); }
      catch { const e = new Error('검사기에 닿지 못했습니다 (검사기가 꺼져 있거나 연결이 끊겼습니다)'); e.pc = true; throw e; }
      if (r.status !== 503 || attempt >= 2) break;   // busy: an inspection is running (or the photo drive is away) - wait and ask again
      await new Promise((res) => setTimeout(res, 3000));
    }
    if (!r.ok) {
      const e = new Error(r.status === 404 ? '검사기에서 이 사진을 찾지 못했습니다' : r.status === 503 ? '검사기가 바쁩니다 (검사 중) — 잠시 뒤 다시 열어 보세요' : '검사기가 오류 ' + r.status + ' 로 답했습니다');
      e.status = r.status; throw e;
    }
    return new Blob([await decrypt(await r.arrayBuffer())], { type: 'image/jpeg' });
  }
  const bundleCache = new Map();   // bundle token|h -> Promise<Map(record id -> small JPEG Blob)>
  const BUNDLE_MAX = 60;
  function bundleBlobs(tb) {   // b'ARGT' + count + (record id, length) per picture + the JPEGs (admin_site._bundle)
    const key = tb[0] + '|' + (tb[1] || '');
    if (bundleCache.has(key)) return bundleCache.get(key);
    const p = (async () => {
      const buf = new Uint8Array(await decrypt(await fetchBin(`thumbs/${encodeURIComponent(tb[0])}.bin?h=${encodeURIComponent(tb[1] || '')}`)));
      if (!(buf[0] === 0x41 && buf[1] === 0x52 && buf[2] === 0x47 && buf[3] === 0x54)) throw new Error('작은 사진 묶음을 읽지 못했습니다');
      const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
      const n = dv.getUint32(4, false), out = new Map();
      let off = 8 + n * 8;
      for (let i = 0; i < n; i++) {
        const rid = dv.getUint32(8 + i * 8, false), len = dv.getUint32(12 + i * 8, false);
        out.set(rid, new Blob([buf.slice(off, off + len)], { type: 'image/jpeg' }));
        off += len;
      }
      return out;
    })();
    p.catch(() => bundleCache.delete(key));   // a failed fetch is tried again next time
    bundleCache.set(key, p);
    while (bundleCache.size > BUNDLE_MAX) bundleCache.delete(bundleCache.keys().next().value);
    return p;
  }
  function hasThumb(rec) { return !!(rec && (rec._tb || rec.ph || (rec.pt && S.index.pcu) || (rec.gd && S.pkey))); }
  async function thumbBlob(rec) {   // the record's small picture: its bundle, else the PC's small photo, else the site / Drive photo (shrunk by the caller)
    if (rec._tb) { try { const b = (await bundleBlobs(rec._tb)).get(rec.id); if (b) return b; } catch (ex) { if (!rec.ph && !(rec.pt && S.index.pcu)) throw ex; } }
    if (rec.pt && S.index.pcu && !rec.ph) return blobFromPc('t', rec.pt);
    const src = photoSrc(rec);
    if (src) return src.get();
    throw new Error('사진 없음');
  }
  async function blobFromDrive(id) {
    const tpl = S.index.gu || 'https://www.googleapis.com/drive/v3/files/{id}?alt=media&key={key}';
    const url = tpl.replace('{id}', encodeURIComponent(id)).replace('{key}', encodeURIComponent(S.index.gk || ''));
    const once = async (cache) => {
      const r = await fetch(url, { cache, referrerPolicy: 'origin' });   // the API key is restricted to the site's origin
      if (!r.ok) { const e = new Error('HTTP ' + r.status); e.status = r.status; throw e; }
      return new Blob([await decryptWith(S.pkey, await r.arrayBuffer())], { type: 'image/jpeg' });
    };
    try { return await once('force-cache'); } catch { return once('reload'); }   // never keep a stored error or a broken copy
  }
  function photoSrc(rec) {   // where this record's photo is: {kind, get()} or null
    if (!rec) return null;
    if (rec.ph) return { kind: 'site', get: () => blobFromSite(`img/${encodeURIComponent(rec.ph)}_o.bin?e=${encodeURIComponent(S.index.e || '')}`) };
    if (rec.pt && S.index.pcu) return { kind: 'pc', get: () => blobFromPc('o', rec.pt) };
    if (rec.gd && S.pkey) return { kind: 'drive', get: () => blobFromDrive(rec.gd) };
    return null;
  }
  function noPhotoText(rec) {
    if (!rec) return '기록 없음';
    if (rec.np) return '보존 기간이 지나 검사기에 사진이 없음';
    if (rec.pt && !S.index.pcu) return '큰 사진은 검사기 연결 후 보입니다 (검사기 설정 › 관리자 사이트 › 검사기 외부 주소)';
    return '사진 없음';
  }
  function driveErrText(ex) {
    const st = ex && ex.status;
    if (st === 403) return 'Google 이 거부했습니다 (API 키 제한 또는 사용량)';
    if (st === 404) return '사진 파일이 없습니다';
    if (st === 429 || st >= 500) return '잠시 응답하지 않습니다 — 다시 열어 보세요';
    return errText(ex);
  }
  function geom(rec) {   // the photo's pixel frame (the aligned image = the board's reference size) for the box overlay
    const b = (S.index.boards || {})[String(rec.bid)] || {};
    const wh = rec.wh || [b.W || 5496, b.H || 3672];
    return { W: wh[0] || 5496, H: wh[1] || 3672, comps: b.c || [] };
  }
  // a small JPEG (thumbnail / Excel picture): decode, scale, optionally draw the defect boxes, encode - never keep the 1200 px bitmap
  async function smallJpeg(blob, width, rec, boxes) {
    let bmp = null, img = null;
    try { bmp = await createImageBitmap(blob); } catch {
      img = new Image(); const u = URL.createObjectURL(blob);
      await new Promise((res, rej) => { img.onload = res; img.onerror = rej; img.src = u; });
      URL.revokeObjectURL(u);
    }
    const src = bmp || img, sw = bmp ? bmp.width : img.naturalWidth, sh = bmp ? bmp.height : img.naturalHeight;
    const w = Math.min(width, sw), hgt = Math.max(1, Math.round((sh * w) / sw));
    const c = document.createElement('canvas'); c.width = w; c.height = hgt;
    const g = c.getContext('2d'); g.drawImage(src, 0, 0, w, hgt);
    if (bmp && bmp.close) bmp.close();
    if (boxes && rec && rec.df && rec.df.length) {
      const { W } = geom(rec), s = w / W;
      g.lineWidth = Math.max(1.5, w / 160); g.strokeStyle = '#ff5a1f'; g.fillStyle = '#ff5a1f';
      g.font = `bold ${Math.max(9, Math.round(w / 22))}px sans-serif`;
      rec.df.forEach((d, i) => {
        if (!d.b) return;
        const [x, y, bw, bh] = d.b.map((v) => v * s);
        g.strokeRect(x, y, Math.max(2, bw), Math.max(2, bh));
        g.fillText(String(i + 1), x, Math.max(10, y - 2));
      });
    }
    return new Promise((res) => c.toBlob((b) => res({ b, w, h: hgt }), 'image/jpeg', 0.8));
  }
  // thumbnails: decoded small, a few at a time, only when on screen, cached (bounded)
  const thumbCache = new Map();
  const THUMB_MAX = 400;
  let thumbActive = 0;
  const thumbQueue = [];
  function thumbPump() {   // the latest rows first (a fling through the list must not fetch every row it passed)
    while (thumbActive < 3 && thumbQueue.length) {
      const job = thumbQueue.pop();
      job.el._queued = false;
      if (!job.el.isConnected || job.el._done) continue;
      if (thumbObs && !job.el._vis) continue;   // scrolled away: queued again when it comes back
      thumbActive++;
      job.run().finally(() => { thumbActive--; job.el._done = true; if (thumbObs) thumbObs.unobserve(job.el); thumbPump(); });
    }
  }
  const thumbObs = 'IntersectionObserver' in window ? new IntersectionObserver((ents) => {
    for (const en of ents) {
      const el = en.target;
      el._vis = en.isIntersecting;
      if (en.isIntersecting && el._job && !el._queued && !el._done) { el._queued = true; thumbQueue.push(el._job); }
    }
    thumbPump();
  }, { rootMargin: '300px' }) : null;
  function thumbEl(rec, cls) {
    if (!hasThumb(rec)) return h('div', { class: 'thumb none ' + (cls || ''), title: rec ? noPhotoText(rec) : '' }, rec ? (rec.np ? '보존 지남' : '사진 없음') : '—');
    const key = 'r:' + rec.id + ':' + (rec._tb ? rec._tb[1] : '') + ':' + (rec.ph || '');
    const img = h('img', { class: 'thumb ' + (cls || ''), alt: '' });
    if (thumbCache.has(key)) { img.src = thumbCache.get(key); return img; }
    img._job = { el: img, run: async () => {
      try {
        const { b } = await smallJpeg(await thumbBlob(rec), 160, rec, true);
        const u = URL.createObjectURL(b);
        thumbCache.set(key, u);
        if (thumbCache.size > THUMB_MAX) { const [k0, u0] = thumbCache.entries().next().value; thumbCache.delete(k0); URL.revokeObjectURL(u0); }
        img.src = u;
      } catch { img.replaceWith(h('div', { class: 'thumb none ' + (cls || '') }, '못 불러옴')); }
    } };
    if (thumbObs) thumbObs.observe(img); else { thumbQueue.push(img._job); thumbPump(); }
    return img;
  }

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
    let day;
    try { day = await getJSON('data/days/' + encodeURIComponent(st.f) + '.bin?h=' + encodeURIComponent(st.h || ''), false); } catch (ex) {
      if (!/HTTP 404/.test(String(ex && ex.message))) throw ex;
      await loadIndex();   // the day changed on the inspection PC since the index was read: read both again once
      const st2 = dayStat(d); if (!st2) return null;
      day = await getJSON('data/days/' + encodeURIComponent(st2.f) + '.bin?h=' + encodeURIComponent(st2.h || ''), false);
    }
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
    if (p === 'month') return [today.slice(0, 8) + '01', today];
    if (p === 'all') return [first, last > today ? last : today];
    return S.range || [addDays(today, -6), today];
  }
  function daysIn(range) { return (S.index.days || []).filter((x) => x.d >= range[0] && x.d <= range[1]); }
  function totals(days) {
    const t = { n: 0, p: 0, ng: 0, rv: 0, inc: 0 };
    for (const d of days) { t.n += d.n; t.p += d.p; t.ng += d.ng; t.rv += d.rv; t.inc += d.inc || 0; }
    return t;
  }
  async function loadUnits(range, onProgress, isStopped) {   // every unit of the range, newest first, each knowing its day
    const days = daysIn(range), out = [];
    let k = 0;
    for (const st of days) {
      if (isStopped && isStopped()) break;
      const day = await loadDay(st.d);
      k++; if (onProgress) onProgress(k, days.length);
      if (!day) continue;
      const tbl = day.tbl || [];
      for (const u of day.units) {
        for (const x of [u.f, u.b]) if (x && x.tb != null && tbl[x.tb]) x._tb = tbl[x.tb];   // the record's small-photo bundle
        out.push(Object.assign({ d: st.d, labels: [day.front || '앞면', day.back || '뒷면'] }, u));
      }
    }
    out.sort((a, b) => (unitTs(b) < unitTs(a) ? -1 : unitTs(b) > unitTs(a) ? 1 : 0));
    return out;
  }
  function unitTs(u) { return (u.f && u.f.ts) || (u.b && u.b.ts) || u.d; }

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
  function lock() { forget(); S.key = null; S.pkey = null; S.index = null; S.days.clear(); S.rec = null; closeOverlays(); history.replaceState(null, '', location.pathname); renderLogin(''); }

  let refreshTimer = null;
  function start() {
    S.range = presetRange(S.preset);
    window.removeEventListener('hashchange', onHash);
    window.addEventListener('hashchange', onHash);
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
    if (!quiet || S.lastSynced !== before) {
      if (S.preset !== 'custom') S.range = presetRange(S.preset);
      if (quiet && S.view && S.view.name === 'rec' && S.rec) return refreshRecordsQuiet();
      S.rec = null; route(true);
    }
    if (!quiet) toast(S.lastSynced !== before ? '새 데이터를 받았습니다' : '최신 상태입니다');
  }

  // ---------------------------------------------------------------- shell / routing
  function topBar(active) {
    const sync = S.index.synced ? S.index.synced.replace('T', ' ').slice(5, 16) : '–';
    return h('header', { class: 'top' }, h('div', { class: 'wrap' },
      h('a', { class: 'brand', href: '#/' }, 'ARGUS', h('small', null, S.index.pc || '')),
      h('nav', { class: 'tabs' },
        h('a', { href: '#/', class: active === 'dash' ? 'on' : null }, '현황'),
        h('a', { href: '#/rec?' + recQuery(Object.assign({}, S.rq || {}, { f: S.range[0], t: S.range[1] })), class: active === 'rec' ? 'on' : null }, '기록')),
      h('div', { class: 'grow' }, h('div', { class: 'sync', title: '검사기가 마지막으로 올린 시각' }, h('span', { class: 'lbl' }, '갱신 '), sync)),
      h('button', { class: 'btn sm', type: 'button', onclick: () => refresh(false) }, '새로고침'),
      h('button', { class: 'btn sm', type: 'button', onclick: lock, title: '이 기기에서 잠그고 기억한 비밀번호도 지웁니다' }, '잠금')));
  }
  function photoNote() {
    const big = S.index.pcu ? '그 밖의 기록은 검사기에서 받아 옵니다 (검사기가 켜져 있을 때)'
      : '그 밖의 기록은 검사기 연결 후 (검사기 설정 › 관리자 사이트 › 검사기 외부 주소)';
    return `사진: 모든 기록의 작은 사진 · 큰 사진은 불량·확인 필요 기록이 사이트에, ${big}`;
  }
  function foot() {
    return h('footer', null, photoNote() + ' · 모든 데이터는 암호화되어 이 기기에서만 풀립니다' + (S.index.build ? ' · ' + S.index.build : ''));
  }
  function parseHash() {
    const m = location.hash.match(/^#\/rec\??(.*)$/);
    if (m) { const p = new URLSearchParams(m[1]); const o = {}; for (const [k, v] of p) o[k] = v; return { name: 'rec', q: o }; }
    const d = location.hash.match(/^#\/day\/(\d{4}-\d{2}-\d{2})/);   // links of the first version
    if (d) return { name: 'rec', q: { f: d[1], t: d[1] } };
    const f = location.hash.match(/^#\/find\/(.+)$/);
    if (f) { let qs; try { qs = decodeURIComponent(f[1]); } catch { qs = f[1]; } return { name: 'rec', q: { f: S.range[0], t: S.range[1], q: qs } }; }
    return { name: 'dash' };
  }
  function recQuery(o) {
    const p = new URLSearchParams();
    for (const k of ['f', 't', 'v', 'r', 'q', 'b', 'dup', 's']) if (o[k]) p.set(k, o[k]);
    return p.toString();
  }
  function onHash() { route(false); }
  function route(force) {
    if (!S.key || !S.index) return;
    const r = parseHash();
    if (r.name === 'rec') return showRecords(r.q, force);
    closeOverlays();
    S.view = { name: 'dash' };
    renderDashboard();
  }

  // ---------------------------------------------------------------- 현황 (dashboard)
  function presetChips(onPick, cur) {
    return [['today', '오늘'], ['yday', '어제'], ['7', '7일'], ['30', '30일'], ['month', '이달'], ['all', '전체']].map(([p, label]) =>
      h('button', { class: 'chip', type: 'button', 'aria-pressed': String(cur === p), onclick: () => onPick(p) }, label));
  }
  function filterRow() {
    const chips = presetChips((p) => { S.preset = p; S.range = presetRange(p); renderDashboard(); }, S.preset);
    const from = h('input', { type: 'date', value: S.range[0], 'aria-label': '시작일' });
    const to = h('input', { type: 'date', value: S.range[1], 'aria-label': '끝일' });
    const setCustom = () => { if (from.value && to.value) { S.preset = 'custom'; S.range = from.value <= to.value ? [from.value, to.value] : [to.value, from.value]; renderDashboard(); } };
    from.addEventListener('change', setCustom); to.addEventListener('change', setCustom);
    const q = h('input', { type: 'search', placeholder: '바코드 찾기 (기간 안)', 'aria-label': '바코드 찾기', enterkeyhint: 'search' });
    q.addEventListener('keydown', (e) => { if (e.key === 'Enter' && q.value.trim()) location.hash = '#/rec?' + recQuery({ f: S.range[0], t: S.range[1], q: q.value.trim() }); });
    return h('div', { class: 'filters' }, chips, h('span', { class: 'daterange' }, from, '~', to), h('span', { class: 'search' }, q), h('span', { class: 'spacer' }),
      h('button', { class: 'btn', type: 'button', onclick: () => exportExcel({ f: S.range[0], t: S.range[1] }, true) }, '엑셀 (사진 포함)'),
      h('button', { class: 'btn', type: 'button', onclick: () => exportExcel({ f: S.range[0], t: S.range[1] }, false) }, '사진 없이'));
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
      filterRow(),
      h('div', { class: 'kpis' },
        tile('검사 기판', fmt(t.n), `${S.range[0] === S.range[1] ? S.range[0] : S.range[0] + ' ~ ' + S.range[1]}${t.inc ? ' · 앞·뒤 짝 없음 ' + fmt(t.inc) : ''}`, null, true),
        tile('양품', fmt(t.p), pctTxt(t.p, t.n), 'good'),
        tile('불량', fmt(t.ng), pctTxt(t.ng, t.n), 'bad'),
        tile('확인 필요', fmt(t.rv), pctTxt(t.rv, t.n), 'warn'),
        tile('불량률', pctTxt(t.ng, t.n), '불량 ÷ 검사 기판')),
      h('div', { class: 'grid2 section' },
        h('section', { class: 'card' }, h('h2', null, '일별 불량·확인 필요', h('span', { class: 'muted' }, '건수 · 눌러서 그날 기록')),
          h('div', { class: 'legend' }, h('span', null, h('i', { class: 'ng' }), '불량'), h('span', null, h('i', { class: 'rv' }), '확인 필요')), chartBox),
        topCard(days)),
      dayTable(days),
      foot());
    app.replaceChildren(topBar('dash'), main);
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
    return h('section', { class: 'card section' }, h('h2', null, '날짜별', h('span', { class: 'muted' }, '눌러서 그날 기록')),
      rows.length ? h('div', { class: 'tablebox' }, h('table', null,
        h('thead', null, h('tr', null, h('th', null, '날짜'), h('th', { class: 'r' }, '검사 기판'), h('th', { class: 'r' }, '양품'), h('th', { class: 'r' }, '불량'),
          h('th', { class: 'r' }, '확인 필요'), h('th', { class: 'r' }, '불량률'), h('th', { class: 'r' }, '짝 없음'))),
        h('tbody', null, rows.map((d) => {
          const tr = h('tr', { class: 'link', tabindex: '0' }, h('td', { class: 'num' }, `${d.d} (${dow(d.d)})`), h('td', { class: 'r' }, fmt(d.n)), h('td', { class: 'r' }, fmt(d.p)),
            h('td', { class: 'r' }, fmt(d.ng)), h('td', { class: 'r' }, fmt(d.rv)), h('td', { class: 'r' }, pctTxt(d.ng, d.n)), h('td', { class: 'r' }, fmt(d.inc || 0)));
          const go = () => { location.hash = '#/rec?' + recQuery({ f: d.d, t: d.d }); };
          tr.addEventListener('click', go); tr.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
          return tr;
        })))) : h('div', { class: 'empty' }, '이 기간에는 검사 기록이 없습니다'));
  }

  // chart: daily NG + 확인 필요, stacked columns (status colours, legend + table twin)
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
      const go = () => { location.hash = '#/rec?' + recQuery({ f: d.d, t: d.d }); };
      g.addEventListener('pointerenter', show); g.addEventListener('pointerleave', hide); g.addEventListener('focus', show); g.addEventListener('blur', hide);
      g.addEventListener('click', go); g.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
      svg.append(g);
    });
    box.append(svg, tip);
  }
  let resizeTimer = null;
  window.addEventListener('resize', () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => { if (S.view && S.view.name === 'dash') renderDashboard(); }, 200); });

  // new data while the 기록 view is open: reload its range in the background (changed days only), redraw the list in place -
  // never while a zoom view or a sheet is open (the next selection change shows the new data)
  async function refreshRecordsQuiet() {
    const r = S.rec;
    let units;
    try { units = await loadUnits([r.f, r.t]); } catch { return; }
    if (S.rec !== r) return;
    S.rec = { f: r.f, t: r.t, units };
    if ($('.lightbox') || $('.overlay.sheet-ov') || (document.activeElement && document.activeElement.dataset && document.activeElement.dataset.role === 'bc')) return;
    const y = window.scrollY;
    renderRecords();
    window.scrollTo(0, y);
  }

  // ---------------------------------------------------------------- 기록 (the program's history tab)
  function wide() { return window.matchMedia('(min-width: 1100px)').matches; }
  function recFilter(units, q) {
    const ql = (q.q || '').trim().toLowerCase();
    const sides = (u) => [u.f, u.b].filter(Boolean);
    return units.filter((u) => {
      if (ql && !(u.bc || '').toLowerCase().includes(ql)) return false;
      if (q.b && !sides(u).some((x) => String(x.bid) === q.b)) return false;
      if (q.dup && !sides(u).some((x) => (x.seq || 0) > 1)) return false;
      if (q.r) {
        if ((q.v || 'u') === 'u') { if (u.v !== q.r) return false; } else if (!sides(u).some((x) => x.r === q.r)) return false;
      }
      return true;
    });
  }
  function recordsOf(units, q) {   // 기록별: one row per side record
    const out = [];
    for (const u of units) for (const [k, x] of [['f', u.f], ['b', u.b]]) {
      if (!x) continue;
      if (q.r && x.r !== q.r) continue;
      if (q.b && String(x.bid) !== q.b) continue;
      if (q.dup && !((x.seq || 0) > 1)) continue;
      out.push({ u, k, x });
    }
    return out;
  }
  async function showRecords(q, force) {
    q = Object.assign({ v: 'u' }, q);
    if (!q.f || !q.t) { q.f = S.range[0]; q.t = S.range[1]; }
    const same = S.rec && S.rec.f === q.f && S.rec.t === q.t;
    const listKey = ['v', 'r', 'q', 'b', 'dup'].map((k) => q[k] || '').join('|');
    if (!force && same && S.view && S.view.name === 'rec' && S.view.listKey === listKey && S.view.f === q.f && S.view.t === q.t) {
      S.rq = q;   // only the selection changed: keep the list and its scroll
      return renderSelection();
    }
    S.rq = q;
    closeOverlays();
    if (!same || force) {
      const ndays = daysIn([q.f, q.t]).length;
      app.replaceChildren(topBar('rec'), h('main', { class: 'wrap' }, h('div', { class: 'card section empty' }, h('span', { class: 'spinner' }), ` 기록을 불러오는 중… (${ndays}일)`)));
      S.view = { name: 'loading' };   // a back press to the previous range must not take the 'only the selection changed' path
      let units;
      try {
        units = await loadUnits([q.f, q.t], (k, n) => { const e = $('main .empty'); if (e) e.lastChild.textContent = ` 기록을 불러오는 중… ${k}/${n}일`; });
      } catch (ex) {
        if (await passwordChanged(ex)) return;
        app.replaceChildren(topBar('rec'), h('main', { class: 'wrap' }, h('div', { class: 'card section empty' }, '불러오지 못했습니다: ' + errText(ex))));
        return;
      }
      const now = parseHash();
      if (now.name !== 'rec' || (now.q.f || q.f) !== q.f || (now.q.t || q.t) !== q.t) return;   // the user went elsewhere while it loaded
      S.rec = { f: q.f, t: q.t, units };
    }
    S.shown = PAGE;
    S.view = { name: 'rec', listKey, f: q.f, t: q.t };
    renderRecords();
  }
  function setQ(patch, push) {
    const q = Object.assign({}, S.rq, patch);
    const hash = '#/rec?' + recQuery(q);
    if (push) location.hash = hash; else { history.replaceState(null, '', hash); route(false); }
  }
  function renderRecords() {
    const q = S.rq, all = S.rec.units;
    const units = recFilter(all, q);
    const mode = q.v || 'u';
    const recs = mode === 'r' ? recordsOf(recFilter(all, Object.assign({}, q, { r: '' })), q) : null;
    const boards = Object.entries(S.index.boards || {});
    // filters (the history tab's row)
    const from = h('input', { type: 'date', value: q.f, 'aria-label': '시작일' });
    const to = h('input', { type: 'date', value: q.t, 'aria-label': '종료일' });
    const setRange = () => { if (from.value && to.value) setQ({ f: from.value <= to.value ? from.value : to.value, t: from.value <= to.value ? to.value : from.value, s: '' }, true); };
    from.addEventListener('change', setRange); to.addEventListener('change', setRange);
    const old = document.activeElement && document.activeElement.dataset && document.activeElement.dataset.role === 'bc' ? document.activeElement : null;
    const raw = S.bcRaw != null && S.bcRaw.trim() === (q.q || '') ? S.bcRaw : (q.q || '');
    const bc = h('input', { type: 'search', class: 'mono', placeholder: '바코드', value: raw, 'aria-label': '개별 바코드', enterkeyhint: 'search', 'data-role': 'bc' });
    let bcTimer = null;
    bc.addEventListener('input', () => { clearTimeout(bcTimer); bcTimer = setTimeout(() => { S.bcRaw = bc.value; setQ({ q: bc.value.trim(), s: '' }, false); }, 350); });
    const refocus = old ? [old.selectionStart, old.selectionEnd] : null;
    const sel = (label, val, opts, on) => h('label', { class: 'fsel' }, h('span', null, label),
      (() => { const s = h('select', { 'aria-label': label }, opts.map(([v, t]) => h('option', { value: v, selected: v === (val || '') ? true : null }, t))); s.addEventListener('change', () => on(s.value)); return s; })());
    const seg = h('div', { class: 'seg', role: 'group', 'aria-label': '보기' },
      h('button', { type: 'button', class: mode === 'u' ? 'on' : null, onclick: () => setQ({ v: 'u' }, false) }, '기판별 (앞·뒤)'),
      h('button', { type: 'button', class: mode === 'r' ? 'on' : null, onclick: () => setQ({ v: 'r' }, false) }, '기록별'));
    const cnt = { n: units.length, ng: 0, rv: 0, p: 0 };
    if (mode === 'u') for (const u of units) { if (u.v === 'NG') cnt.ng++; else if (u.v === 'REVIEW') cnt.rv++; else if (u.v === 'PASS') cnt.p++; }
    else { cnt.n = recs.length; for (const r of recs) { if (r.x.r === 'NG') cnt.ng++; else if (r.x.r === 'REVIEW') cnt.rv++; else if (r.x.r === 'PASS') cnt.p++; } }
    const chip = h('span', { class: 'chip stat ' + (cnt.ng ? 'bad' : 'ok') }, h('span', { class: 'dot' }),
      `${mode === 'u' ? '기판' : '기록'} `, h('b', null, fmt(cnt.n)), ` · 양품 ${fmt(cnt.p)} · 불량 ${fmt(cnt.ng)}${cnt.rv ? ' · 확인 ' + fmt(cnt.rv) : ''}${cnt.n ? ' · 불량률 ' + pctTxt(cnt.ng, cnt.n) : ''}`);
    const filters = h('div', { class: 'filters rec' },
      seg,
      presetChips((p) => { const r = presetRange(p); setQ({ f: r[0], t: r[1], s: '' }, true); }, null),
      h('span', { class: 'daterange' }, from, '~', to),
      h('span', { class: 'search' }, bc),
      sel('판정', q.r, [['', '전체'], ['PASS', '양품'], ['NG', '불량'], ['REVIEW', '확인 필요']], (v) => setQ({ r: v, s: '' }, false)),
      boards.length > 1 ? sel('기판 종류', q.b, [['', '전체'], ...boards.map(([id, b]) => [id, b.n || '#' + id])], (v) => setQ({ b: v, s: '' }, false)) : null,
      sel('같은 바코드', q.dup, [['', '전체'], ['1', '중복만']], (v) => setQ({ dup: v, s: '' }, false)),
      chip,
      h('span', { class: 'spacer' }),
      h('button', { class: 'btn', type: 'button', onclick: () => exportExcel(q, true), title: '이 조건의 기판을 기판별 12열 형식으로, 앞면·뒷면 사진(불량 위치 표시)을 넣어 내려받습니다' }, '엑셀 (사진 포함)'),
      h('button', { class: 'btn', type: 'button', onclick: () => exportExcel(q, false) }, '사진 없이'));
    const listBox = h('div', { class: 'hist-table' });
    const more = h('div', { class: 'more-row' });
    const renderList = () => {
      const total = mode === 'u' ? units.length : recs.length;
      listBox.replaceChildren(mode === 'u' ? unitsTable(units.slice(0, S.shown)) : recordsTable(recs.slice(0, S.shown)));
      more.replaceChildren();
      if (total > S.shown) {
        more.append(h('span', { class: 'muted' }, `${fmt(Math.min(S.shown, total))}건 표시 · ${fmt(total - S.shown)}건 더 있음`),
          h('button', { class: 'btn sm', type: 'button', onclick: () => { S.shown += PAGE; renderList(); markSel(); } }, `다음 ${fmt(Math.min(PAGE, total - S.shown))}건`),
          h('button', { class: 'btn sm', type: 'button', onclick: () => { S.shown = total; renderList(); markSel(); } }, `모두 보기 (${fmt(total)}건)`));
      }
      if (!total) listBox.replaceChildren(h('div', { class: 'empty' }, h('div', { class: 'title' }, '검사 기록이 없습니다'), h('div', null, '조건을 바꿔 보세요.')));
    };
    const detail = h('aside', { class: 'card detail-pane', id: 'detail' }, h('div', { class: 'empty' }, h('div', { class: 'title' }, '기록을 선택하세요'), h('div', null, '검사 사진과 불량 위치, 판정 근거를 볼 수 있습니다.')));
    const main = h('main', { class: 'wrap' }, filters, h('div', { class: 'hist' }, h('section', { class: 'card hist-list' }, listBox, more), detail), foot());
    app.replaceChildren(topBar('rec'), main);
    if (refocus) { bc.focus(); try { bc.setSelectionRange(refocus[0], refocus[1]); } catch { /* type=search without selection API */ } }
    renderList();
    renderSelection();
  }
  function sideCell(u, x, label) {
    if (!x) return h('td', { class: 'unit-side none' }, h('span', { class: 'muted' }, '없음'));
    const td = h('td', { class: 'unit-side', 'data-id': x.id, title: `${label} · #${x.id} · ${x.ts}`, tabindex: '0', role: 'button', 'aria-label': `${label} ${VERDICT_KO[x.r] || x.r} 열기`,
      onclick: (e) => { e.stopPropagation(); openRec(x.id); }, onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.stopPropagation(); openRec(x.id); } } },
      h('div', { class: 'cellrow' }, thumbEl(x), h('div', { class: 'stack' }, h('span', { class: 'verdict-tag ' + x.r }, VERDICT_KO[x.r] || x.r),
        h('span', { class: 'mono muted small' }, hhmm(x.ts) + (x.df && x.df.length ? ' · 불량 ' + x.df.length : '')))));
    return td;
  }
  function unitsTable(units) {
    const lab = units.length ? units[0].labels : ['앞면', '뒷면'];
    return h('table', { class: 'table units' },
      h('thead', null, h('tr', null, h('th', null, '바코드'), h('th', { class: 'hide-s' }, '시각'), h('th', null, lab[0]), h('th', null, lab[1]), h('th', null, '종합'),
        h('th', { class: 'hide-s' }, '시차'), h('th', { class: 'hide-m' }, '기판 종류'))),
      h('tbody', null, units.map((u) => h('tr', { class: 'click', 'data-ids': [u.f && u.f.id, u.b && u.b.id].filter(Boolean).join(','), tabindex: '0',
        onclick: () => { const x = u.f || u.b; if (x) openRec(x.id); }, onkeydown: (e) => { if (e.target === e.currentTarget && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); const x = u.f || u.b; if (x) openRec(x.id); } } },
        h('td', { class: 'mono' }, u.bc || h('span', { class: 'muted' }, '—'), ((u.f && u.f.seq > 1) || (u.b && u.b.seq > 1)) ? h('span', { class: 'chip warn tiny', title: '같은 바코드 회차' }, '×' + Math.max((u.f && u.f.seq) || 0, (u.b && u.b.seq) || 0)) : null,
          h('div', { class: 'mono muted small show-s' }, mdhm(unitTs(u)))),
        h('td', { class: 'mono hide-s' }, mdhm(unitTs(u))),
        sideCell(u, u.f, u.labels[0]), sideCell(u, u.b, u.labels[1]),
        h('td', null, h('span', { class: 'verdict-tag ' + u.v }, VERDICT_KO[u.v] || u.v || '—'), u.note ? h('div', { class: 'muted small' }, u.note) : null),
        h('td', { class: 'mono muted hide-s' }, u.dt != null ? (u.dt >= 60 ? Math.round(u.dt / 60) + '분' : u.dt + '초') : ''),
        h('td', { class: 'hide-m' }, (u.f && u.f.bd) || (u.b && u.b.bd) || '—')))));
  }
  function recordsTable(recs) {
    return h('table', { class: 'table records' },
      h('thead', null, h('tr', null, h('th', { style: 'width:84px' }, ''), h('th', null, '시각'), h('th', { class: 'hide-m' }, '기판 종류'), h('th', null, '바코드'), h('th', null, '판정'),
        h('th', null, '불량'), h('th', { class: 'hide-s' }, 'AI'), h('th', { class: 'hide-s' }, '소요'))),
      h('tbody', null, recs.map(({ u, k, x }) => h('tr', { class: 'click', 'data-ids': String(x.id), tabindex: '0', onclick: () => openRec(x.id),
        onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openRec(x.id); } } },
        h('td', null, thumbEl(x)),
        h('td', { class: 'mono' }, mdhm(x.ts), h('div', { class: 'muted small' }, u.labels[k === 'f' ? 0 : 1])),
        h('td', { class: 'hide-m' }, x.bd || '—'),
        h('td', { class: 'mono' }, u.bc || h('span', { class: 'muted' }, '—'), x.seq > 1 ? h('span', { class: 'chip warn tiny', title: `같은 바코드 ${x.seq}회째` }, '×' + x.seq) : null),
        h('td', null, h('span', { class: 'verdict-tag ' + x.r }, VERDICT_KO[x.r] || x.r), x.ovr ? h('span', { class: 'muted small' }, ' 수동') : null),
        h('td', { class: 'mono' }, x.df && x.df.length ? String(x.df.length) : ''),
        h('td', { class: 'mono muted hide-s' }, x.ai ? '$' + (x.aic || 0).toFixed(3) : ''),
        h('td', { class: 'mono muted hide-s' }, x.ms != null ? (x.ms / 1000).toFixed(1) + '초' : '')))));
  }
  function findRec(id) {
    for (const u of S.rec ? S.rec.units : []) {
      if (u.f && u.f.id === id) return { u, k: 'f', x: u.f };
      if (u.b && u.b.id === id) return { u, k: 'b', x: u.b };
    }
    return null;
  }
  function openRec(id) {   // on a phone the sheet is a history entry: the back button closes it
    const push = !wide() && !(S.rq && S.rq.s);
    if (push) S.pushedSel = true;
    setQ({ s: String(id) }, push);
  }
  function markSel() {
    const id = S.rq && S.rq.s;
    document.querySelectorAll('.hist-table tr[aria-selected]').forEach((tr) => tr.removeAttribute('aria-selected'));
    document.querySelectorAll('.hist-table td.sel').forEach((td) => td.classList.remove('sel'));
    if (!id) return;
    document.querySelectorAll('.hist-table tr[data-ids]').forEach((tr) => { if (tr.dataset.ids.split(',').includes(id)) tr.setAttribute('aria-selected', 'true'); });
    document.querySelectorAll(`.hist-table td.unit-side[data-id="${CSS.escape(id)}"]`).forEach((td) => td.classList.add('sel'));
  }
  function closeLightbox() { if (S.lbClose) S.lbClose(); }
  function renderSelection() {
    closeLightbox();
    const id = S.rq && S.rq.s ? parseInt(S.rq.s, 10) : null;
    markSel();
    const found = id ? findRec(id) : null;
    closeSheet();
    for (const u of S.overlayUrls) URL.revokeObjectURL(u);
    S.overlayUrls = [];
    const pane = $('#detail');
    if (!found) {
      if (pane) pane.replaceChildren(h('div', { class: 'empty' }, h('div', { class: 'title' }, '기록을 선택하세요'), h('div', null, '검사 사진과 불량 위치, 판정 근거를 볼 수 있습니다.')));
      return;
    }
    const body = detailView(found);
    if (wide() && pane) { pane.replaceChildren(body); pane.scrollTop = 0; return; }
    const sheet = h('div', { class: 'sheet', role: 'dialog', 'aria-modal': 'true', 'aria-label': '검사 기록 상세' },
      h('div', { class: 'sheet-close' }, h('button', { class: 'btn sm', type: 'button', onclick: closeDetail }, '닫기')), body);
    const ov = h('div', { class: 'overlay sheet-ov' }, sheet);
    ov.addEventListener('click', (e) => { if (e.target === ov) closeDetail(); });
    document.body.append(ov);
    document.addEventListener('keydown', escDetail);
    const cb = $('.sheet-close button', sheet); if (cb) cb.focus();
    if (pane) pane.replaceChildren(h('div', { class: 'empty' }, '기록을 선택하세요'));
  }
  function escDetail(e) { if (e.key === 'Escape' && !$('.lightbox')) closeDetail(); }
  function closeSheet() { const o = $('.overlay.sheet-ov'); if (o) o.remove(); document.removeEventListener('keydown', escDetail); }
  function closeDetail() {
    if (S.pushedSel && S.rq && S.rq.s) { S.pushedSel = false; history.back(); return; }   // opened from a row on a phone: step back
    setQ({ s: '' }, false);
  }
  function closeOverlays() { closeSheet(); closeLightbox(); for (const u of S.overlayUrls) URL.revokeObjectURL(u); S.overlayUrls = []; }

  // the detail of one record (the history tab's right pane)
  function overlaySvg(rec, hl) {
    const { W, H, comps } = geom(rec);
    const sw = Math.max(2, W / 900), fs = Math.max(12, W / 40);
    const svg = sv('svg', { viewBox: `0 0 ${W} ${H}`, class: 'boxes', 'aria-hidden': 'true' });
    for (const c of comps) svg.append(sv('rect', { x: c[0], y: c[1], width: c[2], height: c[3], fill: 'none', stroke: 'rgba(127,169,155,0.45)', 'stroke-width': sw }));
    (rec.df || []).forEach((d, i) => {
      if (!d.b) return;
      const [x, y, w, hh] = d.b;
      const on = hl === i;
      svg.append(sv('g', { class: 'dbox' + (on ? ' hl' : ''), 'data-i': i },
        sv('rect', { x, y, width: w, height: hh, fill: on ? 'rgba(255,90,31,0.28)' : 'rgba(255,90,31,0.12)', stroke: '#FF5A1F', 'stroke-width': sw * (on ? 3 : 1.6) }),
        sv('text', { x, y: Math.max(fs, y - fs * 0.25), fill: '#FF5A1F', stroke: 'rgba(0,0,0,0.65)', 'stroke-width': fs / 12, 'paint-order': 'stroke', 'font-weight': 700, 'font-size': fs, 'font-family': 'ui-monospace, monospace' }, `${i + 1} ${d.t}`)));
    });
    return svg;
  }
  function photoBox(rec, cls, onClick) {
    const box = h('div', { class: 'photo-box ' + (cls || '') });
    const src = photoSrc(rec);
    if (!src && !rec._tb) { box.append(h('div', { class: 'nophoto' }, noPhotoText(rec))); return box; }
    const { W, H } = geom(rec);
    if (!src) {   // no big photo here (the PC's address is not set): the site's small photo, with a note
      box.style.aspectRatio = `${W} / ${H}`;
      const im = h('img', { alt: '검사 사진 (작은 사진)' });
      box.append(im, overlaySvg(rec, -1), h('div', { class: 'ph-note' }, noPhotoText(rec)));
      thumbBlob(rec).then((b) => { const u = URL.createObjectURL(b); S.overlayUrls.push(u); im.src = u; })
        .catch(() => box.replaceChildren(h('div', { class: 'nophoto' }, noPhotoText(rec))));
      return box;
    }
    box.style.aspectRatio = `${W} / ${H}`;
    const img = h('img', { alt: '검사 사진' });
    const svg = overlaySvg(rec, -1);
    box.append(img, svg, h('div', { class: 'ph-loading' }, h('span', { class: 'spinner' })));
    const show = (b) => { const u = URL.createObjectURL(b); S.overlayUrls.push(u); img.src = u; const l = $('.ph-loading', box); if (l) l.remove(); };
    src.get().then(show).catch(async (ex) => {
      const why = '사진을 불러오지 못했습니다: ' + (src.kind === 'drive' ? driveErrText(ex) : errText(ex));
      if (src.kind === 'pc' && rec._tb) {   // the PC is off or unreachable: the site's small photo instead
        try { show(await thumbBlob(rec)); box.append(h('div', { class: 'ph-note' }, why + ' — 작은 사진을 보여 줍니다')); return; } catch { /* below */ }
      }
      box.replaceChildren(h('div', { class: 'nophoto' }, why));
    });
    if (onClick) { box.classList.add('zoomable'); box.addEventListener('click', onClick); }
    return box;
  }
  function highlight(root, i) {
    root.querySelectorAll('.dbox').forEach((g) => {
      const on = String(i) === g.getAttribute('data-i');
      g.classList.toggle('hl', on);
      const r = g.querySelector('rect'); if (r) { r.setAttribute('fill', on ? 'rgba(255,90,31,0.28)' : 'rgba(255,90,31,0.12)'); }
    });
    root.querySelectorAll('.reason').forEach((el) => el.classList.toggle('hl', String(i) === el.getAttribute('data-i')));
  }
  function detailView({ u, k, x }) {
    const label = u.labels[k === 'f' ? 0 : 1];
    const root = h('div', { class: 'detail' });
    const other = k === 'f' ? u.b : u.f;
    const sideBtn = (rec, lab) => rec ? h('button', { type: 'button', class: 'btn xs' + (rec.id === x.id ? ' primary' : ''), onclick: () => openRec(rec.id) }, lab, ' ', h('span', { class: 'verdict-tag ' + rec.r }, VERDICT_KO[rec.r] || rec.r)) : null;
    root.append(h('div', { class: 'unitbar' }, h('span', { class: 'muted small' }, '기판 ', h('b', { class: 'mono' }, u.bc || '(바코드 없음)')),
      sideBtn(u.f, u.labels[0]), sideBtn(u.b, u.labels[1]),
      !other ? h('span', { class: 'muted small' }, (k === 'f' ? u.labels[1] : u.labels[0]) + ' 기록 없음') : null,
      u.dt != null ? h('span', { class: 'muted small' }, '시차 ' + u.dt + '초') : null));
    const zoom = () => openLightbox(x, label);
    root.append(h('div', { class: 'cardhead' }, h('h3', null, `검사 #${x.id}`, h('span', { class: 'muted' }, ' · ' + label)),
      h('span', { class: 'row' }, photoSrc(x) ? h('button', { class: 'btn xs', type: 'button', onclick: zoom }, '크게 보기') : null, h('span', { class: 'verdict-tag ' + x.r }, VERDICT_KO[x.r] || x.r))));
    root.append(photoBox(x, 'dark', zoom));
    const ai = x.ai ? `사용 · $${(x.aic || 0).toFixed(4)}` : '미사용';
    root.append(h('div', { class: 'kv' },
      h('span', { class: 'k' }, '시각'), h('span', { class: 'mono' }, x.ts),
      h('span', { class: 'k' }, '기판 종류'), h('span', null, x.bd || '—'),
      h('span', { class: 'k' }, '바코드'), h('span', { class: 'mono' }, u.bc || '—', x.seq > 1 ? h('span', { class: 'chip warn tiny' }, `같은 바코드 ${x.seq}회째`) : null),
      h('span', { class: 'k' }, '자동 판정'), h('span', null, h('span', { class: 'verdict-tag ' + (x.res || x.r) }, VERDICT_KO[x.res || x.r] || x.res || x.r)),
      x.ovr ? h('span', { class: 'k' }, '수동 판정') : null, x.ovr ? h('span', null, h('span', { class: 'verdict-tag ' + x.ovr }, VERDICT_KO[x.ovr] || x.ovr)) : null,
      h('span', { class: 'k' }, 'AI'), h('span', { class: 'mono' }, ai),
      h('span', { class: 'k' }, '소요'), h('span', { class: 'mono' }, x.ms != null ? (x.ms / 1000).toFixed(1) + '초' : '—')));
    const ac = x.ac || [], df = x.df || [];
    if (x.ai || ac.length) {
      root.append(h('div', { class: 'aibox' }, h('div', { class: 'label' }, `AI 비용 $${(x.aic || 0).toFixed(3)} 가 든 이유`),
        h('div', { class: 'muted' }, `규칙이 ${ac.length + df.length}곳을 의심해 AI 에 재확인을 보냈습니다${ac.length ? ` · AI 가 ${ac.length}곳을 정상으로 정리` : ''}${df.length ? ` · ${df.length}곳은 ${x.r === 'NG' ? '불량으로' : '확인 필요로'} 남음` : ''}${x.r === 'PASS' && ac.length ? ' → 양품' : ''}.`),
        ac.map((a) => h('div', { class: 'aiitem' }, h('b', null, a.c), ' · 규칙: ', h('b', null, a.t), ' 의심', a.r ? h('span', { class: 'muted' }, ' — ' + a.r) : null, a.n ? h('div', { class: 'ainote' }, '→ ' + a.n) : null)),
        x.sum ? h('div', { class: 'muted', style: 'margin-top:5px' }, x.sum) : null));
    } else if (x.sum) {
      root.append(h('div', { class: 'aibox' }, h('div', { class: 'label' }, '판정 요약'), h('div', null, x.sum)));
    }
    const list = h('div', { class: 'defect-list' }, h('div', { class: 'label' }, `불량 ${df.length}`));
    df.forEach((d, i) => {
      const item = h('div', { class: 'reason', 'data-i': i, tabindex: '0' },
        h('span', { class: 'n' }, String(i + 1)),
        h('div', { class: 'body' }, h('div', { class: 't' }, d.t, h('span', { class: 'k' }, d.c)), d.r ? h('div', { class: 'r' }, d.r) : null,
          d.img && x.ph ? cropImg(`img/${encodeURIComponent(x.ph)}_${encodeURIComponent(d.img)}.bin`, `${d.c} 골든(왼쪽)과 검사 사진(오른쪽)`) : null),
        h('span', { class: 'tags' }, h('span', { class: 'src-tag' }, SOURCE_KO[d.src] || d.src || '규칙'), d.cf ? h('span', { class: 'tag-ng' }, 'NG 확정') : null));
      const on = () => highlight(root, i);
      item.addEventListener('mouseenter', on); item.addEventListener('focus', on); item.addEventListener('click', on);
      list.append(item);
    });
    if (!df.length) list.append(h('div', { class: 'muted small' }, x.r === 'PASS' ? '검출된 불량이 없습니다.' : '남은 불량 항목 없음 (작업자가 지움)'));
    root.append(list);
    if (!photoSrc(x)) root.append(h('div', { class: 'note' }, photoNote()));
    return root;
  }
  function cropImg(path, alt) {
    const img = h('img', { class: 'crop', alt, loading: 'lazy' });
    blobFromSite(path + '?e=' + encodeURIComponent(S.index.e || '')).then((b) => { const u = URL.createObjectURL(b); S.overlayUrls.push(u); img.src = u; })
      .catch(() => img.replaceWith(h('div', { class: 'note' }, '비교 사진을 불러오지 못했습니다')));
    return img;
  }

  // zoom view: wheel / pinch to zoom, drag to pan, the boxes stay on the photo (one transform for both)
  function openLightbox(rec, label) {
    const src = photoSrc(rec); if (!src) return;
    const { W, H } = geom(rec);
    const stage = h('div', { class: 'lb-stage' });
    const layer = h('div', { class: 'lb-layer' });
    const img = h('img', { alt: '검사 사진', draggable: 'false' });
    layer.style.width = W + 'px'; layer.style.height = H + 'px';
    const svg = overlaySvg(rec, -1); svg.setAttribute('width', W); svg.setAttribute('height', H);
    layer.append(img, svg);
    stage.append(layer);
    let s = 1, tx = 0, ty = 0, fitS = 1;
    const apply = () => { layer.style.transform = `translate(${tx}px, ${ty}px) scale(${s})`; };
    const fit = () => { const r = stage.getBoundingClientRect(); fitS = Math.min(r.width / W, r.height / H); s = fitS; tx = (r.width - W * s) / 2; ty = (r.height - H * s) / 2; apply(); };
    const zoomAt = (f, cx, cy) => { const ns = Math.max(fitS * 0.5, Math.min(fitS * 40, s * f)); tx = cx - ((cx - tx) * ns) / s; ty = cy - ((cy - ty) * ns) / s; s = ns; apply(); };
    stage.addEventListener('wheel', (e) => { e.preventDefault(); const r = stage.getBoundingClientRect(); zoomAt(e.deltaY < 0 ? 1.2 : 1 / 1.2, e.clientX - r.left, e.clientY - r.top); }, { passive: false });
    const pts = new Map();
    let last = null;
    stage.addEventListener('pointerdown', (e) => { stage.setPointerCapture(e.pointerId); pts.set(e.pointerId, [e.clientX, e.clientY]); last = null; });
    stage.addEventListener('pointermove', (e) => {
      if (!pts.has(e.pointerId)) return;
      const prev = pts.get(e.pointerId); pts.set(e.pointerId, [e.clientX, e.clientY]);
      if (pts.size === 1) { tx += e.clientX - prev[0]; ty += e.clientY - prev[1]; apply(); }
      else if (pts.size === 2) {
        const [a, b] = [...pts.values()], d = Math.hypot(a[0] - b[0], a[1] - b[1]), r = stage.getBoundingClientRect();
        if (last) zoomAt(d / last, (a[0] + b[0]) / 2 - r.left, (a[1] + b[1]) / 2 - r.top);
        last = d;
      }
    });
    const up = (e) => { pts.delete(e.pointerId); last = null; };
    stage.addEventListener('pointerup', up); stage.addEventListener('pointercancel', up);
    stage.addEventListener('dblclick', (e) => { const r = stage.getBoundingClientRect(); zoomAt(2, e.clientX - r.left, e.clientY - r.top); });
    const close = () => { lb.remove(); document.removeEventListener('keydown', key); if (S.lbClose === close) S.lbClose = null; };
    const key = (e) => { if (e.key === 'Escape') close(); else if (e.key === '+' || e.key === '=') { const r = stage.getBoundingClientRect(); zoomAt(1.4, r.width / 2, r.height / 2); } else if (e.key === '-') { const r = stage.getBoundingClientRect(); zoomAt(1 / 1.4, r.width / 2, r.height / 2); } else if (e.key === '0') fit(); };
    const btn = (t, f, title) => h('button', { class: 'btn sm', type: 'button', title, onclick: f }, t);
    const lb = h('div', { class: 'lightbox', role: 'dialog', 'aria-modal': 'true', 'aria-label': '사진 크게 보기' },
      h('div', { class: 'lb-bar' }, h('span', { class: 'lb-title' }, `#${rec.id} · ${label} · ${rec.ts}`),
        btn('＋', () => { const r = stage.getBoundingClientRect(); zoomAt(1.4, r.width / 2, r.height / 2); }, '확대 (+)'),
        btn('－', () => { const r = stage.getBoundingClientRect(); zoomAt(1 / 1.4, r.width / 2, r.height / 2); }, '축소 (-)'),
        btn('맞춤', fit, '화면에 맞춤 (0)'), btn('닫기', close, '닫기 (Esc)')),
      stage);
    closeLightbox();
    document.body.append(lb);
    document.addEventListener('keydown', key);
    S.lbClose = close;
    const first = lb.querySelector('.lb-bar .btn:last-child'); if (first) first.focus();
    fit();
    src.get().then((b) => { const u = URL.createObjectURL(b); S.overlayUrls.push(u); img.src = u; }).catch((ex) => { stage.replaceChildren(h('div', { class: 'nophoto' }, '사진을 불러오지 못했습니다: ' + errText(ex))); });
  }

  // ---------------------------------------------------------------- Excel: the '기판별 (앞·뒤)' sheet, 12 columns (the user's format), with the photos
  const XL_HEAD = ['번호', '개별 바코드', '앞면 사진', '뒷면 사진', '종합 판정', '앞면 판정', '뒷면 판정', '앞면 시각', '뒷면 시각', '시차(초)', '앞면 불량 요약', '뒷면 불량 요약'];
  const XL_W = [7, 22, 28, 28, 10, 10, 10, 19, 19, 8, 44, 44];   // the photo columns hold a 180 px picture
  async function exportExcel(q, withPhotos) {
    if (S.busy) { toast('엑셀을 만드는 중입니다'); return; }
    const range = [q.f, q.t];
    if (!daysIn(range).length) { toast('이 기간에는 기록이 없습니다'); return; }
    const prog = h('div', { class: 'xl-prog' }, '기록을 불러오는 중…');
    let cancelled = false;
    const dlg = h('div', { class: 'overlay xl' }, h('div', { class: 'card xl-box' }, h('h3', null, withPhotos ? '엑셀 만들기 (사진 포함)' : '엑셀 만들기'), prog,
      h('div', { class: 'row' }, h('button', { class: 'btn sm', type: 'button', onclick: () => { cancelled = true; } }, '취소'))));
    document.body.append(dlg);
    S.busy = true;
    try {
      const units = recFilter(await loadUnits(range, (k, n) => { prog.textContent = `기록을 불러오는 중… ${k}/${n}일`; }, () => cancelled), Object.assign({}, q, { v: 'u' }));
      if (cancelled) { toast('취소했습니다'); return; }
      units.reverse();   // oldest first, like the program's sheet
      if (!units.length) { toast('조건에 맞는 기판이 없습니다'); return; }
      const rows = [], pics = [];
      units.forEach((u, i) => {
        const r = i + 2;   // sheet row (1 = header)
        rows.push([range[0] === range[1] ? u.n : i + 1, u.bc || '', '', '', VERDICT_KO[u.v] || u.v || '', (u.f && (VERDICT_KO[u.f.r] || u.f.r)) || '', (u.b && (VERDICT_KO[u.b.r] || u.b.r)) || '',
          (u.f && u.f.ts) || '', (u.b && u.b.ts) || '', u.dt == null ? '' : u.dt, (u.f && u.f.s) || '', (u.b && u.b.s) || '']);
        if (withPhotos) for (const [col, x] of [[2, u.f], [3, u.b]]) {
          if (!x) continue;
          if (x.ph || hasThumb(x)) pics.push({ row: r, col, x }); else rows[i][col] = noPhotoText(x);
        }
      });
      if (withPhotos && pics.length > XL_PHOTO_MAX) { toast(`사진이 ${fmt(pics.length)}장이라 한 파일에 넣을 수 없습니다 (${fmt(XL_PHOTO_MAX)}장까지) - 기간을 줄이거나 '사진 없이'로 받으세요`); return; }
      if (withPhotos && pics.length > XL_PHOTO_WARN && !window.confirm(`사진 ${fmt(pics.length)}장을 넣습니다. 몇 분 걸릴 수 있습니다 (기간을 줄이면 빨라집니다). 계속할까요?`)) return;
      if (cancelled) { toast('취소했습니다'); return; }
      const images = [];
      if (withPhotos && pics.length) {
        let done = 0, failed = 0, next = 0;
        const worker = async () => {
          while (!cancelled && next < pics.length) {
            const p = pics[next++];
            try {
              // NG / 확인 필요: the site's 1200 px photo (sharper boxes); every other record: its small photo (site bundle, else the PC)
              const sj = await smallJpeg(p.x.ph ? await photoSrc(p.x).get() : await thumbBlob(p.x), XL_PHOTO_W, p.x, true);
              images.push({ row: p.row, col: p.col, data: new Uint8Array(await sj.b.arrayBuffer()), w: sj.w, h: sj.h });
            } catch { failed++; rows[p.row - 2][p.col] = '사진을 불러오지 못함'; }
            done++;
            if (done % 10 === 0 || done === pics.length) prog.textContent = `사진 ${fmt(done)} / ${fmt(pics.length)}${failed ? ` (실패 ${failed})` : ''}`;
          }
        };
        await Promise.all(Array.from({ length: 6 }, worker));
        if (cancelled) { toast('취소했습니다'); return; }
      }
      if (cancelled) { toast('취소했습니다'); return; }
      prog.textContent = '파일을 만드는 중…';
      const blob = buildXlsx('기판별 (앞·뒤)', XL_HEAD, XL_W, rows, images);
      const name = `ARGUS_기판별_${range[0]}${range[0] === range[1] ? '' : '~' + range[1]}${withPhotos ? '_사진' : ''}.xlsx`;
      const a = h('a', { href: URL.createObjectURL(blob), download: name });
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 60000);
      toast(`${name} · ${fmt(rows.length)}행${withPhotos ? ' · 사진 ' + fmt(images.length) + '장' : ''}`);
    } catch (ex) {
      if (await passwordChanged(ex)) return;
      toast('엑셀을 만들지 못했습니다: ' + errText(ex));
    } finally {
      S.busy = null;
      dlg.remove();
    }
  }
  function xesc(s) {
    return String(s).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F￾￿]/g, '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function colName(i) { let s = ''; i++; while (i) { const m = (i - 1) % 26; s = String.fromCharCode(65 + m) + s; i = Math.floor((i - 1) / 26); } return s; }
  // a minimal xlsx: one sheet, styles, frozen header, autofilter; with images: one drawing part (oneCellAnchor per picture, JPEG media)
  function buildXlsx(sheetName, head, widths, rows, images) {
    images = (images || []).slice().sort((a, b) => a.row - b.row || a.col - b.col);
    const last = colName(head.length - 1), nRows = rows.length + 1;
    const picRows = new Map();
    for (const im of images) picRows.set(im.row, Math.max(picRows.get(im.row) || 0, im.h));
    const cell = (r, c, v, st) => {
      const ref = colName(c) + r;
      if (v === '' || v == null) return st ? `<c r="${ref}" s="${st}"/>` : '';
      if (typeof v === 'number' && isFinite(v)) return `<c r="${ref}" s="${st}"><v>${v}</v></c>`;
      return `<c r="${ref}" s="${st}" t="inlineStr"><is><t xml:space="preserve">${xesc(v)}</t></is></c>`;
    };
    const vs = (v) => (v === '양품' || v === 'PASS' ? 2 : v === '불량' || v === '확인 필요' || v === 'NG' || v === 'REVIEW' ? 3 : 1);
    const parts = ['<row r="1" ht="22" customHeight="1">' + head.map((t, c) => cell(1, c, t, 4)).join('') + '</row>'];
    rows.forEach((row, i) => {
      const r = i + 2, ph = picRows.get(r);
      parts.push(`<row r="${r}"${ph ? ` ht="${Math.ceil((ph + 8) * 0.75)}" customHeight="1"` : ''}>` +
        row.map((v, c) => cell(r, c, v, c >= 4 && c <= 6 ? vs(v) : (c === 10 || c === 11 || c === 2 || c === 3 ? 5 : 1))).join('') + '</row>');
    });
    const cols = widths.map((w, i) => `<col min="${i + 1}" max="${i + 1}" width="${w}" customWidth="1"/>`).join('');
    const sheet = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><dimension ref="A1:${last}${nRows}"/><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><sheetFormatPr defaultRowHeight="15"/><cols>${cols}</cols><sheetData>${parts.join('')}</sheetData><autoFilter ref="A1:${last}${nRows}"/>${images.length ? '<drawing r:id="rId1"/>' : ''}</worksheet>`;
    const sn = xesc(sheetName);
    const wb = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="${sn}" sheetId="1" r:id="rId1"/></sheets><definedNames><definedName name="_xlnm._FilterDatabase" localSheetId="0" hidden="1">'${sn}'!$A$1:$${last}$${nRows}</definedName></definedNames></workbook>`;
    const styles = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="4"><font><sz val="10"/><name val="Malgun Gothic"/></font><font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Malgun Gothic"/></font><font><b/><sz val="10"/><color rgb="FF0B6B3A"/><name val="Malgun Gothic"/></font><font><b/><sz val="10"/><color rgb="FFA3261B"/><name val="Malgun Gothic"/></font></fonts><fills count="5"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF1F1F1F"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFDDF3E4"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFBDCD5"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border><border><left style="thin"><color rgb="FFD0D0D0"/></left><right style="thin"><color rgb="FFD0D0D0"/></right><top style="thin"><color rgb="FFD0D0D0"/></top><bottom style="thin"><color rgb="FFD0D0D0"/></bottom><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="6"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="center"/></xf><xf numFmtId="0" fontId="2" fillId="3" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="center"/></xf><xf numFmtId="0" fontId="3" fillId="4" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="center"/></xf><xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>`;
    const files = [
      ['[Content_Types].xml', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>${images.length ? '<Default Extension="jpeg" ContentType="image/jpeg"/>' : ''}<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>${images.length ? '<Override PartName="/xl/drawings/drawing1.xml" ContentType="application/vnd.openxmlformats-officedocument.drawing+xml"/>' : ''}</Types>`],
      ['_rels/.rels', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`],
      ['xl/workbook.xml', wb],
      ['xl/_rels/workbook.xml.rels', `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`],
      ['xl/styles.xml', styles],
      ['xl/worksheets/sheet1.xml', sheet],
    ].map(([n, t]) => [n, te.encode(t)]);
    if (images.length) {
      const EMU = 9525;   // EMU per pixel
      const anchors = images.map((im, k) => `<xdr:twoCellAnchor editAs="twoCell"><xdr:from><xdr:col>${im.col}</xdr:col><xdr:colOff>${4 * EMU}</xdr:colOff><xdr:row>${im.row - 1}</xdr:row><xdr:rowOff>${4 * EMU}</xdr:rowOff></xdr:from><xdr:to><xdr:col>${im.col}</xdr:col><xdr:colOff>${(4 + im.w) * EMU}</xdr:colOff><xdr:row>${im.row - 1}</xdr:row><xdr:rowOff>${(4 + im.h) * EMU}</xdr:rowOff></xdr:to><xdr:pic><xdr:nvPicPr><xdr:cNvPr id="${k + 2}" name="Picture ${k + 1}"/><xdr:cNvPicPr><a:picLocks noChangeAspect="1"/></xdr:cNvPicPr></xdr:nvPicPr><xdr:blipFill><a:blip r:embed="rId${k + 1}"/><a:stretch><a:fillRect/></a:stretch></xdr:blipFill><xdr:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="${im.w * EMU}" cy="${im.h * EMU}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></xdr:spPr></xdr:pic><xdr:clientData/></xdr:twoCellAnchor>`).join('');
      files.push(['xl/worksheets/_rels/sheet1.xml.rels', te.encode(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/drawing" Target="../drawings/drawing1.xml"/></Relationships>`)]);
      files.push(['xl/drawings/drawing1.xml', te.encode(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<xdr:wsDr xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">${anchors}</xdr:wsDr>`)]);
      files.push(['xl/drawings/_rels/drawing1.xml.rels', te.encode(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${images.map((im, k) => `<Relationship Id="rId${k + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="../media/image${k + 1}.jpeg"/>`).join('')}</Relationships>`)]);
      images.forEach((im, k) => files.push([`xl/media/image${k + 1}.jpeg`, im.data]));
    }
    return new Blob([zipStore(files)], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
  }
  let CRC_T = null;
  function crc32(u) {
    if (!CRC_T) { CRC_T = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; CRC_T[n] = c >>> 0; } }
    let c = 0xffffffff; for (let i = 0; i < u.length; i++) c = CRC_T[(c ^ u[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0;
  }
  function zipStore(files) {   // a stored (uncompressed) zip - a valid xlsx container without any library
    if (files.length > 65535) throw new Error('파일 안의 항목이 너무 많습니다 - 기간을 줄이세요');
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
    if (off + cdSize >= 0xffffffff) throw new Error('파일이 4 GB 를 넘습니다 - 기간을 줄이세요');
    const end = new DataView(new ArrayBuffer(22));
    end.setUint32(0, 0x06054b50, true); end.setUint16(8, files.length, true); end.setUint16(10, files.length, true);
    end.setUint32(12, cdSize, true); end.setUint32(16, off, true);
    return new Blob([...parts, ...central, new Uint8Array(end.buffer)]);
  }

  boot();
})();
