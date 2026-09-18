/* Vuln-Trainer – Phase B, Kernübung: CVSS-Vektor aus der Beschreibung bauen.
   Reines JS, kein Build. Lädt data/*.json relativ (python3 -m http.server). */
(function () {
  'use strict';
  const { METRICS, parseVector, formatVector, baseScore, severity } = window.CVSS31;

  // Deutsche Beschriftung der acht Basismetriken und ihrer Werte.
  const METRIC_DEFS = [
    { k: 'AV', name: 'Angriffsvektor', vals: [
      ['N', 'Netzwerk', 'über das Netz erreichbar'],
      ['A', 'Angrenzend', 'nur aus dem angrenzenden Netz (LAN, WLAN, Bluetooth)'],
      ['L', 'Lokal', 'lokaler Zugriff / lokale Ausführung'],
      ['P', 'Physisch', 'physischer Zugang zum Gerät'] ] },
    { k: 'AC', name: 'Angriffskomplexität', vals: [
      ['L', 'Niedrig', 'keine besonderen Bedingungen'],
      ['H', 'Hoch', 'Bedingungen außerhalb der Kontrolle des Angreifers'] ] },
    { k: 'PR', name: 'Erforderliche Rechte', vals: [
      ['N', 'Keine', 'kein Konto nötig'],
      ['L', 'Niedrig', 'einfaches Benutzerkonto'],
      ['H', 'Hoch', 'Admin / privilegiertes Konto'] ] },
    { k: 'UI', name: 'Nutzerinteraktion', vals: [
      ['N', 'Keine', 'kein Opfer muss mitwirken'],
      ['R', 'Erforderlich', 'ein Opfer muss klicken / öffnen'] ] },
    { k: 'S', name: 'Scope', vals: [
      ['U', 'Unverändert', 'Wirkung bleibt in der verwundbaren Komponente'],
      ['C', 'Verändert', 'Wirkung erreicht eine andere Sicherheitszone'] ] },
    { k: 'C', name: 'Vertraulichkeit', vals: [
      ['N', 'Keine', 'keine Preisgabe'],
      ['L', 'Niedrig', 'begrenzter Umfang'],
      ['H', 'Hoch', 'alle oder die wertvollsten Daten'] ] },
    { k: 'I', name: 'Integrität', vals: [
      ['N', 'Keine', 'keine Manipulation'],
      ['L', 'Niedrig', 'begrenzte Manipulation'],
      ['H', 'Hoch', 'vollständige / gezielte Manipulation'] ] },
    { k: 'A', name: 'Verfügbarkeit', vals: [
      ['N', 'Keine', 'keine Einbuße'],
      ['L', 'Niedrig', 'begrenzte / vorübergehende Einbuße'],
      ['H', 'Hoch', 'vollständiger Ausfall'] ] },
  ];
  const STACK_DE = { web: 'Web', network: 'Netzwerk', linux: 'Linux', windows: 'Windows', application: 'Anwendung',
    library: 'Bibliothek', 'ics-iot': 'ICS / IoT', apple: 'Apple', android: 'Android', 'other-os': 'Sonstiges OS' };
  const SRC_DE = { nvd: 'NVD', cna: 'CNA' };
  const LOG_KEY = 'vt-attempts';
  // Knappe Begründungen (< TERSE_LIMIT Zeichen) werden um den generischen Metrik-Hinweis ergänzt.
  const TERSE_LIMIT = 25;
  function genericHint(k, v) {
    const d = METRIC_DEFS.find(x => x.k === k); const e = d && d.vals.find(x => x[0] === v);
    return e ? `${e[1]} – ${e[2]}` : '';
  }

  const $ = (id) => document.getElementById(id);
  const state = { cves: [], byId: new Map(), classes: {}, meta: {}, cur: null, choice: {}, seen: new Set(), locked: false, trapFilter: null };
  const session = { tries: 0, perfect: 0 };

  // ---------- Daten ----------
  async function loadData() {
    const [cves, classes, meta] = await Promise.all([
      fetch('data/cves.json').then(r => r.json()),
      fetch('data/classes.json').then(r => r.json()),
      fetch('data/meta.json').then(r => r.json()),
    ]);
    state.cves = cves; state.classes = classes; state.meta = meta;
    for (const c of cves) state.byId.set(c.id, c);
    $('meta-line').textContent = `${meta.cves} CVEs · KEV ${meta.kev_catalog_version} · EPSS ${meta.epss_model}`;
  }

  // ---------- Auswahl der nächsten CVE ----------
  // ---------- Spaced Repetition (Klassen-Ebene) ----------
  const lastCls = { cvss: null, quiz: null };
  function srAttempts() {
    let a = [], b = [];
    try { a = JSON.parse(localStorage.getItem(LOG_KEY) || '[]'); } catch (_) {}
    try { b = JSON.parse(localStorage.getItem('vt-class-attempts') || '[]'); } catch (_) {}
    return a.map(x => ({ cls: x.cls, ok: !!x.allOk, ts: x.ts })).concat(b.map(x => ({ cls: x.cls, ok: !!x.ok, ts: x.ts })));
  }
  function srStats() { return window.SR.computeStats(srAttempts()); }
  // Wählt erst die Klasse per Gewicht, dann eine zufällige CVE dieser Klasse.
  function srPick(src, kind) {
    const stats = srStats();
    const classes = [...new Set(src.map(c => c.cwe.learn_class))];
    const cls = window.SR.pickClass(stats, classes, lastCls[kind]);
    const cand = src.filter(c => c.cwe.learn_class === cls);
    const pick = (cand.length ? cand : src)[Math.floor(Math.random() * (cand.length ? cand : src).length)];
    lastCls[kind] = pick.cwe.learn_class;
    pick._srReason = window.SR.reasonFor(pick.cwe.learn_class, stats);
    return pick;
  }
  function pickNext() {
    const base = candidates('cvss');
    const pool = base.filter(c => !state.seen.has(c.id));
    const src = pool.length ? pool : (state.seen.clear(), base);
    return srPick(src.length ? src : state.cves, 'cvss');
  }

  // ---------- Rendering: Übung ----------
  function renderMetrics() {
    const host = $('metrics'); host.innerHTML = '';
    for (const def of METRIC_DEFS) {
      const box = document.createElement('div'); box.className = 'metric'; box.dataset.k = def.k;
      box.innerHTML = `<div class="mname"><b>${def.name}</b><span class="mk">${def.k}</span></div><div class="opts"></div>`;
      const opts = box.querySelector('.opts');
      for (const [v, label, hint] of def.vals) {
        const b = document.createElement('button'); b.type = 'button'; b.className = 'opt'; b.dataset.v = v;
        b.innerHTML = `${def.k}:${v} · ${label}<small>${hint}</small>`;
        b.addEventListener('click', () => choose(def.k, v));
        opts.appendChild(b);
      }
      host.appendChild(box);
    }
  }

  function choose(k, v) {
    if (state.locked) return;
    state.choice[k] = v;
    document.querySelectorAll(`.metric[data-k="${k}"] .opt`).forEach(b => b.classList.toggle('sel', b.dataset.v === v));
    updateLive();
  }

  function complete() { return METRICS.every(k => state.choice[k]); }

  function updateLive() {
    const n = METRICS.filter(k => state.choice[k]).length;
    if (complete()) {
      const sc = baseScore(state.choice), sev = severity(sc);
      $('live-vector').textContent = formatVector(state.choice);
      $('live-score').textContent = sc.toFixed(1);
      setSev($('live-sev'), sev);
      $('btn-compare').disabled = false;
    } else {
      $('live-vector').textContent = 'CVSS:3.1/' + METRICS.map(k => k + ':' + (state.choice[k] || '–')).join('/');
      $('live-score').textContent = `– (${n}/8)`;
      setSev($('live-sev'), null);
      $('btn-compare').disabled = true;
    }
  }

  function setSev(el, sev) {
    el.className = 'sev' + (sev ? ' sev-' + sev : '');
    el.textContent = sev || '';
    el.hidden = !sev;
  }

  function showCVE(cve) {
    state.cur = cve; state.choice = {}; state.locked = false; state.seen.add(cve.id);
    $('cve-id').textContent = cve.id;
    $('cve-published').textContent = cve.published ? cve.published.slice(0, 10) : '';
    $('cve-stack').textContent = STACK_DE[cve.stack] || cve.stack;
    const cls = state.classes[cve.cwe.learn_class];
    $('cve-class').textContent = (cls ? cls.name : cve.cwe.learn_class) + (cve.cwe.id ? ` · ${cve.cwe.id}` : '');
    $('cve-desc').textContent = (cve.description || '').trim();
    $('cve-sr').textContent = cve._srReason ? 'SR: ' + cve._srReason : '';
    document.querySelectorAll('.metric').forEach(m => { m.classList.remove('locked'); m.querySelectorAll('.opt').forEach(b => b.classList.remove('sel')); });
    updateLive();
    $('result').hidden = true; $('context').hidden = true;
    if (!$('quiz') || $('quiz').hidden) $('exercise').hidden = false;
    window.scrollTo({ top: 0 });
  }

  // ---------- Abgleich ----------
  function compare() {
    if (!complete() || state.locked) return;
    state.locked = true;
    document.querySelectorAll('.metric').forEach(m => m.classList.add('locked'));
    const cve = state.cur, off = parseVector(cve.cvss.official.vector);
    const ex = cve.exercises.cvss || {}, exm = ex.metrics || {};
    const correct = {}; let allOk = true;

    const tb = $('cmp-table').querySelector('tbody'); tb.innerHTML = '';
    for (const def of METRIC_DEFS) {
      const k = def.k, you = state.choice[k], nvd = off[k], ok = you === nvd;
      correct[k] = ok; if (!ok) allOk = false;
      const info = exm[k] || {};
      const tr = document.createElement('tr'); tr.className = ok ? 'ok' : 'bad';
      const whyText = (info.why || '').trim();
      let why = `<p class="why">${esc(whyText)}</p>`;
      if (whyText.length < TERSE_LIMIT) {
        why += `<p class="generic">Allgemein ${k}:${nvd} · ${esc(genericHint(k, nvd))}</p>`;
      }
      if (info.pitfall) {
        why += `<p class="pitfall"><b>${ok ? 'Falle vermieden' : 'Falle'}:</b> ${esc(info.pitfall)}</p>`;
      }
      tr.innerHTML = `<td><b>${def.name}</b> <span class="muted">${k}</span></td>
        <td class="v you">${k}:${you}</td><td class="v">${k}:${nvd}</td>
        <td class="mark">${ok ? '✓' : '✗'}</td><td>${why}</td>`;
      tb.appendChild(tr);
    }

    const offScore = cve.cvss.official.score, offSev = cve.cvss.official.severity;
    $('off-source').textContent = SRC_DE[cve.cvss.official.source] || cve.cvss.official.source;
    $('off-vector').textContent = cve.cvss.official.vector;
    $('off-score').textContent = Number(offScore).toFixed(1);
    setSev($('off-sev'), offSev);
    const nOk = METRICS.filter(k => correct[k]).length;
    $('result-title').textContent = allOk ? 'Abgleich: alle 8 Metriken richtig' : `Abgleich: ${nOk} von 8 Metriken richtig`;

    renderProvenance(cve, ex);
    renderContext(cve, ex);
    logAttempt(cve, correct, allOk);

    $('result').hidden = false; $('context').hidden = false;
    $('result').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // Vektor-Provenienz: NVD vs. CNA, abweichende Metriken + Dissens-Texte.
  function renderProvenance(cve, ex) {
    const box = $('provenance'); const d = cve.cvss.differs || [];
    if (!d.length || !cve.cvss.nvd || !cve.cvss.cna) { box.hidden = true; box.innerHTML = ''; return; }
    const mark = (vec) => {
      const p = parseVector(vec);
      return 'CVSS:3.1/' + METRICS.map(k => d.includes(k) ? `<span class="dm">${k}:${p[k]}</span>` : `${k}:${p[k]}`).join('/');
    };
    let html = `<h3>Vektor-Provenienz: NVD und CNA weichen ab (${d.join(', ')})</h3>
      <div class="row"><span class="src">NVD</span><code class="vector">${mark(cve.cvss.nvd.vector)}</code><span class="muted">${Number(cve.cvss.nvd.score).toFixed(1)}</span></div>
      <div class="row"><span class="src">CNA</span><code class="vector">${mark(cve.cvss.cna.vector)}</code><span class="muted">${Number(cve.cvss.cna.score).toFixed(1)}</span></div>`;
    const dis = ex.dissent || {};
    const items = METRICS.filter(k => dis[k]).map(k => `<li><b>${k}:</b> ${esc(dis[k])}</li>`);
    if (items.length) html += `<ul>${items.join('')}</ul>`;
    html += `<p class="muted" style="margin:.5rem 0 0">Grundlage der Übung ist der offizielle Vektor (${SRC_DE[cve.cvss.official.source] || cve.cvss.official.source}).</p>`;
    box.innerHTML = html; box.hidden = false;
  }

  // Kontext-Panel: EPSS / KEV / Einordnung.
  function renderContext(cve, ex) {
    $('ctx-summary').textContent = ex.summary_de || '';
    const e = cve.context.epss;
    $('ctx-epss').textContent = (e == null) ? 'k. A.' : (e * 100).toFixed(1) + ' %';
    $('ctx-epss-pct').textContent = (cve.context.epss_percentile == null) ? '' :
      `Perzentil ${(cve.context.epss_percentile * 100).toFixed(0)} – Wahrscheinlichkeit einer Ausnutzung in 30 Tagen`;
    const kev = cve.context.kev, kb = $('ctx-kev-box');
    if (kev) {
      kb.classList.add('kev-yes'); $('ctx-kev').textContent = 'Ja – aktiv ausgenutzt';
      const rw = kev.ransomware && kev.ransomware !== 'Unknown' ? ` · Ransomware: ${kev.ransomware}` : '';
      $('ctx-kev-detail').textContent = `aufgenommen ${kev.date_added}${rw}${kev.required_action ? ' · ' + kev.required_action : ''}`;
    } else {
      kb.classList.remove('kev-yes'); $('ctx-kev').textContent = 'Nein'; $('ctx-kev-detail').textContent = 'nicht im KEV-Katalog';
    }
    $('ctx-text').textContent = ex.context_de || '';
    const refs = $('ctx-refs'); refs.innerHTML = '';
    for (const u of (cve.references || []).slice(0, 6)) {
      const a = document.createElement('a'); a.href = u; a.target = '_blank'; a.rel = 'noopener'; a.textContent = u; refs.appendChild(a);
    }
  }

  // ---------- Fortschritt (Grundlage für Spaced Repetition) ----------
  function logAttempt(cve, correct, allOk) {
    session.tries++; if (allOk) session.perfect++;
    $('session-counter').textContent = `${session.perfect} / ${session.tries} vollständig richtig`;
    try {
      const log = JSON.parse(localStorage.getItem(LOG_KEY) || '[]');
      log.push({ id: cve.id, cls: cve.cwe.learn_class, ts: Date.now(), correct, allOk, traps: cve.traps });
      localStorage.setItem(LOG_KEY, JSON.stringify(log.slice(-2000)));
    } catch (_) { /* localStorage nicht verfügbar – kein Problem */ }
  }

  function esc(s) { return String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }


  // ---------- Filterleiste: Klasse × Stack (nur im Arbeitsspeicher, nichts wird gespeichert) ----------
  const filters = { cvss: { cls: '', stack: '' }, quiz: { cls: '', stack: '' } };
  const FB_ID = { cvss: 'cvss-filter', quiz: 'quiz-filter' };
  // Grundmenge je Ansicht: CVSS inkl. Fallen-Filter, Quiz ohne unklassifizierte CVEs.
  function filterBase(kind) {
    if (kind === 'quiz') return quizPool();
    return state.trapFilter ? state.cves.filter(c => (c.traps || []).includes(state.trapFilter)) : state.cves;
  }
  const fMatch = (c, f) => (!f.cls || c.cwe.learn_class === f.cls) && (!f.stack || c.stack === f.stack);
  // Treffer für Klasse+Stack; ergibt die Kombination nichts, bleibt die Grundmenge (und die Leiste warnt).
  function candidates(kind) {
    const base = filterBase(kind), hit = base.filter(c => fMatch(c, filters[kind]));
    return hit.length ? hit : base;
  }

  function refreshFilterBar(kind) {
    const bar = $(FB_ID[kind]); if (!bar) return;
    const f = filters[kind], base = filterBase(kind);
    const clsSel = bar.querySelector('[data-f=cls]'), stSel = bar.querySelector('[data-f=stack]');
    // Zählungen berücksichtigen jeweils den anderen Filter, damit man sieht, was kombinierbar ist.
    const byStack = base.filter(c => !f.stack || c.stack === f.stack);
    const byCls = base.filter(c => !f.cls || c.cwe.learn_class === f.cls);
    const clsKeys = Object.keys(state.classes).filter(k => k !== 'unclassified')
      .sort((x, y) => state.classes[x].name.localeCompare(state.classes[y].name, 'de'));
    clsSel.innerHTML = `<option value="">Alle Klassen (${byStack.length})</option>` + clsKeys.map(k => {
      const n = byStack.filter(c => c.cwe.learn_class === k).length;
      return `<option value="${k}"${k === f.cls ? ' selected' : ''}${n === 0 && k !== f.cls ? ' disabled' : ''}>${esc(state.classes[k].name)} (${n})</option>`;
    }).join('');
    const stacks = [...new Set(base.map(c => c.stack))]
      .sort((x, y) => base.filter(c => c.stack === y).length - base.filter(c => c.stack === x).length);
    stSel.innerHTML = `<option value="">Alle Stacks (${byCls.length})</option>` + stacks.map(st => {
      const n = byCls.filter(c => c.stack === st).length;
      return `<option value="${st}"${st === f.stack ? ' selected' : ''}${n === 0 && st !== f.stack ? ' disabled' : ''}>${esc(STACK_DE[st] || st)} (${n})</option>`;
    }).join('');
    clsSel.classList.toggle('active', !!f.cls); stSel.classList.toggle('active', !!f.stack);
    const hits = base.filter(c => fMatch(c, f)).length, active = !!(f.cls || f.stack);
    const cnt = bar.querySelector('.fb-count');
    cnt.classList.toggle('warn', active && hits === 0);
    cnt.textContent = !active ? '' : hits ? `${hits} CVE${hits === 1 ? '' : 's'}` : 'keine Treffer – Filter wird ignoriert';
    bar.querySelector('.fb-reset').hidden = !active;
    const hint = bar.querySelector('.fb-hint'); if (hint) hint.hidden = !f.cls;
  }

  // Nach einer Filteränderung: aktuelle CVE behalten, wenn sie passt, sonst die nächste passende zeigen.
  function applyFilter(kind) {
    refreshFilterBar(kind);
    const f = filters[kind];
    if (kind === 'cvss') { if (!state.cur || !fMatch(state.cur, f) || (state.trapFilter && !(state.cur.traps || []).includes(state.trapFilter))) showCVE(pickNext()); }
    else if (!qstate.cur || !fMatch(qstate.cur, f)) showQuiz(qPickNext());
  }

  function initFilterBar(kind) {
    const bar = $(FB_ID[kind]); if (!bar) return;
    const clsSel = bar.querySelector('[data-f=cls]'), stSel = bar.querySelector('[data-f=stack]');
    const onChange = () => { filters[kind].cls = clsSel.value; filters[kind].stack = stSel.value; applyFilter(kind); };
    clsSel.addEventListener('change', onChange); stSel.addEventListener('change', onChange);
    bar.querySelector('.fb-reset').addEventListener('click', () => { filters[kind] = { cls: '', stack: '' }; applyFilter(kind); });
    refreshFilterBar(kind);
  }

  // ---------- Klassen-Quiz ----------
  const QLOG_KEY = 'vt-class-attempts';
  const qstate = { cur: null, seen: new Set(), done: false };
  const qsession = { tries: 0, right: 0 };

  function quizPool() { return state.cves.filter(c => c.cwe.learn_class !== 'unclassified' && c.exercises.class); }
  function qPickNext() {
    const base = candidates('quiz');
    const pool = base.filter(c => !qstate.seen.has(c.id));
    const src = pool.length ? pool : (qstate.seen.clear(), base);
    return srPick(src.length ? src : quizPool(), 'quiz');
  }
  function shuffle(a) { for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; }

  function showQuiz(cve) {
    qstate.cur = cve; qstate.done = false; qstate.seen.add(cve.id);
    $('q-id').textContent = cve.id;
    $('q-published').textContent = cve.published ? cve.published.slice(0, 10) : '';
    $('q-stack').textContent = STACK_DE[cve.stack] || cve.stack;
    $('q-desc').textContent = (cve.description || '').trim();
    $('q-sr').textContent = cve._srReason ? 'SR: ' + cve._srReason : '';
    const ex = cve.exercises.class;
    let keys = $('q-all').checked
      ? Object.keys(state.classes).filter(k => k !== 'unclassified').sort((x, y) => state.classes[x].name.localeCompare(state.classes[y].name, 'de'))
      : shuffle([ex.answer, ...(ex.distractors || [])].filter((k, i, arr) => arr.indexOf(k) === i));
    const host = $('q-opts'); host.innerHTML = '';
    for (const k of keys) {
      const cls = state.classes[k]; if (!cls) continue;
      const b = document.createElement('button'); b.type = 'button'; b.className = 'q-opt'; b.dataset.k = k;
      b.innerHTML = `${esc(cls.name)}<small>${esc((cls.cwes || []).slice(0, 4).join(', '))}${(cls.cwes || []).length > 4 ? ' …' : ''}</small>`;
      b.addEventListener('click', () => answerQuiz(k));
      host.appendChild(b);
    }
    $('q-result').hidden = true; $('q-next').hidden = true;
    window.scrollTo({ top: 0 });
  }

  function answerQuiz(k) {
    if (qstate.done) return;
    qstate.done = true;
    const cve = qstate.cur, ans = cve.exercises.class.answer, ok = k === ans;
    document.querySelectorAll('.q-opt').forEach(b => {
      b.disabled = true;
      if (b.dataset.k === ans) b.classList.add('right');
      else if (b.dataset.k === k) b.classList.add('wrong');
    });
    const cls = state.classes[ans], picked = state.classes[k];
    const conf = (cls.confusable || []).map(c => state.classes[c] ? state.classes[c].name : c);
    const r = $('q-result'); r.className = 'q-result ' + (ok ? 'ok' : 'bad');
    r.innerHTML = `<h3>${ok ? 'Richtig' : 'Falsch'} – ${esc(cls.name)}</h3>
      <p style="margin:0">NVD-CWE: <b>${esc(cve.cwe.id || 'k. A.')}</b>${cve.cwe.all && cve.cwe.all.length > 1 ? ' (weitere: ' + esc(cve.cwe.all.filter(x => x !== cve.cwe.id).join(', ')) + ')' : ''}</p>
      ${ok ? '' : `<p style="margin:.3rem 0 0">Deine Wahl: ${esc(picked ? picked.name : k)}</p>`}
      ${conf.length ? `<p class="conf">Leicht zu verwechseln mit: ${esc(conf.join(' · '))}</p>` : ''}
      ${cve.exercises.cvss && cve.exercises.cvss.summary_de ? `<p class="conf">${esc(cve.exercises.cvss.summary_de)}</p>` : ''}`;
    r.hidden = false; $('q-next').hidden = false;
    qsession.tries++; if (ok) qsession.right++;
    $('session-counter').textContent = `Quiz: ${qsession.right} / ${qsession.tries} richtig`;
    try {
      const log = JSON.parse(localStorage.getItem(QLOG_KEY) || '[]');
      log.push({ id: cve.id, cls: ans, picked: k, ok, ts: Date.now() });
      localStorage.setItem(QLOG_KEY, JSON.stringify(log.slice(-2000)));
    } catch (_) {}
  }



  // ---------- Export / Import des Fortschritts ----------
  // Der Spaced-Repetition-Zustand wird vollständig aus den beiden Protokollen abgeleitet,
  // deshalb genügt es, diese zu sichern. Zusammenführen statt überschreiben:
  // Versuche sind append-only Ereignisse, Dubletten erkennen wir an id + Zeitstempel.
  const QLOG = 'vt-class-attempts';
  const IO_VERSION = 1;
  const LOG_CAP = 2000;

  function readLog(key) {
    try { const v = JSON.parse(localStorage.getItem(key) || '[]'); return Array.isArray(v) ? v : []; }
    catch (_) { return []; }
  }
  function ioMsg(text, kind) {
    const el = $('prog-io'); el.textContent = text;
    el.className = 'prog-io' + (kind ? ' ' + kind : ''); el.hidden = false;
  }

  function exportProgress() {
    const payload = {
      app: 'vuln-trainer', kind: 'progress', version: IO_VERSION,
      exported: new Date().toISOString(),
      corpus: { cves: (state.meta && state.meta.cves) || state.cves.length, generated: (state.meta && state.meta.generated) || null },
      cvss_attempts: readLog(LOG_KEY),
      class_attempts: readLog(QLOG),
    };
    const total = payload.cvss_attempts.length + payload.class_attempts.length;
    if (!total) { ioMsg('Nichts zu exportieren: Das Protokoll ist leer.', 'bad'); return; }
    const blob = new Blob([JSON.stringify(payload, null, 1)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const d = new Date(), pad = (n) => String(n).padStart(2, '0');
    const a = document.createElement('a');
    a.href = url; a.download = `vuln-trainer-fortschritt-${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}.json`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    ioMsg(`${total} Versuche exportiert (${payload.cvss_attempts.length} CVSS, ${payload.class_attempts.length} Quiz).`, 'ok');
  }

  // Vereinigt zwei Versuchslisten ohne Dubletten, sortiert nach Zeit.
  function mergeAttempts(mine, theirs) {
    const key = (a) => `${a && a.id}|${a && a.ts}|${a && a.cls}`;
    const seen = new Set(mine.map(key));
    let added = 0;
    const out = mine.slice();
    for (const a of theirs) {
      if (!a || typeof a !== 'object' || !a.ts) continue;
      const k = key(a);
      if (seen.has(k)) continue;
      seen.add(k); out.push(a); added++;
    }
    out.sort((x, y) => (x.ts || 0) - (y.ts || 0));
    return { list: out.slice(-LOG_CAP), added };
  }

  function importProgress(file) {
    const reader = new FileReader();
    reader.onerror = () => ioMsg('Datei konnte nicht gelesen werden.', 'bad');
    reader.onload = () => {
      let data;
      try { data = JSON.parse(reader.result); }
      catch (_) { ioMsg('Das ist keine gültige JSON-Datei.', 'bad'); return; }
      if (!data || data.app !== 'vuln-trainer' || data.kind !== 'progress') {
        ioMsg('Datei passt nicht: Es fehlt die Kennung einer Vuln-Trainer-Sicherung.', 'bad'); return;
      }
      if (!Array.isArray(data.cvss_attempts) || !Array.isArray(data.class_attempts)) {
        ioMsg('Datei ist unvollständig: Die Versuchslisten fehlen.', 'bad'); return;
      }
      const a = mergeAttempts(readLog(LOG_KEY), data.cvss_attempts);
      const b = mergeAttempts(readLog(QLOG), data.class_attempts);
      try {
        localStorage.setItem(LOG_KEY, JSON.stringify(a.list));
        localStorage.setItem(QLOG, JSON.stringify(b.list));
      } catch (_) { ioMsg('Speichern fehlgeschlagen: localStorage nicht verfügbar oder voll.', 'bad'); return; }
      renderProgress();
      const skipped = (data.cvss_attempts.length + data.class_attempts.length) - (a.added + b.added);
      ioMsg(`${a.added + b.added} neue Versuche übernommen (${a.added} CVSS, ${b.added} Quiz).`
        + (skipped > 0 ? ` ${skipped} waren bereits vorhanden und wurden übersprungen.` : '')
        + ` Bestand jetzt: ${a.list.length} CVSS, ${b.list.length} Quiz.`, 'ok');
    };
    reader.readAsText(file);
  }

  // ---------- Fehlerbilder ----------
  // Jede Falle zielt auf bestimmte Metriken; nur die zählen für die Quote.
  const TRAP_METRICS = {
    scope_c: ['S'], scope_u_high_impact: ['S'],
    c_low: ['C'], c_high_scoped: ['C'],
    pr_n_network_only: ['PR'], pr_n_but_ui_r: ['PR', 'UI'], pr_l_authenticated: ['PR'],
    ac_h: ['AC'],
  };
  const TRAP_NAME = {
    scope_c: 'Scope: Changed', scope_u_high_impact: 'Scope: Unchanged trotz Maximalschaden',
    c_low: 'C:L – begrenzter Umfang', c_high_scoped: 'C:H – voller Zugriff',
    pr_n_network_only: 'PR:N – nur Netzzugang nötig', pr_n_but_ui_r: 'PR:N, aber UI:R',
    pr_l_authenticated: 'PR:L – Konto nötig', ac_h: 'AC:H – Bedingungen außer Kontrolle',
  };
  // Deine vier dokumentierten Fehlerbilder, je aus mehreren Fallen zusammengesetzt.
  const PATTERNS = [
    { key: 'scope', title: 'Scope U vs. C', traps: ['scope_c', 'scope_u_high_impact'],
      expl: 'Scope fragt, ob die Wirkung eine andere Sicherheitszone erreicht. Maximaler Schaden in derselben Komponente ist weiterhin S:U.' },
    { key: 'cval', title: 'C:L vs. C:H', traps: ['c_low', 'c_high_scoped'],
      expl: 'C misst den Umfang der preisgegebenen Information, nicht deren Wert. Ein einzelnes Cookie oder Speicherfragment bleibt C:L, auch wenn es wertvoll ist.' },
    { key: 'pr', title: 'PR:N erkennen', traps: ['pr_n_network_only', 'pr_n_but_ui_r', 'pr_l_authenticated'],
      expl: 'PR bewertet nur, welche Rechte der Angreifer vorher besitzt. Erlangte Admin-Rechte, ein Auth-Bypass oder die Rechte eines getäuschten Opfers sind Wirkung, keine Voraussetzung.' },
    { key: 'ac', title: 'Wahrscheinlichkeit vs. Auswirkung', traps: ['ac_h'],
      expl: 'AC:H senkt die Wahrscheinlichkeit (Race, Sonderkonfiguration, MITM-Position), nicht den Schaden. Impact-Metriken bleiben davon unberührt, so wie Segmentierung die Wahrscheinlichkeit senkt und Offline-Backups die Auswirkung.' },
  ];

  function trapStats() {
    let log = [];
    try { log = JSON.parse(localStorage.getItem(LOG_KEY) || '[]'); } catch (_) {}
    const st = {};
    for (const t of Object.keys(TRAP_METRICS)) st[t] = { seen: 0, hit: 0, of: 0 };
    for (const a of log) {
      if (!a || !a.traps || !a.correct) continue;
      for (const t of a.traps) {
        if (!st[t]) continue;
        st[t].seen++;
        for (const m of TRAP_METRICS[t]) { st[t].of++; if (a.correct[m]) st[t].hit++; }
      }
    }
    return st;
  }
  function corpusTrapCounts() {
    const c = {};
    for (const t of Object.keys(TRAP_METRICS)) c[t] = 0;
    for (const cve of state.cves) for (const t of (cve.traps || [])) if (t in c) c[t]++;
    return c;
  }

  function renderPatterns() {
    const st = trapStats(), counts = corpusTrapCounts(), doc = (state.meta && state.meta.trap_doc) || {};
    const host = $('pat-cards'); host.innerHTML = '';
    for (const p of PATTERNS) {
      const of = p.traps.reduce((s, t) => s + st[t].of, 0);
      const hit = p.traps.reduce((s, t) => s + st[t].hit, 0);
      const seen = p.traps.reduce((s, t) => s + st[t].seen, 0);
      const acc = of ? hit / of : null;
      const div = document.createElement('div');
      div.className = 'pat-card' + (acc === null ? '' : acc < 0.7 ? ' weak' : acc >= 0.9 ? ' good' : '');
      const mets = [...new Set(p.traps.flatMap(t => TRAP_METRICS[t]))].join(', ');
      div.innerHTML = `<h3>${esc(p.title)}</h3>
        <p class="metrics-hit">Metrik ${esc(mets)} · ${seen} mal in deinen Übungen aufgetaucht</p>
        <div class="quote">${acc === null ? '<span class="muted">noch keine Daten</span>'
          : `<span class="bar"><i style="width:${Math.round(acc * 100)}%"></i></span><b>${Math.round(acc * 100)} %</b><span class="muted">richtig gesetzt</span>`}</div>
        <p class="expl">${esc(p.expl)}</p>`;
      host.appendChild(div);
    }
    const tb = $('pat-table').querySelector('tbody'); tb.innerHTML = '';
    const keys = Object.keys(TRAP_METRICS).sort((x, y) => {
      const ax = st[x].of ? st[x].hit / st[x].of : 2, ay = st[y].of ? st[y].hit / st[y].of : 2;
      return ax - ay || counts[y] - counts[x];
    });
    for (const t of keys) {
      const s = st[t], acc = s.of ? s.hit / s.of : null;
      const tr = document.createElement('tr');
      tr.innerHTML = `<td><b>${esc(TRAP_NAME[t])}</b><span class="mini">${esc(doc[t] || '')}</span></td>
        <td>${counts[t]} CVEs<span class="mini">${(100 * counts[t] / state.cves.length).toFixed(1)} %</span></td>
        <td>${s.seen}</td>
        <td>${acc === null ? '<span class="muted">–</span>' : `<span class="bar"><i style="width:${Math.round(acc * 100)}%"></i></span>${Math.round(acc * 100)} %`}</td>
        <td><button class="ghost small" data-trap="${t}">üben</button></td>`;
      tb.appendChild(tr);
    }
    tb.querySelectorAll('button[data-trap]').forEach(b => b.addEventListener('click', () => startTrapDrill(b.dataset.trap)));
    $('pat-note').textContent = st.scope_c.of || st.c_low.of
      ? 'Die Quote zählt nur die Metrik, auf die die Falle zielt – nicht den ganzen Vektor.'
      : 'Sobald du Vektoren abgeglichen hast, erscheinen hier deine Quoten je Falle.';
  }

  // Gefilterte Übung: nur CVEs mit dieser Falle.
  function startTrapDrill(trap) {
    state.trapFilter = trap;
    $('trap-banner-name').textContent = TRAP_NAME[trap] || trap;
    $('trap-banner-n').textContent = `· ${state.cves.filter(c => (c.traps || []).includes(trap)).length} CVEs`;
    $('trap-banner').hidden = false;
    showView('cvss');
    refreshFilterBar('cvss');
    showCVE(pickNext());
  }
  function clearTrapDrill() {
    state.trapFilter = null; $('trap-banner').hidden = true; refreshFilterBar('cvss'); showCVE(pickNext());
  }

  // ---------- Fälligkeit (nur Anzeige) ----------
  function dueText(dueAt, now) {
    const DAY = window.SR.DAY, diff = dueAt - now;
    if (diff <= 0) { const d = Math.floor(-diff / DAY); return d === 0 ? 'heute fällig' : `fällig seit ${d} ${d === 1 ? 'Tag' : 'Tagen'}`; }
    if (diff < DAY) { const h = Math.max(1, Math.ceil(diff / 3600000)); return `fällig in ${h} Std.`; }
    const d = Math.round(diff / DAY); return `fällig in ${d} ${d === 1 ? 'Tag' : 'Tagen'}`;
  }
  function dueDate(ts) {
    return new Date(ts).toLocaleDateString('de-DE', { weekday: 'short', day: '2-digit', month: '2-digit' });
  }

  // ---------- Tabs ----------
  function renderProgress() {
    const stats = srStats(); const tb = $('prog-table').querySelector('tbody'); tb.innerHTML = '';
    const keys = Object.keys(state.classes).filter(k => k !== 'unclassified');
    // Nach Dringlichkeit: am längsten überfällig zuerst (frühestes dueAt), bei Gleichstand
    // die schwächere Quote. Noch nie gesehene Klassen haben kein Datum und stehen am Ende.
    keys.sort((x, y) => {
      const sx = stats[x], sy = stats[y];
      if (!!sx !== !!sy) return sx ? -1 : 1;
      if (sx) return (sx.dueAt - sy.dueAt) || (sx.acc - sy.acc);
      return state.classes[x].name.localeCompare(state.classes[y].name, 'de');
    });
    const now = Date.now();
    const fmt = (ts) => { if (!ts) return '–'; const d = (Date.now() - ts) / window.SR.DAY; return d < 1 ? 'heute' : d < 2 ? 'gestern' : `vor ${Math.floor(d)} Tagen`; };
    const seen = keys.filter(k => stats[k]);
    const due = seen.filter(k => stats[k].due).length;
    $('prog-summary').textContent = seen.length
      ? `${seen.length} von ${keys.length} Klassen geübt · ${due} zur Wiederholung fällig · ${keys.length - seen.length} noch nie gesehen`
      : `Noch keine Versuche protokolliert. Alle ${keys.length} Klassen sind gleich wahrscheinlich.`;
    for (const k of keys) {
      const s = stats[k]; const tr = document.createElement('tr');
      const st = s ? s.status : 'neu';
      tr.innerHTML = `<td><b>${esc(state.classes[k].name)}</b></td>
        <td>${s ? s.n : 0}</td>
        <td>${s ? `<span class="bar"><i style="width:${Math.round(s.acc * 100)}%"></i></span>${Math.round(s.acc * 100)} %` : '–'}</td>
        <td>${s ? s.streak : '–'}</td><td>${fmt(s && s.lastTs)}</td>
        <td class="st-${st}">${st}</td>
        <td class="due ${s && s.dueAt <= now ? 'due-now' : ''}">${s ? `${dueText(s.dueAt, now)}<span class="mini">${dueDate(s.dueAt)}</span>` : '<span class="muted">–</span>'}</td>`;
      tb.appendChild(tr);
    }
  }

  function showView(v) {
    document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.view === v));
    $('exercise').hidden = v !== 'cvss'; $('quiz').hidden = v !== 'class';
    $('progress').hidden = v !== 'progress'; $('patterns').hidden = v !== 'patterns';
    if (v !== 'cvss') { $('result').hidden = true; $('context').hidden = true; }
    if (v === 'cvss') $('session-counter').textContent = `${session.perfect} / ${session.tries} vollständig richtig`;
    if (v === 'class') { if (!qstate.cur) showQuiz(qPickNext()); $('session-counter').textContent = `Quiz: ${qsession.right} / ${qsession.tries} richtig`; }
    if (v === 'progress') { renderProgress(); $('session-counter').textContent = 'Fortschritt'; }
    if (v === 'patterns') { renderPatterns(); $('session-counter').textContent = 'Fehlerbilder'; }
  }

  // ---------- Start ----------
  // ---------- Offline (Service Worker) ----------
  // Erst nach dem Seitenladen registrieren: Die 3-MB-Daten liegen dann schon im
  // HTTP-Cache und werden beim Vorab-Cachen nicht doppelt geladen.
  function registerServiceWorker() {
    if (!('serviceWorker' in navigator) || location.protocol === 'file:') return;
    const go = () => navigator.serviceWorker.register('sw.js')
      .then(() => navigator.serviceWorker.ready)
      .then(() => { const f = $('offline-flag'); if (f) f.hidden = false; })
      .catch((e) => console.warn('Service Worker nicht registriert:', e));
    if (document.readyState === 'complete') go(); else window.addEventListener('load', go, { once: true });
  }

  async function main() {
    registerServiceWorker();
    try { await loadData(); }
    catch (e) { $('loading').textContent = 'Konnte data/*.json nicht laden. Starte im Ordner docs: python3 -m http.server'; console.error(e); return; }
    $('loading').hidden = true;
    renderMetrics();
    $('btn-compare').addEventListener('click', compare);
    $('btn-next').addEventListener('click', () => showCVE(pickNext()));
    $('btn-next-2').addEventListener('click', () => showCVE(pickNext()));
    const jump = () => { const id = $('jump').value.trim().toUpperCase(); const c = state.byId.get(id); if (c) showCVE(c); else alert('CVE nicht im Korpus: ' + id); };
    $('jump-btn').addEventListener('click', jump);
    $('jump').addEventListener('keydown', e => { if (e.key === 'Enter') jump(); });
    document.querySelectorAll('.tab:not(:disabled)').forEach(t => t.addEventListener('click', () => showView(t.dataset.view)));
    $('q-next').addEventListener('click', () => showQuiz(qPickNext()));
    $('prog-export').addEventListener('click', exportProgress);
    $('prog-import').addEventListener('click', () => $('prog-file').click());
    $('prog-file').addEventListener('change', (e) => { const f = e.target.files && e.target.files[0]; if (f) importProgress(f); e.target.value = ''; });
    $('prog-reset').addEventListener('click', () => { if (confirm('Beide Protokolle (CVSS-Übung und Klassen-Quiz) wirklich löschen?')) { try { localStorage.removeItem(LOG_KEY); localStorage.removeItem('vt-class-attempts'); } catch (_) {} renderProgress(); ioMsg('Protokoll gelöscht.', 'ok'); } });
    $('trap-clear').addEventListener('click', clearTrapDrill);
    window.__vt = { filters, candidates, applyFilter, dueText, pickNext, qPickNext, srStats, renderProgress, renderPatterns, trapStats, startTrapDrill, exportProgress, importProgress, mergeAttempts, readLog };
    $('q-all').addEventListener('change', () => { if (qstate.cur) showQuiz(qstate.cur); });
    initFilterBar('cvss'); initFilterBar('quiz');
    showCVE(pickNext());
  }
  main();
})();
