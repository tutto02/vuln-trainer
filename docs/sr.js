/* Spaced Repetition auf Lernklassen-Ebene – reine Logik, keine DOM-Zugriffe.
   Eingabe: Versuche [{cls, ok, ts}] aus beiden Logs (CVSS-Übung: ok = alle 8 Metriken richtig;
   Klassen-Quiz: ok = richtige Klasse). Ausgabe: Statistik + Gewicht je Klasse.

   Gewichtung (transparent, in der Fortschrittsansicht erklärt):
   - nie gesehen:        weight = 3            (mittelhoch, damit jede Klasse drankommt)
   - gesehen:  acc       = Trefferquote der letzten 10 Versuche
               errWeight = 1 + 4·(1 − acc)   → 1 (alles richtig) … 5 (alles falsch)
               streak    = Serie richtiger Antworten am Ende
               interval  = 1 Tag · 2^min(streak,5)   (1d, 2d, 4d, 8d, 16d, 32d)
               overdue   = (jetzt − zuletzt) / interval, begrenzt auf 0.2 … 2
               weight    = errWeight · overdue
   - „fällig“ = overdue ≥ 1 oder acc < 0.7
   - dueAt   = lastTs + interval, bei acc < 0.7 = lastTs (sofort wieder fällig) */
(function (global) {
  'use strict';
  const DAY = 86400000;
  const WINDOW = 10;

  function computeStats(attempts, now) {
    now = now || Date.now();
    const by = {};
    for (const a of attempts) {
      if (!a || !a.cls) continue;
      (by[a.cls] = by[a.cls] || []).push(a);
    }
    const stats = {};
    for (const cls of Object.keys(by)) {
      const list = by[cls].slice().sort((x, y) => (x.ts || 0) - (y.ts || 0));
      const recent = list.slice(-WINDOW);
      const okN = recent.filter(a => a.ok).length;
      const acc = recent.length ? okN / recent.length : 0;
      let streak = 0;
      for (let i = list.length - 1; i >= 0 && list[i].ok; i--) streak++;
      const lastTs = list[list.length - 1].ts || 0;
      const interval = DAY * Math.pow(2, Math.min(streak, 5));
      const overdueRaw = lastTs ? (now - lastTs) / interval : 2;
      const overdue = Math.min(2, Math.max(0.2, overdueRaw));
      const errWeight = 1 + 4 * (1 - acc);
      // Nächste Fälligkeit: letzter Versuch + Intervall; bei schwacher Quote (< 70 %)
      // sofort nach dem letzten Versuch. Nur berechnet, nie gespeichert.
      const dueAt = lastTs ? (acc < 0.7 ? lastTs : lastTs + interval) : now;
      stats[cls] = {
        n: list.length, ok: list.filter(a => a.ok).length, acc, streak, lastTs, dueAt,
        interval, overdue: overdueRaw, weight: errWeight * overdue,
        due: overdueRaw >= 1 || acc < 0.7,
        status: acc < 0.7 ? 'fällig' : (overdueRaw >= 1 ? 'wiederholen' : 'gefestigt'),
      };
    }
    return stats;
  }

  function weightFor(cls, stats) {
    if (cls === 'unclassified') return 0.5;
    const s = stats[cls];
    return s ? s.weight : 3;
  }

  // Gewichtete Zufallswahl einer Klasse aus `candidates`; die zuletzt gezeigte Klasse wird halbiert.
  function pickClass(stats, candidates, lastCls, rnd) {
    rnd = rnd || Math.random;
    const ws = candidates.map(c => weightFor(c, stats) * (c === lastCls && candidates.length > 1 ? 0.5 : 1));
    const total = ws.reduce((a, b) => a + b, 0);
    if (!total) return candidates[Math.floor(rnd() * candidates.length)] || null;
    let r = rnd() * total;
    for (let i = 0; i < candidates.length; i++) { r -= ws[i]; if (r <= 0) return candidates[i]; }
    return candidates[candidates.length - 1];
  }

  function reasonFor(cls, stats) {
    const s = stats[cls];
    if (!s) return 'neu';
    if (s.acc < 0.7) return `fällig · ${Math.round(s.acc * 100)} % zuletzt`;
    if (s.overdue >= 1) return 'wiederholen';
    return 'Routine';
  }

  global.SR = { computeStats, weightFor, pickClass, reasonFor, DAY };
})(window);
