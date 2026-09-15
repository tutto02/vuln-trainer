/* CVSS v3.1 Basis-Score-Rechner – 1:1-Port von pipeline/vt_pipeline/cvss31.py
   (FIRST-Spezifikation Abschnitt 7, Roundup nach Appendix A).
   Muss dieselben Ergebnisse liefern wie computed_score in cves.json. */
(function (global) {
  'use strict';

  const METRICS = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
  const ALLOWED = {
    AV: ['N', 'A', 'L', 'P'], AC: ['L', 'H'], PR: ['N', 'L', 'H'], UI: ['N', 'R'],
    S: ['U', 'C'], C: ['N', 'L', 'H'], I: ['N', 'L', 'H'], A: ['N', 'L', 'H'],
  };
  const W_AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const W_AC = { L: 0.77, H: 0.44 };
  const W_PR_U = { N: 0.85, L: 0.62, H: 0.27 };
  const W_PR_C = { N: 0.85, L: 0.68, H: 0.5 };
  const W_UI = { N: 0.85, R: 0.62 };
  const W_CIA = { H: 0.56, L: 0.22, N: 0.0 };

  function parseVector(vector) {
    const m = /^CVSS:3\.[01]\/(.+)$/.exec(String(vector).trim());
    if (!m) throw new Error('Kein CVSS-3.x-Vektor: ' + vector);
    const parts = {};
    for (const token of m[1].split('/')) {
      const i = token.indexOf(':');
      if (i < 0) throw new Error('Ungültiges Token ' + token);
      const key = token.slice(0, i), val = token.slice(i + 1);
      if (ALLOWED[key]) {
        if (!ALLOWED[key].includes(val)) throw new Error('Ungültiger Wert ' + key + ':' + val);
        parts[key] = val;
      }
    }
    const missing = METRICS.filter(k => !(k in parts));
    if (missing.length) throw new Error('Fehlende Metriken ' + missing.join(','));
    const out = {};
    for (const k of METRICS) out[k] = parts[k];
    return out;
  }

  function formatVector(metrics) {
    return 'CVSS:3.1/' + METRICS.map(k => k + ':' + metrics[k]).join('/');
  }

  // Roundup nach Appendix A – vermeidet Float-Artefakte.
  function roundup(x) {
    const intInput = Math.round(x * 100000);
    if (intInput % 10000 === 0) return intInput / 100000.0;
    return (Math.floor(intInput / 10000) + 1) / 10.0;
  }

  function baseScore(m) {
    const sChanged = m.S === 'C';
    const iss = 1 - (1 - W_CIA[m.C]) * (1 - W_CIA[m.I]) * (1 - W_CIA[m.A]);
    const impact = sChanged
      ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
      : 6.42 * iss;
    const prW = (sChanged ? W_PR_C : W_PR_U)[m.PR];
    const exploitability = 8.22 * W_AV[m.AV] * W_AC[m.AC] * prW * W_UI[m.UI];
    if (impact <= 0) return 0.0;
    if (sChanged) return roundup(Math.min(1.08 * (impact + exploitability), 10));
    return roundup(Math.min(impact + exploitability, 10));
  }

  function severity(score) {
    if (score === 0) return 'NONE';
    if (score < 4.0) return 'LOW';
    if (score < 7.0) return 'MEDIUM';
    if (score < 9.0) return 'HIGH';
    return 'CRITICAL';
  }

  function diffVectors(a, b) {
    const pa = parseVector(a), pb = parseVector(b);
    return METRICS.filter(k => pa[k] !== pb[k]);
  }

  global.CVSS31 = { METRICS, ALLOWED, parseVector, formatVector, roundup, baseScore, severity, diffVectors };
})(window);
