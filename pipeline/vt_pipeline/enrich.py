"""Stufe `enrich`: Schema, Arbeitspakete und Validierung der Anreicherung.

Die Anreicherung (Begründung pro Metrik, Kontext, optional Angriffskette) wird
NICHT per API erzeugt. Claude schreibt sie in Claude Code direkt als JSON in
`enrich/done/batch-NNN.json`. Diese Datei definiert nur das Format und prüft es.

Format einer Done-Datei:
{
  "batch": "batch-001",
  "items": {
    "CVE-2021-44228": {
      "vector_basis": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",   # muss dem offiziellen Vektor entsprechen
      "summary_de": "Ein Satz: was ist kaputt und was kann der Angreifer.",
      "metrics": {
        "AV": {"why": "…", "pitfall": "…(optional)"}, "AC": …, "PR": …, "UI": …,
        "S": …, "C": …, "I": …, "A": …
      },
      "context_de": "1–2 Sätze: KEV/EPSS, Wahrscheinlichkeit vs. Auswirkung.",
      "dissent": {"S": "Warum der offizielle Wert fragwürdig ist"},              # optional
      "chain": {                                                                 # optional, kommt zuletzt
        "steps": [{"phase": "precondition", "text": "…"}, {"phase": "trigger", "text": "…"},
                  {"phase": "impact", "text": "…"}, {"phase": "stopper", "text": "…"}],
        "distractors": ["…", "…"]
      }
    }
  }
}
"""
from __future__ import annotations

import json
import pathlib

from . import cvss31

ENRICH_DIR = pathlib.Path(__file__).resolve().parents[1] / "enrich"
TODO_DIR = ENRICH_DIR / "todo"
DONE_DIR = ENRICH_DIR / "done"
PHASES = ("precondition", "trigger", "impact", "stopper")


def load_done() -> tuple[dict[str, dict], list[str]]:
    """Liest alle Done-Dateien. Gibt ({cve: item}, fehlerliste) zurück (nur syntaktisch geprüft)."""
    items: dict[str, dict] = {}
    errors: list[str] = []
    for p in sorted(DONE_DIR.glob("*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            errors.append(f"{p.name}: JSON-Fehler {e}")
            continue
        for cve, item in data.get("items", {}).items():
            if cve in items:
                errors.append(f"{p.name}: {cve} doppelt (bereits in anderer Datei)")
            items[cve] = item
    return items, errors


def validate_item(cve: str, item: dict, official_vector: str) -> list[str]:
    errs: list[str] = []
    if item.get("vector_basis") != official_vector:
        errs.append(f"{cve}: vector_basis {item.get('vector_basis')} ≠ offiziell {official_vector}")
    if not item.get("summary_de", "").strip():
        errs.append(f"{cve}: summary_de fehlt")
    metrics = item.get("metrics", {})
    for m in cvss31.METRICS:
        entry = metrics.get(m)
        if not isinstance(entry, dict) or not entry.get("why", "").strip():
            errs.append(f"{cve}: metrics.{m}.why fehlt")
        elif len(entry["why"]) < 10:
            errs.append(f"{cve}: metrics.{m}.why zu kurz")
    extra = set(metrics) - set(cvss31.METRICS)
    if extra:
        errs.append(f"{cve}: unbekannte Metriken {sorted(extra)}")
    if not item.get("context_de", "").strip():
        errs.append(f"{cve}: context_de fehlt")
    dissent = item.get("dissent")
    if dissent is not None:
        if not isinstance(dissent, dict) or any(k not in cvss31.METRICS for k in dissent):
            errs.append(f"{cve}: dissent muss {{Metrik: Text}} sein")
    chain = item.get("chain")
    if chain is not None:
        steps = chain.get("steps", [])
        phases = [s.get("phase") for s in steps]
        if phases != list(PHASES):
            errs.append(f"{cve}: chain.steps müssen genau die Phasen {PHASES} in dieser Reihenfolge haben")
        if any(not s.get("text", "").strip() for s in steps):
            errs.append(f"{cve}: chain.steps mit leerem Text")
        if not isinstance(chain.get("distractors"), list) or len(chain["distractors"]) < 1:
            errs.append(f"{cve}: chain.distractors fehlt")
    return errs


def validate(corpus: list[dict]) -> tuple[dict[str, dict], list[str]]:
    """Gibt (gültige Anreicherungen nach CVE, Fehler) zurück."""
    items, errors = load_done()
    by_id = {r["id"]: r for r in corpus}
    valid: dict[str, dict] = {}
    for cve, item in items.items():
        rec = by_id.get(cve)
        if not rec:
            errors.append(f"{cve}: nicht im Korpus (bleibt erhalten, wird aber nicht gebaut)")
            continue
        errs = validate_item(cve, item, rec["cvss"]["official"]["vector"])
        if errs:
            errors.extend(errs)
        else:
            valid[cve] = item
    return valid, errors


def todo_packet(rec: dict) -> dict:
    """Kompakte Arbeitsvorlage für eine CVE – so wenig Tokens wie möglich."""
    k = rec["context"]["kev"]
    return {
        "id": rec["id"],
        "desc": rec["description"],
        "vector": rec["cvss"]["official"]["vector"],
        "score": rec["cvss"]["official"]["score"],
        "src": rec["cvss"]["official"]["source"],
        "cna_vector": (rec["cvss"]["cna"] or {}).get("vector") if rec["cvss"]["differs"] else None,
        "differs": rec["cvss"]["differs"],
        "cwe": rec["cwe"]["id"],
        "class": rec["cwe"]["learn_class"],
        "stack": rec["stack"],
        "products": rec["products"][:3],
        "kev": bool(k),
        "ransomware": (k or {}).get("ransomware"),
        "epss": rec["context"]["epss"],
        "traps": rec["traps"],
    }


def _work_order(records: list[dict]) -> list[dict]:
    """Reihenfolge der Arbeitspakete: Klassen im Round-Robin, innerhalb der Klasse zuerst
    CVEs mit Fallen-Markern für die dokumentierten Fehlerbilder und NVD≠CNA-Abweichungen."""
    from collections import defaultdict
    weight = {"c_low": 6, "scope_c": 5, "pr_n_but_ui_r": 4, "c_high_scoped": 3, "pr_l_authenticated": 2, "ac_h": 2}
    by_class: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_class[r["cwe"]["learn_class"]].append(r)
    for lst in by_class.values():
        lst.sort(key=lambda r: (-(sum(weight.get(t, 0) for t in r["traps"]) + 3 * len(r["cvss"]["differs"])
                                  + (2 if r["context"]["kev"] else 0)), r["id"]))
    out: list[dict] = []
    classes = sorted(by_class, key=lambda c: (c == "unclassified", c))
    i = 0
    while any(by_class[c] for c in classes):
        for c in classes:
            if by_class[c]:
                out.append(by_class[c].pop(0))
        i += 1
    return out


def export_todo(corpus: list[dict], batch_size: int = 20, with_chain: bool = False) -> list[pathlib.Path]:
    """Schreibt Arbeitspakete für alle noch nicht (gültig) angereicherten CVEs."""
    valid, _ = validate(corpus)
    missing = _work_order([r for r in corpus if r["id"] not in valid])
    TODO_DIR.mkdir(parents=True, exist_ok=True)
    for old in TODO_DIR.glob("*.json"):
        old.unlink()
    existing = {p.stem for p in DONE_DIR.glob("*.json")}
    n = 1
    paths = []
    for i in range(0, len(missing), batch_size):
        while f"batch-{n:03d}" in existing:
            n += 1
        chunk = missing[i:i + batch_size]
        p = TODO_DIR / f"batch-{n:03d}.json"
        p.write_text(json.dumps({"batch": f"batch-{n:03d}", "with_chain": with_chain,
                                 "items": [todo_packet(r) for r in chunk]}, ensure_ascii=False, indent=0),
                     encoding="utf-8")
        paths.append(p)
        n += 1
    return paths


def status(corpus: list[dict]) -> str:
    valid, errors = validate(corpus)
    chains = sum(1 for v in valid.values() if v.get("chain"))
    lines = [
        f"Korpus: {len(corpus)}",
        f"gültig angereichert: {len(valid)}  (davon mit Angriffskette: {chains})",
        f"offen: {len(corpus) - len(valid)}",
        f"Fehler: {len(errors)}",
    ] + [f"  - {e}" for e in errors[:40]]
    if len(errors) > 40:
        lines.append(f"  … und {len(errors) - 40} weitere")
    return "\n".join(lines)


# --- Kurzformen automatisch ausschreiben -------------------------------------
_TERSE = {
    "C": {"Alles.": "Vollzugriff: alle Daten lesbar.", "root: alles.": "Root-Rechte: alle Daten lesbar.",
          "Admin: alles.": "Admin-Rechte: alle Daten lesbar.", "SYSTEM: alles.": "SYSTEM-Rechte: alle Daten lesbar.",
          "RCE: alles.": "Codeausführung: alle Daten lesbar.", "Befehle: alles.": "Befehlsausführung: alle Daten lesbar."},
    "I": {"Alles.": "Vollzugriff: alle Daten änderbar.", "root: alles.": "Root-Rechte: alles änderbar.",
          "Admin: alles.": "Admin-Rechte: alles änderbar.", "SYSTEM: alles.": "SYSTEM-Rechte: alles änderbar.",
          "RCE: alles.": "Codeausführung: alles änderbar.", "Befehle: alles.": "Befehlsausführung: alles änderbar.",
          "EoP: alles.": "Erhöhte Rechte: alles änderbar.", "Nur Lesen.": "Nur Lesezugriff, keine Änderung."},
    "A": {"Alles.": "Vollzugriff: Dienst oder System abschaltbar.", "root: alles.": "Root-Rechte: System abschaltbar.",
          "Admin: alles.": "Admin-Rechte: Dienst abschaltbar.", "SYSTEM: alles.": "SYSTEM-Rechte: System abschaltbar.",
          "RCE: alles.": "Codeausführung: Dienst abschaltbar.", "Befehle: alles.": "Befehlsausführung: System abschaltbar.",
          "Befehle: abschaltbar.": "Befehlsausführung: Dienst abschaltbar.", "EoP: alles.": "Erhöhte Rechte: System abschaltbar."},
    "AV": {"Lokal.": "Lokaler Zugriff auf das System nötig.", "Web-CMS.": "Web-CMS, Angriff über HTTP.",
           "Webanwendung.": "Webanwendung, Angriff über HTTP.", "Im Netzpfad.": "Angreifer sitzt im Netzpfad (MITM)."},
    "AC": {"Seite laden.": "Seite laden reicht, keine Sonderbedingung.", "Eine URL.": "Eine URL aufrufen, kein Aufwand.",
           "Link genügt.": "Ein präparierter Link genügt.", "Datei lesen.": "Datei lesen, kein Aufwand."},
    "PR": {"Keine Rechte.": "Keine Rechte nötig.", "Lokaler Nutzer.": "Ein lokales Nutzerkonto reicht."},
    "UI": {"Seitenbesuch.": "Das Opfer muss die Seite besuchen."},
    "S": {"Im Browser.": "Bleibt im Browser des Nutzers.", "Im Renderer.": "Bleibt im Renderer-Prozess.",
          "Im Plugin.": "Bleibt im Plugin-Prozess.", "XSS: S:C.": "XSS: Code läuft im Browser des Opfers, Scope Changed."},
}
_GENERIC = {"C": "Vertraulichkeit: ", "I": "Integrität: ", "A": "Verfügbarkeit: ", "AV": "Angriffsvektor: ",
            "AC": "Komplexität: ", "PR": "Rechte: ", "UI": "Interaktion: ", "S": "Scope: "}


def expand_terse(min_len: int = 10) -> list[str]:
    """Schreibt zu knappe `why`-Texte in allen Done-Dateien aus. Gibt Liste generisch erweiterter Einträge zurück."""
    generic: list[str] = []
    for p in sorted(DONE_DIR.glob("*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        changed = False
        for cve, it in d.get("items", {}).items():
            for m, e in it.get("metrics", {}).items():
                w = e.get("why", "").strip()
                if 0 < len(w) < min_len:
                    new = _TERSE.get(m, {}).get(w)
                    if new is None:
                        new = _GENERIC[m] + w
                        generic.append(f"{cve} {m}: {w}")
                    e["why"] = new
                    changed = True
        if changed:
            p.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
    return generic
