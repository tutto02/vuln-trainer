"""Stufe `select`: Aus dem NVD-Cache einen ausgewogenen Übungskorpus bilden.

Prinzipien
- Ground Truth ist immer ein CVSS-3.1-Vektor. Provenienz (NVD oder CNA) wird gespeichert,
  Abweichungen zwischen beiden werden metrikweise festgehalten.
- Priorität: KEV > hoher EPSS > passende Fallen-Marker > NVD-Provenienz.
- Balance: Round-Robin über Lernklassen, Deckel pro Stack (Windows), pro Vendor,
  für 'unclassified' und für CVEs ab 2024.
- Stabilität: Bereits angereicherte CVEs bleiben immer im Korpus.
"""
from __future__ import annotations

import json
import pathlib
import random
import re
from collections import Counter, defaultdict

from . import classify, cvss31, fetch_nvd

OUT_DIR = pathlib.Path(__file__).resolve().parents[1] / "out"

USER_TRAPS = {"scope_c", "scope_u_high_impact", "c_low", "c_high_scoped", "pr_n_network_only", "pr_n_but_ui_r"}

NVD_SOURCE = "nvd@nist.gov"


def _pick_vectors(metrics: list[dict]) -> tuple[dict | None, dict | None]:
    """Gibt (nvd_eintrag, cna_eintrag) zurück. Andere ADP-Quellen zählen als CNA-Seite."""
    nvd = next((m for m in metrics if m["source"] == NVD_SOURCE), None)
    cna = next((m for m in metrics if m["source"] != NVD_SOURCE), None)
    return nvd, cna


_MS_TEMPLATE = re.compile(r"allows? an (un)?authori[sz]ed attacker to .{0,60}(over a network|locally|over an adjacent network)\.?\s*$")
_VAGUE = ("unspecified vectors", "unknown vectors", "Unspecified vulnerability", "** REJECT **",
          "handles objects in memory", "scripting engine handles objects")


def usable_description(desc: str) -> bool:
    """Filtert Beschreibungen, aus denen sich kein Vektor ableiten lässt: Einzeiler-Titel,
    Microsofts Schablonensätze, 'unspecified vectors' aus der Frühzeit der NVD."""
    d = desc.strip()
    if len(d) < 120:
        return False
    if any(v in d for v in _VAGUE):
        return False
    if len(d) < 200 and _MS_TEMPLATE.search(d):
        return False
    return True


def build_record(raw: dict, kev: dict, epss: dict, force: bool = False) -> dict | None:
    if not raw or raw.get("status") == "Rejected":
        return None
    if not force and not usable_description(raw.get("description", "")):
        return None
    nvd, cna = _pick_vectors(raw.get("metrics_v31", []))
    official = nvd or cna
    if not official:
        return None
    try:
        parsed = cvss31.parse_vector(official["vector"])
    except ValueError:
        return None
    computed = cvss31.base_score(parsed)
    differs = cvss31.diff_vectors(nvd["vector"], cna["vector"]) if (nvd and cna) else []
    cwe, cwe_src, all_cwes = classify.primary_cwe(raw.get("weaknesses", []))
    lclass = classify.learn_class(cwe) or ("unclassified" if not cwe else "unclassified")
    stack, vendor = classify.stack_for(raw.get("cpes", []), raw.get("description", ""))
    products = []
    for c in raw.get("cpes", [])[:20]:
        _, v, p = classify._vendor_product(c)
        if p and f"{v}:{p}" not in products:
            products.append(f"{v}:{p}")
    ep = epss.get(raw["id"])
    k = kev.get(raw["id"])
    return {
        "id": raw["id"],
        "published": (raw.get("published") or "")[:10],
        "description": raw["description"],
        "stack": stack,
        "vendor": vendor,
        "products": products[:6],
        "cwe": {"id": cwe, "source": cwe_src, "all": all_cwes, "learn_class": lclass},
        "cvss": {
            "official": {
                "vector": cvss31.format_vector(parsed),
                "score": official["score"],
                "computed_score": computed,
                "severity": cvss31.severity(official["score"]),
                "source": "nvd" if official is nvd else "cna",
                "source_id": official["source"],
            },
            "nvd": {"vector": nvd["vector"], "score": nvd["score"]} if nvd else None,
            "cna": {"vector": cna["vector"], "score": cna["score"], "source_id": cna["source"]} if cna else None,
            "differs": differs,
        },
        "context": {
            "epss": ep[0] if ep else None,
            "epss_percentile": ep[1] if ep else None,
            "kev": k,
        },
        "traps": classify.traps_for(official["vector"]),
        "references": raw.get("references", [])[:5],
    }


def priority(rec: dict) -> float:
    """Reihenfolge innerhalb einer Lernklasse. KEV zählt, aber nicht mehr alles:
    Medium-Scores und C:L-Fälle bekommen eigenes Gewicht, damit die dokumentierten
    Fehlerbilder (C:L vs. C:H, Scope) genug Material haben."""
    p = 0.0
    if rec["context"]["kev"]:
        p += 30                                   # vorher 100
    if rec["context"]["epss"]:
        p += 40 * rec["context"]["epss"]
    traps = set(rec["traps"])
    p += 5 * len(USER_TRAPS & traps)
    if "c_low" in traps:
        p += 15
    if "scope_c" in traps:
        p += 6
    sev = rec["cvss"]["official"]["severity"]
    if sev == "MEDIUM":
        p += 20
    elif sev == "LOW":
        p += 12
    if rec["cvss"]["official"]["source"] == "nvd":
        p += 10
    if rec["cvss"]["differs"]:
        p += 8
    if rec["cwe"]["learn_class"] == "unclassified":
        p -= 30
    return p


def corrective_priority(rec: dict) -> float:
    """Priorität für den Rebalancing-Modus: bevorzugt gezielt die unterrepräsentierten
    Fallen-Marker (C:L, eingeschränkter Scope, Scope-Wechsel, Medium/Low) und
    bestraft die überrepräsentierten (KEV, PR:N-nur-Netz)."""
    traps = set(rec["traps"])
    sev = rec["cvss"]["official"]["severity"]
    p = 0.0
    if "c_low" in traps:
        p += 45
    if "c_high_scoped" in traps:
        p += 20
    if "scope_c" in traps:
        p += 25
    if sev == "MEDIUM":
        p += 35
    elif sev == "LOW":
        p += 25
    if rec["context"]["epss"]:
        p += 10 * rec["context"]["epss"]
    if rec["cvss"]["official"]["source"] == "nvd":
        p += 5
    if rec["cvss"]["differs"]:
        p += 6
    if rec["context"]["kev"]:
        p -= 25
    if "pr_n_network_only" in traps:
        p -= 30
    if rec["cwe"]["learn_class"] == "unclassified":
        p -= 40
    return p


def select_corpus(records: list[dict], target: int, pinned: set[str], seed: int = 7,
                  max_windows_share: float = 0.15, max_vendor_share: float = 0.05,
                  max_unclassified_share: float = 0.05, max_recent_share: float = 0.15,
                  rebalance: bool = False, max_pr_n_only_share: float = 0.42,
                  max_kev_share: float = 0.60) -> list[dict]:
    rng = random.Random(seed)
    by_class: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_class[r["cwe"]["learn_class"]].append(r)
    _prio = corrective_priority if rebalance else priority
    for lst in by_class.values():
        lst.sort(key=lambda r: (-_prio(r), r["id"]))

    chosen: dict[str, dict] = {}
    stack_count: Counter = Counter()
    vendor_count: Counter = Counter()
    recent = 0
    uncl = 0

    marker = Counter()

    def accept(r: dict, force: bool = False) -> bool:
        nonlocal recent, uncl
        if r["id"] in chosen:
            return False
        is_recent = r["published"][:4] >= "2024"
        is_uncl = r["cwe"]["learn_class"] == "unclassified"
        traps = set(r["traps"])
        if not force:
            n = max(len(chosen), 1)
            if r["stack"] == "windows" and stack_count["windows"] + 1 > max_windows_share * max(n, target):
                return False
            if r["vendor"] and vendor_count[r["vendor"]] + 1 > max_vendor_share * max(n, target):
                return False
            if is_recent and recent + 1 > max_recent_share * target:
                return False
            if is_uncl and uncl + 1 > max_unclassified_share * target:
                return False
            if rebalance:
                if "pr_n_network_only" in traps and marker["pr_n_only"] + 1 > max_pr_n_only_share * target:
                    return False
                if r["context"]["kev"] and marker["kev"] + 1 > max_kev_share * target:
                    return False
        chosen[r["id"]] = r
        stack_count[r["stack"]] += 1
        if r["vendor"]:
            vendor_count[r["vendor"]] += 1
        recent += is_recent
        uncl += is_uncl
        if "pr_n_network_only" in traps:
            marker["pr_n_only"] += 1
        if r["context"]["kev"]:
            marker["kev"] += 1
        return True

    # 1) Gepinnte (bereits angereicherte) CVEs immer behalten
    for r in records:
        if r["id"] in pinned:
            accept(r, force=True)

    # 2) Round-Robin über Klassen, Reihenfolge der Klassen pro Runde gemischt
    classes = [c for c in by_class if c != "unclassified"]
    cursors = {c: 0 for c in by_class}
    while len(chosen) < target:
        progressed = False
        order = classes + ["unclassified"]
        rng.shuffle(order)
        for c in order:
            lst = by_class[c]
            while cursors[c] < len(lst):
                r = lst[cursors[c]]
                cursors[c] += 1
                if accept(r):
                    progressed = True
                    break
            if len(chosen) >= target:
                break
        if not progressed:
            break
    return sorted(chosen.values(), key=lambda r: r["id"])


def write_report(corpus: list[dict], pool_size: int, path: pathlib.Path) -> str:
    lines = [f"# Korpus-Bericht", "", f"Pool: {pool_size} Kandidaten mit CVSS-3.1-Vektor, gewählt: {len(corpus)}", ""]

    def table(title: str, counter: Counter):
        lines.append(f"## {title}")
        lines.append("")
        lines.append("| Wert | Anzahl | Anteil |")
        lines.append("|---|---:|---:|")
        for k, v in counter.most_common():
            lines.append(f"| {k} | {v} | {100 * v / max(len(corpus), 1):.1f}% |")
        lines.append("")

    table("Lernklassen", Counter(r["cwe"]["learn_class"] for r in corpus))
    table("Stacks", Counter(r["stack"] for r in corpus))
    table("Top-Vendors", Counter(r["vendor"] or "?" for r in corpus))
    table("Vektor-Provenienz", Counter(r["cvss"]["official"]["source"] for r in corpus))
    table("NVD ≠ CNA (Metriken)", Counter(m for r in corpus for m in r["cvss"]["differs"]))
    table("Jahr", Counter(r["published"][:4] for r in corpus))
    table("Fallen-Marker", Counter(t for r in corpus for t in r["traps"]))
    table("Severity", Counter(r["cvss"]["official"]["severity"] for r in corpus))
    kev_n = sum(1 for r in corpus if r["context"]["kev"])
    lines.append(f"KEV-Anteil: {kev_n} ({100 * kev_n / max(len(corpus), 1):.1f}%)")
    mism = [r["id"] for r in corpus if abs(r["cvss"]["official"]["computed_score"] - r["cvss"]["official"]["score"]) > 0.05]
    lines.append(f"Score-Abweichung Rechner vs. offiziell: {len(mism)} {mism[:10]}")
    text = "\n".join(lines) + "\n"
    path.write_text(text, encoding="utf-8")
    return text


def run_select(kev: dict, epss: dict, target: int, pinned: set[str], seed: int = 7, rebalance: bool = False) -> list[dict]:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    raws = fetch_nvd.all_cached_cves()
    excluded = {k for k in json.loads((classify.DATA_DIR / "exclude.json").read_text(encoding="utf-8")) if k.startswith("CVE-")}
    # Bereits angereicherte CVEs (pinned) umgehen den Beschreibungsfilter: dort wurde von Hand geprüft.
    records = [r for r in (build_record(raw, kev, epss, force=raw["id"] in pinned)
                           for raw in raws if raw["id"] not in excluded) if r]
    corpus = select_corpus(records, target, pinned, seed=seed, rebalance=rebalance)
    (OUT_DIR / "corpus.json").write_text(json.dumps(corpus, ensure_ascii=False, indent=1), encoding="utf-8")
    (OUT_DIR / "pool.json").write_text(json.dumps([r["id"] for r in records]), encoding="utf-8")
    report = write_report(corpus, len(records), OUT_DIR / "report.md")
    print(report)
    return corpus
