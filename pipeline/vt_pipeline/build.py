"""Stufe `build`: Korpus + Anreicherung → statische JSON-Dateien für die Web-App."""
from __future__ import annotations

import datetime as dt
import json
import pathlib
import random

from . import classify, enrich

WEB_DATA = pathlib.Path(__file__).resolve().parents[2] / "docs" / "data"


def class_distractors(lclass: str, rng: random.Random, n: int = 3) -> list[str]:
    conf = [c for c in classify.CLASSES.get(lclass, {}).get("confusable", []) if c in classify.CLASSES]
    out = conf[:n]
    others = [c for c in classify.CLASSES if c not in out and c not in (lclass, "unclassified")]
    rng.shuffle(others)
    while len(out) < n and others:
        out.append(others.pop())
    return out


def build(corpus: list[dict], kev_meta: dict, epss_meta: dict) -> dict:
    valid, errors = enrich.validate(corpus)
    WEB_DATA.mkdir(parents=True, exist_ok=True)
    cves = []
    for r in corpus:
        rng = random.Random(r["id"])
        e = valid.get(r["id"])
        item = {
            **{k: r[k] for k in ("id", "published", "description", "stack", "vendor", "products", "cwe", "cvss", "context", "traps", "references")},
            "enriched": bool(e),
            "exercises": {
                "cvss": {"metrics": e["metrics"], "summary_de": e["summary_de"], "context_de": e["context_de"],
                         "dissent": e.get("dissent")} if e else None,
                "class": {"answer": r["cwe"]["learn_class"],
                          "distractors": class_distractors(r["cwe"]["learn_class"], rng)}
                         if r["cwe"]["learn_class"] != "unclassified" else None,
                "chain": e.get("chain") if e else None,
            },
        }
        cves.append(item)
    (WEB_DATA / "cves.json").write_text(json.dumps(cves, ensure_ascii=False), encoding="utf-8")
    classes = {cid: {"name": c["name"], "cwes": c["cwes"], "confusable": c["confusable"],
                     "count": sum(1 for x in cves if x["cwe"]["learn_class"] == cid)}
               for cid, c in classify.CLASSES.items()}
    (WEB_DATA / "classes.json").write_text(json.dumps(classes, ensure_ascii=False, indent=1), encoding="utf-8")
    meta = {
        "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "cves": len(cves),
        "enriched": len(valid),
        "with_chain": sum(1 for x in cves if x["exercises"]["chain"]),
        "kev_catalog_version": kev_meta.get("catalog_version"),
        "kev_date": kev_meta.get("date_released"),
        "epss_model": epss_meta.get("model"),
        "epss_date": epss_meta.get("date"),
        "validation_errors": len(errors),
        "trap_doc": json.loads((classify.DATA_DIR / "classes.json").read_text(encoding="utf-8"))["trap_doc"],
    }
    (WEB_DATA / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1), encoding="utf-8")
    return meta
