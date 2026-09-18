"""Kommandozeile: python -m vt_pipeline <stufe> [optionen]"""
from __future__ import annotations

import argparse
import json
import sys

from . import build as build_mod
from . import enrich, fetch_epss, fetch_kev, fetch_nvd, select


def _load_corpus() -> list[dict]:
    p = select.OUT_DIR / "corpus.json"
    if not p.exists():
        sys.exit("Kein Korpus – erst `select` ausführen.")
    return json.loads(p.read_text(encoding="utf-8"))


def cmd_fetch(args: argparse.Namespace) -> None:
    kev = fetch_kev.load_kev(refresh=args.refresh)
    print(f"KEV: {len(kev['items'])} Einträge (Katalog {kev['catalog_version']})")
    epss = fetch_epss.load_epss(refresh=args.refresh)
    print(f"EPSS: {len(epss['items'])} Einträge (Modell {epss['model']}, Stand {epss['date']})")
    limiter = fetch_nvd.make_limiter()
    print("NVD-Key:", "ja" if fetch_nvd._api_key() else "nein (5 Anfragen / 30 s)")
    kev_cves = fetch_nvd.fetch_kev_cves(limiter, refresh=args.refresh)
    print(f"NVD hasKev: {len(kev_cves)} CVEs")
    # Ergänzung: Top-EPSS-CVEs (nicht in KEV), Jahr <= max_year
    ranked = sorted(epss["items"].items(), key=lambda kv: -kv[1][0])
    todo = []
    for cve, (score, _pct) in ranked:
        if len(todo) >= args.epss_top:
            break
        year = int(cve.split("-")[1])
        if cve in kev["items"] or year > args.max_year or year < args.min_year:
            continue
        if score < args.epss_min:
            break
        if fetch_nvd.load_cached_cve(cve) is None and not fetch_nvd._single_path(cve).exists():
            todo.append(cve)
    print(f"NVD Einzelabrufe nötig: {len(todo)} (Top-EPSS {args.epss_top}, Jahre {args.min_year}–{args.max_year})")
    for i, cve in enumerate(todo, 1):
        fetch_nvd.fetch_cve(cve, limiter)
        if i % 25 == 0 or i == len(todo):
            print(f"  {i}/{len(todo)} {cve}", flush=True)
    print("fetch fertig.")


def cmd_fetch_cvss(args: argparse.Namespace) -> None:
    limiter = fetch_nvd.make_limiter()
    print("NVD-Key:", "ja" if fetch_nvd._api_key() else "nein (5 Anfragen / 30 s)")
    sev = [x.strip().upper() for x in args.severity.split(",") if x.strip()]
    print(f"Severity-Fetch {sev}, Jahre {args.min_year}-{args.max_year}, "
          f"nur Korrektiv={not args.all}")
    res = fetch_nvd.fetch_by_cvss(sev, args.min_year, args.max_year, limiter,
                                  only_corrective=not args.all)
    print(f"fetch-cvss fertig: gesehen={res['seen']} behalten={res['kept']} neu={res['new']}")


def cmd_select(args: argparse.Namespace) -> None:
    kev = fetch_kev.load_kev()["items"]
    epss = fetch_epss.load_epss()["items"]
    pinned = set(enrich.load_done()[0].keys())
    corpus = select.run_select(kev, epss, args.target, pinned, seed=args.seed, rebalance=args.rebalance)
    print(f"Korpus: {len(corpus)} CVEs → out/corpus.json, Bericht in out/report.md")


def cmd_enrich_export(args: argparse.Namespace) -> None:
    paths = enrich.export_todo(_load_corpus(), batch_size=args.batch_size, with_chain=args.with_chain)
    print(f"{len(paths)} Arbeitspakete in enrich/todo/ (je {args.batch_size})")


def cmd_enrich_fix(_: argparse.Namespace) -> None:
    generic = enrich.expand_terse()
    print(f"generisch erweitert ({len(generic)}):", *generic, sep="\n  ")


def cmd_status(_: argparse.Namespace) -> None:
    print(enrich.status(_load_corpus()))


def cmd_refresh_context(args: argparse.Namespace) -> None:
    """EPSS und KEV frisch laden und NUR die context-Felder der bestehenden Korpus-CVEs
    aktualisieren. Keine neuen CVEs, keine Auswahl, keine Vektoren, keine Anreicherung.
    Danach `build` ausführen."""
    corpus = _load_corpus()
    kev = fetch_kev.load_kev(refresh=True)
    epss = fetch_epss.load_epss(refresh=True)
    print(f"KEV-Katalog {kev['catalog_version']} ({len(kev['items'])} Einträge), "
          f"EPSS-Modell {epss['model']} vom {epss['date']}")
    changes = []
    for r in corpus:
        old = dict(r["context"])
        ep = epss["items"].get(r["id"])
        # identisch zu select.build_record
        r["context"] = {"epss": ep[0] if ep else None,
                        "epss_percentile": ep[1] if ep else None,
                        "kev": kev["items"].get(r["id"])}
        changes.append((r["id"], old, r["context"]))
    (select.OUT_DIR / "corpus.json").write_text(json.dumps(corpus, ensure_ascii=False, indent=1), encoding="utf-8")
    report = select.OUT_DIR / "context-refresh.json"
    report.write_text(json.dumps([{"id": i, "old": o, "new": n} for i, o, n in changes], ensure_ascii=False), encoding="utf-8")
    print(f"{len(corpus)} CVEs aktualisiert → out/corpus.json, Vorher/Nachher in {report.name}. Jetzt `build`.")


def cmd_build(_: argparse.Namespace) -> None:
    meta = build_mod.build(_load_corpus(), fetch_kev.load_kev(), fetch_epss.load_epss())
    print(json.dumps({k: v for k, v in meta.items() if k != "trap_doc"}, indent=1, ensure_ascii=False))


def main() -> None:
    ap = argparse.ArgumentParser(prog="vt_pipeline")
    sub = ap.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fetch", help="KEV, EPSS und NVD laden (mit Cache)")
    f.add_argument("--refresh", action="store_true", help="KEV/EPSS/hasKev neu laden")
    f.add_argument("--epss-top", type=int, default=2500, help="zusätzliche Top-EPSS-CVEs einzeln laden")
    f.add_argument("--epss-min", type=float, default=0.05)
    f.add_argument("--min-year", type=int, default=2014)
    f.add_argument("--max-year", type=int, default=2023)
    f.set_defaults(func=cmd_fetch)

    s = sub.add_parser("select", help="Korpus auswählen und Bericht schreiben")
    s.add_argument("--target", type=int, default=900)
    s.add_argument("--seed", type=int, default=7)
    s.add_argument("--rebalance", action="store_true", help="Korrektiv-Auswahl: C:L / Scope / Medium / non-KEV bevorzugen")
    s.set_defaults(func=cmd_select)

    fc = sub.add_parser("fetch-cvss", help="NVD nach cvssV3Severity (MEDIUM/LOW) laden, EPSS-unabhängig")
    fc.add_argument("--severity", default="MEDIUM,LOW", help="Kommaliste, z.B. MEDIUM,LOW")
    fc.add_argument("--min-year", type=int, default=2016)
    fc.add_argument("--max-year", type=int, default=2023)
    fc.add_argument("--all", action="store_true", help="alle behalten statt nur Korrektiv-Kandidaten")
    fc.set_defaults(func=cmd_fetch_cvss)

    e = sub.add_parser("enrich-export", help="Arbeitspakete für fehlende Anreicherung schreiben")
    e.add_argument("--batch-size", type=int, default=20)
    e.add_argument("--with-chain", action="store_true")
    e.set_defaults(func=cmd_enrich_export)

    sub.add_parser("enrich-fix", help="zu knappe Begründungen ausschreiben").set_defaults(func=cmd_enrich_fix)
    sub.add_parser("status", help="Anreicherung validieren und Fortschritt zeigen").set_defaults(func=cmd_status)
    sub.add_parser("refresh-context", help="EPSS/KEV neu laden, nur context der Korpus-CVEs aktualisieren").set_defaults(func=cmd_refresh_context)
    sub.add_parser("build", help="docs/data/*.json erzeugen").set_defaults(func=cmd_build)

    args = ap.parse_args()
    args.func(args)
