"""NVD API 2.0 – KEV-Liste per `hasKev`, Einzel-CVEs per `cveId`.

Rate-Limits laut NVD: 5 Anfragen / 30 s ohne Key, 50 / 30 s mit Key.
Key kommt aus der Umgebungsvariable NVD_API_KEY (oder Datei pipeline/.env).
Jede CVE wird auf die benötigten Felder reduziert und einzeln gecacht.
"""
from __future__ import annotations

import json
import os
import pathlib
import urllib.parse

from .http import CACHE_DIR, RateLimiter, cached_json, get_bytes

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _api_key() -> str | None:
    key = os.environ.get("NVD_API_KEY")
    if key:
        return key.strip()
    env = pathlib.Path(__file__).resolve().parents[1] / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            if line.startswith("NVD_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"')
    return None


def make_limiter() -> RateLimiter:
    return RateLimiter(45, 30.0) if _api_key() else RateLimiter(5, 30.5)


def _headers() -> dict[str, str]:
    key = _api_key()
    return {"apiKey": key} if key else {}


def slim(cve: dict) -> dict:
    """Reduziert einen NVD-CVE-Eintrag auf das, was die Pipeline braucht."""
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
    metrics = []
    for entry in cve.get("metrics", {}).get("cvssMetricV31", []):
        metrics.append({
            "source": entry.get("source"),
            "type": entry.get("type"),          # Primary (NVD) / Secondary (CNA/ADP)
            "vector": entry["cvssData"]["vectorString"],
            "score": entry["cvssData"]["baseScore"],
            "severity": entry["cvssData"].get("baseSeverity") or entry.get("baseSeverity"),
        })
    weaknesses = []
    for w in cve.get("weaknesses", []):
        ids = [d["value"] for d in w.get("description", []) if d["lang"] == "en"]
        weaknesses.append({"source": w.get("source"), "type": w.get("type"), "ids": ids})
    cpes: list[str] = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                c = m.get("criteria")
                if c and c not in cpes:
                    cpes.append(c)
    return {
        "id": cve["id"],
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),
        "source_identifier": cve.get("sourceIdentifier"),
        "description": desc,
        "metrics_v31": metrics,
        "weaknesses": weaknesses,
        "cpes": cpes[:60],
        "references": [r.get("url") for r in cve.get("references", [])][:15],
    }


def _query(params: dict, limiter: RateLimiter) -> dict:
    url = NVD_URL + "?" + urllib.parse.urlencode(params, doseq=True).replace("hasKev=", "hasKev")
    return json.loads(get_bytes(url, headers=_headers(), limiter=limiter, timeout=120))


def fetch_kev_cves(limiter: RateLimiter, refresh: bool = False) -> list[dict]:
    """Alle CVEs mit KEV-Markierung – 2000 pro Seite, also nur 1–2 Anfragen."""
    def fetch():
        out, start = [], 0
        while True:
            print(f"  NVD hasKev startIndex={start}", flush=True)
            data = _query({"hasKev": "", "resultsPerPage": 2000, "startIndex": start}, limiter)
            out.extend(slim(v["cve"]) for v in data["vulnerabilities"])
            start += data["resultsPerPage"]
            if start >= data["totalResults"]:
                break
        return out
    items = cached_json("nvd_haskev", fetch, max_age_days=0 if refresh else 7)
    for it in items:                      # auch einzeln ablegen
        _store_single(it)
    return items


def _single_path(cve_id: str) -> pathlib.Path:
    year = cve_id.split("-")[1]
    return CACHE_DIR / "nvd" / year / f"{cve_id}.json"


def _store_single(item: dict) -> None:
    p = _single_path(item["id"])
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(item, ensure_ascii=False), encoding="utf-8")


def fetch_cve(cve_id: str, limiter: RateLimiter) -> dict | None:
    """Einzelne CVE, gecacht. Gibt None zurück, wenn NVD sie nicht kennt."""
    p = _single_path(cve_id)
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    data = _query({"cveId": cve_id}, limiter)
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("null", encoding="utf-8")
        return None
    item = slim(vulns[0]["cve"])
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(item, ensure_ascii=False), encoding="utf-8")
    return item


def load_cached_cve(cve_id: str) -> dict | None:
    p = _single_path(cve_id)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def all_cached_cves() -> list[dict]:
    out = []
    for p in sorted((CACHE_DIR / "nvd").glob("*/*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        if d:
            out.append(d)
    return out


# --- Severity-gezielter Fetch (MEDIUM/LOW, EPSS-unabhängig) ---------------

_CORR_KEEP = ("/C:L", "/S:C/", "PR:N/UI:R")  # C:L, Scope-Wechsel, PR:N-mit-UI


def _is_corrective(item: dict) -> bool:
    """Leichtgewichtiger String-Filter auf den v3.1-Vektor, ohne select zu importieren."""
    if len(item.get("description", "")) < 120:
        return False
    for m in item.get("metrics_v31", []):
        v = m.get("vector", "")
        if any(tok in v for tok in _CORR_KEEP):
            return True
    return False


def _iso_windows(start_year: int, end_year: int, days: int = 120):
    import datetime as _dt
    cur = _dt.datetime(start_year, 1, 1)
    end = _dt.datetime(end_year, 12, 31, 23, 59, 59)
    while cur <= end:
        nxt = min(cur + _dt.timedelta(days=days), end)
        fmt = "%Y-%m-%dT%H:%M:%S.000"
        yield cur.strftime(fmt), nxt.strftime(fmt)
        cur = nxt + _dt.timedelta(seconds=1)


def fetch_by_cvss(severities: list[str], start_year: int, end_year: int,
                  limiter: RateLimiter, only_corrective: bool = True) -> dict:
    """Paginiert die NVD-Liste nach cvssV3Severity über Datumsfenster (max. 120 Tage),
    unabhängig von EPSS/KEV. Speichert passende CVEs einzeln im Cache.
    Gibt {'seen':N,'kept':N,'new':N} zurück."""
    seen = kept = new = 0
    for sev in severities:
        for pub_start, pub_end in _iso_windows(start_year, end_year):
            start = 0
            while True:
                params = {
                    "cvssV3Severity": sev,
                    "pubStartDate": pub_start,
                    "pubEndDate": pub_end,
                    "resultsPerPage": 2000,
                    "startIndex": start,
                }
                data = _query(params, limiter)
                total = data.get("totalResults", 0)
                vulns = data.get("vulnerabilities", [])
                for v in vulns:
                    seen += 1
                    item = slim(v["cve"])
                    if only_corrective and not _is_corrective(item):
                        continue
                    kept += 1
                    p = _single_path(item["id"])
                    if not p.exists():
                        _store_single(item)
                        new += 1
                per = data.get("resultsPerPage", 2000) or 2000
                start += per
                print(f"  {sev} {pub_start[:10]}..{pub_end[:10]} "
                      f"idx={start}/{total} kept={kept} new={new}", flush=True)
                if start >= total or not vulns:
                    break
    return {"seen": seen, "kept": kept, "new": new}
