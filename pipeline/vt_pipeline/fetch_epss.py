"""FIRST EPSS – tägliches CSV (gzip) statt tausender API-Aufrufe."""
from __future__ import annotations

import csv
import gzip
import io

from .http import cached_json, get_bytes

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def load_epss(refresh: bool = False) -> dict:
    """Gibt {"model": ..., "date": ..., "items": {cve: [epss, percentile]}} zurück."""
    def fetch():
        raw = get_bytes(EPSS_URL)
        try:
            text = gzip.decompress(raw).decode("utf-8")
        except gzip.BadGzipFile:
            text = raw.decode("utf-8")
        lines = text.splitlines()
        meta = {}
        if lines and lines[0].startswith("#"):
            # Kopfzeile: "#model_version:v2025.03.14,score_date:2026-09-14T00:00:00+0000"
            for part in lines[0].lstrip("#").split(","):
                if ":" in part:
                    k, v = part.split(":", 1)
                    meta[k.strip()] = v.strip()
            lines = lines[1:]
        items = {}
        for row in csv.DictReader(io.StringIO("\n".join(lines))):
            items[row["cve"]] = [float(row["epss"]), float(row["percentile"])]
        return {"model": meta.get("model_version"), "date": meta.get("score_date"), "items": items}
    return cached_json("epss", fetch, max_age_days=0 if refresh else 1)
