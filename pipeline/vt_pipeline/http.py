"""HTTP-Zugriff mit Disk-Cache, Rate-Limiter und Retry. Nur Standardbibliothek."""
from __future__ import annotations

import gzip
import json
import os
import pathlib
import time
import urllib.error
import urllib.request

CACHE_DIR = pathlib.Path(os.environ.get("VT_CACHE_DIR", pathlib.Path(__file__).resolve().parents[1] / "cache"))
USER_AGENT = "vuln-trainer-pipeline/0.1 (+lernprojekt)"


def _log(msg: str) -> None:
    print(msg, flush=True)


class RateLimiter:
    """Einfaches Fenster: höchstens `max_calls` Aufrufe pro `window` Sekunden."""

    def __init__(self, max_calls: int, window: float):
        self.max_calls = max_calls
        self.window = window
        self._calls: list[float] = []

    def wait(self) -> None:
        now = time.monotonic()
        self._calls = [t for t in self._calls if now - t < self.window]
        if len(self._calls) >= self.max_calls:
            sleep_for = self.window - (now - self._calls[0]) + 0.2
            time.sleep(max(sleep_for, 0))
        self._calls.append(time.monotonic())


def get_bytes(url: str, headers: dict[str, str] | None = None, retries: int = 5,
              limiter: RateLimiter | None = None, timeout: int = 60) -> bytes:
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    last_err: Exception | None = None
    for attempt in range(retries):
        if limiter:
            limiter.wait()
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    data = gzip.decompress(data)
                return data
        except urllib.error.HTTPError as e:
            last_err = e
            # 403/429/503: NVD-Rate-Limit oder Wartung → Backoff
            if e.code in (403, 429, 500, 502, 503, 504):
                wait = min(60, 6 * (attempt + 1))
                _log(f"  HTTP {e.code} für {url[:90]} … warte {wait}s")
                time.sleep(wait)
                continue
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last_err = e
            wait = min(60, 6 * (attempt + 1))
            _log(f"  Netzfehler {e} … warte {wait}s")
            time.sleep(wait)
    raise RuntimeError(f"Aufgabe nach {retries} Versuchen fehlgeschlagen: {url}") from last_err


def cached_json(key: str, fetch, max_age_days: float | None = None):
    """Liest `cache/<key>.json`, sonst ruft `fetch()` auf und speichert das Ergebnis.

    max_age_days=None bedeutet: nie verfallen (NVD-Daten für alte CVEs ändern
    sich selten; erneut laden geht per `--refresh`).
    """
    path = CACHE_DIR / f"{key}.json"
    if path.exists():
        if max_age_days is None or (time.time() - path.stat().st_mtime) < max_age_days * 86400:
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
    data = fetch()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    tmp.replace(path)
    return data
