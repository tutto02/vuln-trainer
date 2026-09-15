"""CWE → Lernklasse, CPE → Stack, Vektor → Fallen-Marker (traps)."""
from __future__ import annotations

import json
import pathlib

from . import cvss31

DATA_DIR = pathlib.Path(__file__).resolve().parents[1] / "data"
_CLASSES = json.loads((DATA_DIR / "classes.json").read_text(encoding="utf-8"))
CLASSES: dict[str, dict] = _CLASSES["classes"]
STACKS: dict[str, list[str]] = _CLASSES["stacks"]

_CWE_TO_CLASS: dict[str, str] = {}
for _cid, _c in CLASSES.items():
    for _cwe in _c["cwes"]:
        _CWE_TO_CLASS.setdefault(_cwe, _cid)


def learn_class(cwe: str | None) -> str | None:
    """Gibt die Lernklasse für eine CWE-ID zurück, None wenn unbekannt."""
    if not cwe:
        return None
    return _CWE_TO_CLASS.get(cwe)


def primary_cwe(weaknesses: list[dict]) -> tuple[str | None, str | None, list[str]]:
    """Wählt die maßgebliche CWE: erst NVD (Primary), sonst CNA. Gibt (cwe, quelle, alle) zurück.

    Bevorzugt eine CWE, die einer Lernklasse zugeordnet ist, gegenüber NVD-CWE-noinfo.
    """
    all_ids: list[str] = []
    ranked: list[tuple[int, str, str]] = []
    for w in weaknesses:
        prio = 0 if w.get("type") == "Primary" else 1
        for cid in w.get("ids", []):
            if cid not in all_ids:
                all_ids.append(cid)
            known = 0 if (learn_class(cid) and learn_class(cid) != "unclassified") else 1
            ranked.append((known * 10 + prio, cid, "nvd" if w.get("source") == "nvd@nist.gov" else "cna"))
    if not ranked:
        return None, None, all_ids
    ranked.sort()
    _, cid, src = ranked[0]
    return cid, src, all_ids


def _vendor_product(cpe: str) -> tuple[str, str, str]:
    parts = cpe.split(":")
    if len(parts) < 5:
        return "", "", ""
    return parts[2], parts[3], parts[4]        # part (a/o/h), vendor, product


def stack_for(cpes: list[str], description: str = "") -> tuple[str, str | None]:
    """Heuristische Stack-Zuordnung. Gibt (stack, hauptvendor) zurück."""
    vendors: list[str] = []
    parts: list[str] = []
    vp_keys: list[str] = []
    for c in cpes:
        part, vendor, product = _vendor_product(c)
        if vendor and vendor not in vendors:
            vendors.append(vendor)
        parts.append(part)
        vp_keys.append(f"{vendor}:{product}")
    main_vendor = vendors[0] if vendors else None

    def hit(lst: list[str]) -> bool:
        for key in lst:
            if ":" in key:
                if any(k.startswith(key) for k in vp_keys):
                    return True
            elif key in vendors:
                return True
        return False

    if hit(STACKS["windows_vendors"]):
        return "windows", main_vendor
    if hit(STACKS["network_vendors"]):
        return "network", main_vendor
    if hit(STACKS["ics_vendors"]):
        return "ics-iot", main_vendor
    if hit(STACKS["linux_vendors"]) and "o" in parts:
        return "linux", main_vendor
    if hit(STACKS["apple_vendors"]):
        return "apple", main_vendor
    if hit(STACKS["android_vendors"]):
        return "android", main_vendor
    if hit(STACKS["web_vendors"]):
        return "web", main_vendor
    if hit(STACKS["library_vendors"]):
        return "library", main_vendor
    if hit(STACKS["linux_vendors"]):
        return "linux", main_vendor
    # Produkt-Stichwörter als letzte Stufe
    text = " ".join(vp_keys) + " " + description.lower()[:300]
    if any(w in text for w in ("wordpress", "plugin", "cms", "web", "http", "servlet", "portal", "php", "webapp", "rest api", "html", "url")):
        return "web", main_vendor
    if any(w in text for w in ("lib", "library", "parser", "codec", "sdk", "framework", "module", "package", "npm", "pypi", "crate", "gem")):
        return "library", main_vendor
    if "o" in parts and vendors:
        return "other-os", main_vendor
    if "h" in parts:
        return "ics-iot", main_vendor
    return "application", main_vendor


def traps_for(vector: str) -> list[str]:
    """Marker aus dem offiziellen Vektor, um die dokumentierten Fehlerbilder gezielt zu treffen."""
    m = cvss31.parse_vector(vector)
    t: list[str] = []
    if m["S"] == "C":
        t.append("scope_c")
    elif m["C"] == "H" and m["I"] == "H" and m["A"] == "H":
        t.append("scope_u_high_impact")
    if m["C"] == "L":
        t.append("c_low")
    elif m["C"] == "H" and (m["I"] == "N" or m["I"] == "L"):
        t.append("c_high_scoped")
    if m["AV"] == "N" and m["PR"] == "N":
        t.append("pr_n_but_ui_r" if m["UI"] == "R" else "pr_n_network_only")
    elif m["AV"] == "N" and m["PR"] == "L":
        t.append("pr_l_authenticated")
    if m["AC"] == "H":
        t.append("ac_h")
    return t
