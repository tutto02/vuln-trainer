"""CVSS v3.1 Basis-Score-Rechner (Spezifikation FIRST, Abschnitt 7).

Rein, ohne Abhängigkeiten. Wird in der Pipeline benutzt, um jeden Vektor
gegen den offiziellen Score zu prüfen. Das TypeScript-Gegenstück im Web
muss dieselben Testvektoren (tests/test_cvss31.py) bestehen.
"""
from __future__ import annotations

import math
import re

METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

ALLOWED = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "R"),
    "S": ("U", "C"),
    "C": ("N", "L", "H"),
    "I": ("N", "L", "H"),
    "A": ("N", "L", "H"),
}

_W_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_W_AC = {"L": 0.77, "H": 0.44}
_W_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_W_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_W_UI = {"N": 0.85, "R": 0.62}
_W_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_VECTOR_RE = re.compile(r"^CVSS:3\.[01]/(.+)$")


def parse_vector(vector: str) -> dict[str, str]:
    """Zerlegt 'CVSS:3.1/AV:N/AC:L/...' in ein Dict der acht Basismetriken.

    Temporal-/Environmental-Metriken werden ignoriert. Wirft ValueError bei
    fehlenden oder ungültigen Basismetriken.
    """
    m = _VECTOR_RE.match(vector.strip())
    if not m:
        raise ValueError(f"Kein CVSS-3.x-Vektor: {vector!r}")
    parts: dict[str, str] = {}
    for token in m.group(1).split("/"):
        if ":" not in token:
            raise ValueError(f"Ungültiges Token {token!r} in {vector!r}")
        key, val = token.split(":", 1)
        if key in ALLOWED:
            if val not in ALLOWED[key]:
                raise ValueError(f"Ungültiger Wert {key}:{val} in {vector!r}")
            parts[key] = val
    missing = [k for k in METRICS if k not in parts]
    if missing:
        raise ValueError(f"Fehlende Metriken {missing} in {vector!r}")
    return {k: parts[k] for k in METRICS}


def format_vector(metrics: dict[str, str]) -> str:
    return "CVSS:3.1/" + "/".join(f"{k}:{metrics[k]}" for k in METRICS)


def roundup(x: float) -> float:
    """Roundup nach CVSS-3.1-Spezifikation (Appendix A), vermeidet Float-Artefakte."""
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def base_score(metrics: dict[str, str]) -> float:
    s_changed = metrics["S"] == "C"
    iss = 1 - (1 - _W_CIA[metrics["C"]]) * (1 - _W_CIA[metrics["I"]]) * (1 - _W_CIA[metrics["A"]])
    if s_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    pr_w = (_W_PR_C if s_changed else _W_PR_U)[metrics["PR"]]
    exploitability = 8.22 * _W_AV[metrics["AV"]] * _W_AC[metrics["AC"]] * pr_w * _W_UI[metrics["UI"]]
    if impact <= 0:
        return 0.0
    if s_changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def score_from_vector(vector: str) -> float:
    return base_score(parse_vector(vector))


def severity(score: float) -> str:
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def diff_vectors(a: str, b: str) -> list[str]:
    """Liste der Metriken, in denen sich zwei Vektoren unterscheiden."""
    pa, pb = parse_vector(a), parse_vector(b)
    return [k for k in METRICS if pa[k] != pb[k]]
