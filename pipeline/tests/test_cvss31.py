"""Testvektoren mit offiziellen NVD-Scores. Dieselbe Liste liegt als
tests/vectors.json für den TypeScript-Rechner bereit."""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from vt_pipeline import cvss31  # noqa: E402

VECTORS = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # klassisches XSS
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),   # lokale Privilege Escalation
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),   # DoS
    ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1),
    ("CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 4.6),
    ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 6.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L", 5.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
]


def test_scores():
    for vec, expected in VECTORS:
        assert cvss31.score_from_vector(vec) == expected, (vec, cvss31.score_from_vector(vec), expected)


def test_roundtrip():
    for vec, _ in VECTORS:
        assert cvss31.format_vector(cvss31.parse_vector(vec)) == vec


def test_diff():
    assert cvss31.diff_vectors(VECTORS[0][0], VECTORS[1][0]) == ["S"]


if __name__ == "__main__":
    test_scores(); test_roundtrip(); test_diff()
    pathlib.Path(__file__).with_name("vectors.json").write_text(
        json.dumps([{"vector": v, "score": s} for v, s in VECTORS], indent=1))
    print(f"ok, {len(VECTORS)} Vektoren")
