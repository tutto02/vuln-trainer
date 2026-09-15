# vuln-trainer

Lern-App für Schwachstellen-Analyse: CVSS-Vektoren bauen, Schwachstellenklassen erkennen,
Gefährlichkeit im Kontext (KEV, EPSS) einschätzen.

Zwei strikt getrennte Phasen:

- **Phase A – `pipeline/`** (Python, nur Standardbibliothek): zieht NVD, EPSS und KEV,
  wählt einen ausgewogenen Korpus und erzeugt statische JSON-Dateien.
- **Phase B – `docs/`**: statische Web-App (zugleich GitHub-Pages-Wurzel), liest nur `docs/data/*.json`. Kein Server,
  keine laufenden Kosten.

## Pipeline

```bash
cd pipeline
cp .env.example .env            # NVD-API-Key eintragen (50 statt 5 Anfragen / 30 s)
python3 -m vt_pipeline fetch    # KEV + EPSS + NVD (alles gecacht in cache/)
python3 -m vt_pipeline select --target 900   # out/corpus.json + out/report.md
python3 -m vt_pipeline enrich-export         # Arbeitspakete → enrich/todo/
python3 -m vt_pipeline status                # Anreicherung validieren
python3 -m vt_pipeline build                 # docs/data/*.json
python3 tests/test_cvss31.py                 # CVSS-Rechner prüfen
```

### Anreicherung ohne API

Die Begründungen pro Metrik und die Angriffsketten entstehen **nicht** per API-Aufruf.
`enrich-export` schreibt kompakte Arbeitspakete nach `enrich/todo/batch-NNN.json`.
Claude (in Claude Code) liest ein Paket und schreibt `enrich/done/batch-NNN.json` im
Schema aus `vt_pipeline/enrich.py`. `status` validiert: Vektorbasis muss dem offiziellen
Vektor entsprechen, alle acht Metriken brauchen eine Begründung. Ungültige Einträge
werden beim Build ignoriert, nicht stillschweigend übernommen.

### Kernkonzepte in den Daten

- **Vektor-Provenienz**: `cvss.official.source` ist `nvd` oder `cna`. Liegen beide vor,
  listet `cvss.differs` die abweichenden Metriken.
- **Lernklassen**: `data/classes.json` bildet CWE-IDs auf ~30 lernbare Klassen ab. Spaced
  Repetition arbeitet auf dieser Ebene, nicht auf einzelnen CVEs.
- **Fallen-Marker** (`traps`): aus dem offiziellen Vektor berechnet, damit Übungen die
  dokumentierten Fehlerbilder (Scope U/C, C:L vs. C:H, PR:N) gezielt treffen.
