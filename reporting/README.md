# Reporting Engine

The reporting module generates HTML/PDF outputs from the artifacts produced by the pipeline (`artifacts/<sha>.json`).  
It also provides a structured JSON export designed for integration with SIEM/SOAR systems.

Il modulo di reporting genera output HTML/PDF a partire dagli artefatti prodotti dalla pipeline (`artifacts/<sha>.json`).  
Inoltre espone un export JSON strutturato pensato per l’integrazione con sistemi SIEM/SOAR.

---

## Features / Funzionalità
* **Jinja2 Templating** (`templates/report.html.j2`)  
  * Executive summary, ML confidence, confirmed/suspicious threat intelligence, local IoCs, and YARA coverage.  
  * Executive summary, fiducia ML, threat intelligence confermata/sospetta, IoC locali e copertura YARA.  
  * Embedded CSS for standalone distribution.  
  * CSS embedded per distribuzione standalone.

* **PDF Rendering** (`engine.py`) using WeasyPrint.  
  **Rendering PDF** (`engine.py`) tramite WeasyPrint.

* **Structured Export** (`structured_export.py`)  
  * Generates `scan_report.json` and `network_indicators.json` with a stable schema.  
  * Genera `scan_report.json` e `network_indicators.json` con schema stabile.  
  * Includes ML confidence, triggered signals, confirmed/suspicious indicators, and filtered YARA warnings.  
  * Include confidenza ML, segnali attivati, indicatori confermati/sospetti e warning YARA filtrati.

* **Warning Filtering / Filtraggio warning**  
  * Non-actionable messages (e.g., performance notes) are not displayed in the reports.  
  * Messaggi non azionabili (es. note di performance) non vengono mostrati nei report.

---

## Dependencies / Dipendenze
* Jinja2
* WeasyPrint (+ cairo/pango/gdk-pixbuf/libffi system-level)  
  WeasyPrint (+ cairo/pango/gdk-pixbuf/libffi a livello di sistema)

### WeasyPrint Note / Nota WeasyPrint
Typical installation on Debian/Ubuntu:  
Installazione tipica su Debian/Ubuntu:
```bash
sudo apt-get install libcairo2 pango1.0-tools libgdk-pixbuf2.0-dev libffi-dev
```

On macOS/Homebrew, check `scripts/env.darwin.sh` for required exported variables (`PKG_CONFIG_PATH`, `GI_TYPELIB_PATH`, `DYLD_FALLBACK_LIBRARY_PATH`).  
Su macOS/Homebrew consultare `scripts/env.darwin.sh` per le variabili da esportare (`PKG_CONFIG_PATH`, `GI_TYPELIB_PATH`, `DYLD_FALLBACK_LIBRARY_PATH`).

---

## Usage / Utilizzo
```bash
python cli.py report <sha256>
```

Or use the webapp to automatically obtain HTML/PDF reports at the end of the upload pipeline.  
Oppure utilizza la webapp per ottenere report HTML/PDF automaticamente al termine della pipeline di upload.

---

## Output
* `artifacts/<sha>.pdf` – final report  
  Report finale
* `artifacts/<sha>.html` – archived HTML version  
  Versione HTML archiviata
* `artifacts/structured/<sha>/scan_report.json`
* `artifacts/structured/<sha>/network_indicators.json`
