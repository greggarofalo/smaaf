# Reporting Engine

Il modulo di reporting genera output HTML/PDF a partire dagli artefatti prodotti
dalla pipeline (`artifacts/<sha>.json`). Inoltre espone un export JSON
strutturato pensato per l’integrazione con sistemi SIEM/SOAR.

## Funzionalità
* **Templating Jinja2** (`templates/report.html.j2`)
  * Executive summary, fiducia ML, threat intelligence confermata/sospetta,
    IoC locali e copertura YARA.
  * CSS embedded per distribuzione standalone.
* **Rendering PDF** (`engine.py`) tramite WeasyPrint.
* **Export strutturato** (`structured_export.py`)
  * Genera `scan_report.json` e `network_indicators.json` con schema stabile.
  * Include confidenza ML, segnali attivati, indicatori confermati/sospetti e
    warning YARA filtrati.
* **Filtraggio warning**
  * Messaggi non azionabili (es. note di performance) non vengono mostrati nei
    report.

## Dipendenze
* Jinja2
* WeasyPrint (+ cairo/pango/gdk-pixbuf/libffi a livello di sistema)

### Nota WeasyPrint
Installazione tipica su Debian/Ubuntu:
```bash
sudo apt-get install libcairo2 pango1.0-tools libgdk-pixbuf2.0-dev libffi-dev
```
Su macOS/Homebrew consultare `scripts/env.darwin.sh` per le variabili da
esportare (`PKG_CONFIG_PATH`, `GI_TYPELIB_PATH`, `DYLD_FALLBACK_LIBRARY_PATH`).

## Utilizzo
```bash
python cli.py report <sha256>
```
Oppure utilizza la webapp per ottenere report HTML/PDF automaticamente al termine
 della pipeline di upload.

## Output
* `artifacts/<sha>.pdf` – report finale
* `artifacts/<sha>.html` – versione HTML archiviata
* `artifacts/structured/<sha>/scan_report.json`
* `artifacts/structured/<sha>/network_indicators.json`

