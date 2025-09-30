# Webapp Module — Flask Interface

The `webapp/` package provides a **minimal Flask-based interface** for SMAAF, allowing analysts to upload Windows PE samples, track analysis progress, and view/download reports.

Il package `webapp/` fornisce una **interfaccia minimale basata su Flask** per SMAAF, consentendo agli analisti di caricare campioni PE Windows, monitorare l’avanzamento dell’analisi e visualizzare/scaricare i report.

---

## Features / Funzionalità

- **Upload interface**  
  Analysts can upload PE files (`.exe`, `.dll`, `.sys`, `.bin`) via a simple form.  
  Gli analisti possono caricare file PE (`.exe`, `.dll`, `.sys`, `.bin`) tramite un form semplice.

- **Real-time progress tracking**  
  Progress bar and stage messages are updated via `/status/<sha>` polling.  
  Barra di progresso e messaggi di stato aggiornati in tempo reale tramite polling su `/status/<sha>`.

- **Integrated pipeline orchestration**  
  Upon upload, the full pipeline runs asynchronously with `ThreadPoolExecutor`:  
  Dopo l’upload, la pipeline completa viene eseguita in asincrono con `ThreadPoolExecutor`:
  1. Radare2 static analysis / Analisi Radare2  
  2. ML prediction / Predizione ML  
  3. IOC & YARA correlation / Correlazione IOC & YARA  
  4. Structured JSON export / Export JSON strutturati  
  5. Report rendering (HTML + PDF) / Rendering report (HTML + PDF)

- **Report management**  
  - `reports/<sha>` → summary view + download links  
  - `reports/<sha>/pdf` → PDF report  
  - `reports/<sha>/inline` → inline HTML view  
  - `reports/<sha>/export/<kind>` → JSON exports (`scan_report.json`, `network_indicators.json`)  

  **Gestione report**:
  - `reports/<sha>` → vista riepilogativa + link download  
  - `reports/<sha>/pdf` → report PDF  
  - `reports/<sha>/inline` → visualizzazione HTML integrata  
  - `reports/<sha>/export/<kind>` → export JSON (`scan_report.json`, `network_indicators.json`)

- **Recent analyses list**  
  The homepage shows the most recent artifacts with ML confidence, prediction, and quick links.  
  La homepage mostra gli ultimi artefatti con percentuale di confidenza ML, prediction e link rapidi.

---

## Architecture / Architettura

```
webapp/
├── __init__.py        # create_app() factory
├── __main__.py        # Entrypoint for Flask run
├── templates/
│   ├── base.html      # Shared layout
│   ├── index.html     # Upload form + recent analyses
│   ├── loading.html   # Dynamic progress tracking
│   └── report_view.html # Report viewer + exports
```

---

## API Endpoints

- `/` → Homepage with upload + recent reports  
  Homepage con upload e report recenti

- `/upload` → POST endpoint for sample upload  
  Endpoint POST per caricamento campione

- `/processing/<sha>` → Shows progress bar while job runs  
  Mostra barra di progresso durante l’analisi

- `/status/<sha>` → Returns JSON job status (progress, stage, error)  
  Restituisce stato job in JSON (progresso, stage, errore)

- `/reports/<sha>` → Report summary page with links  
  Pagina di riepilogo con link ai report

- `/reports/<sha>/inline` → Inline HTML report viewer  
  Visualizzatore report HTML inline

- `/reports/<sha>/pdf` → PDF download  
  Download PDF

- `/reports/<sha>/export/<kind>` → JSON exports  
  Export JSON

---

## Usage / Utilizzo

Run the webapp with Flask:

```bash
export FLASK_APP=webapp:create_app
flask run --host 0.0.0.0 --port 5000
```

Or directly via `__main__.py`:

```bash
python -m webapp
```

Access in browser: `http://localhost:5000`

---

## Configuration / Configurazione

Environment variables:

| Variable | Default | Description / Descrizione |
|----------|---------|---------------------------|
| `SMAAF_WEB_SECRET` | `smaaf-dev-secret` | Flask session key / Chiave sessione Flask |
| `SMAAF_WEB_MAX_UPLOAD` | `50MB` | Max upload size / Dimensione massima upload |
| `SMAAF_MAX_JOBS` | `2` | Thread pool workers / Numero massimo job concorrenti |
| `SMAAF_PREDICTOR_MODEL` | `predictor_artifacts/predictor_model.joblib` | ML model path / Percorso modello ML |
| `SMAAF_PREDICT_THRESHOLD` | `0.5` | ML decision threshold / Soglia decisionale ML |

---

## Output

- `artifacts/<sha>.json` → unified artifact  
- `artifacts/<sha>.pdf` → PDF report  
- `artifacts/<sha>.html` → HTML archived report  
- `artifacts/structured/<sha>/scan_report.json`  
- `artifacts/structured/<sha>/network_indicators.json`

---

© 2025 — Gregorio Garofalo
