# Static Malware Analysis Automation Framework — CLI

La CLI basata su [Typer](https://typer.tiangolo.com/) consente di orchestrare
l’intera pipeline di analisi statica: import dei disassemblati, inferenza del
modello ML, estrazione IOC/YARA e generazione report.

---

## Requisiti
* Python ≥ 3.9
* Dipendenze principali: `typer`, `jinja2`, `weasyprint`
* Struttura del progetto disponibile (cartelle `core/`, `analyzer/`,
  `disassembler/`, `predictor/`, `reporting/`, `webapp/`).

Installazione rapida:
```bash
git clone https://github.com/<tuo_repo>/static-malware-analyzer.git
cd static-malware-analyzer
pip install -r requirements.txt
```

Assicurati che i JSON generati da Radare2 siano presenti in
`disassembler/disassembled/json/<sha256>.json` prima di lanciare `assemble`.

---

## Utilizzo
```bash
python cli.py --help
```

### Comandi principali
* **assemble**
  ```bash
  python cli.py assemble <sha256>
  ```
  Importa il JSON statico e crea/aggiorna l’artefatto locale.

* **predict**
  ```bash
  python cli.py predict <sha256> --model-path predictor_artifacts/predictor_model.joblib
  ```
  Carica il modello, estrae le feature e salva verdetto + probabilità del
  classificatore. La percentuale di confidenza sarà poi mostrata nei report.

* **iocs**
  ```bash
  python cli.py iocs <sha256>
  ```
  Esegue correlazione IOC/YARA, aggiorna i feed di threat intelligence e popola
  i segnali che verranno evidenziati nel report.

* **report**
  ```bash
  python cli.py report <sha256>
  ```
  Genera il PDF sfruttando il template Jinja2 + WeasyPrint.

* **pipeline**
  ```bash
  python cli.py pipeline <sha256>
  ```
  Esegue in sequenza assemble → predict → iocs → report. Opzioni `--model-path`
  e `--threshold` sono disponibili anche qui.

* **pipeline-all**
  ```bash
  python cli.py pipeline-all
  ```
  Applica la pipeline completa a tutti i JSON presenti nella directory
  configurata (`DISASM_JSON`).

### Comandi opzionali
* **train-predictor**
  ```bash
  python cli.py train-predictor --malicious-dir samples/malicious --benign-dir samples/benign
  ```
  Estrae le feature legacy, salva `ml_vectors.bin`/`ml_index.jsonl` e addestra
  `predictor_model.joblib` + `training_summary.json`.

* **fetch-samples**
  ```bash
  python cli.py fetch-samples 100
  ```
  Scarica campioni da MalwareBazaar usando il collector integrato.

---

## Output
* `artifacts/<sha256>.json` – artefatto consolidato.
* `artifacts/<sha256>.pdf` / `artifacts/<sha256>.html` – report.
* `artifacts/structured/<sha256>/` – esportazioni JSON (scan + network).

---

## Note
* `assemble` fallisce se il JSON Radare2 non è disponibile.
* WeasyPrint richiede dipendenze native (cairo, pango, gdk-pixbuf, libffi).
* Il percorso del modello ML è configurabile tramite variabile
  `SMAAF_PREDICTOR_MODEL` oppure opzioni CLI.

© 2025 — Gregorio Garofalo
