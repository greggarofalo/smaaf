# Static Malware Analysis Automation Framework (SMAAF)

## Panoramica
SMAAF è un framework modulare per l’analisi statica di campioni Windows PE. Il
progetto combina disassemblaggio automatico, estrazione di Indicatori di
Compromissione (IoC), correlazione con feed open threat-intelligence e
classificazione tramite modello di machine learning addestrabile in locale.

L’ecosistema è composto da CLI, webapp Flask e motore di reportistica
HTML/PDF. Tutti i moduli sono riutilizzabili singolarmente oppure orchestrati
attraverso `cli.py`.

### Obiettivi principali
* Disassemblare in batch (Radare2) e arricchire i metadati PE.
* Estrarre IoC da stringhe/ASM, filtrare segnali rumorosi e correlare con feed
  pubblici (URLhaus, Feodo).
* Applicare un predittore ML che restituisce **percentuale di confidenza**
  anziché livelli di severità arbitrari.
* Generare report leggibili e esportazioni JSON strutturate per integrazione
  con pipeline esterne.
* Offrire una webapp con pagina di caricamento e stato avanzamento in tempo
  reale.

---

## Struttura dei sorgenti
```
analyzer/
 ├── __init__.py
 ├── ioc/                     # Estrazione IOC, gestione feed TI, YARA
 └── ioc_signatures.py        # Regole regex supplementari

collector/
 └── download.py              # Integrazione MalwareBazaar

core/
 ├── artifacts.py             # Gestione JSON/PDF e merge dati
 ├── db.py                    # Helper per dataset locali
 └── settings.py              # Percorsi e variabili globali

disassembler/
 └── r2_scan.py               # Wrapper Radare2 per JSON/ASM

predictor/
 ├── extractor.py             # Feature engineering per il modello ML
 ├── inference.py             # Runtime scoring (PredictorEngine)
 └── trainer.py               # Pipeline di training (scikit-learn)

reporting/
 ├── engine.py                # Rendering HTML→PDF
 ├── structured_export.py     # Export JSON strutturato
 └── templates/               # Template Jinja2

scripts/
 └── evaluate_yara_rules.py   # Analisi qualità bundle YARA

webapp/
 ├── __init__.py              # Applicazione Flask
 ├── __main__.py              # Entrypoint sviluppatori
 └── templates/               # Vista report, indice, loading page

cli.py                        # Entrypoint CLI unificato
```

---

## Moduli in evidenza
### Disassembler (`disassembler/r2_scan.py`)
* Disassemblaggio tramite `r2pipe`, output JSON e dump ASM.
* Estrae funzioni, import/export, entropy sezioni, overlay, TLS callbacks,
  firme Authenticode e metadata PE aggiuntivi.

### Analyzer & IoC (`analyzer/ioc/*`)
* Normalizza stringhe e ASM, applica regex robuste per URL, domini, IPv4/IPv6,
  registry, percorsi Windows, hash.
* Determina IP pubblici significativi, segnala API sospette e popola la sezione
  “notable IoC” del report.
* Correlazione con feed TI (URLhaus, Feodo). Le liste confermate e sospette
  vengono propagate al report e al JSON strutturato.
* Gestione YARA tramite `YaraManager`, compilazione bundle, filtraggio warning
  non rilevanti e conteggio regole disponibili.
  * **Fonte YARA primaria:** [HydraDragonAntivirus/hydradragon/yara](https://github.com/HydraDragonAntivirus/HydraDragonAntivirus)
    (per mantenere continuità con il dataset originale).
  * Altre fonti: `Neo23x0/signature-base`, `Yara-Rules/rules` (subset Windows).

### Predictor (`predictor/`)
* `PEFeatureExtractor` implementa lo stesso schema numerico storicamente usato
  dal progetto per garantire compatibilità con dataset legacy.
* `PredictorTrainer` addestra un pipeline `StandardScaler + RandomForest` e
  produce `predictor_model.joblib` insieme a `training_summary.json`.
* `PredictorEngine` fornisce inferenza runtime, includendo soglia decisionale,
  probabilità per classe e **percentuale di confidenza** da utilizzare nei
  report.

### Reporting (`reporting/`)
* `engine.py` genera report HTML e PDF (WeasyPrint) e aggiorna l’artefatto.
* `report.html.j2` visualizza la confidenza ML, i segnali attivati, i feed TI e
  le regole YARA significative. I warning YARA non essenziali vengono filtrati
  in automatico.
* `structured_export.py` produce export JSON (scan + network) con schema
  documentato, utile per pipeline SIEM/SOAR.

### Webapp (`webapp/`)
* Upload asincrono con thread pool e **pagina di caricamento dinamica**: la
  progress bar si aggiorna interrogando `/status/<sha>` finché l’analisi non è
  conclusa.
* Lista dei report recenti con confidenza ML, accesso rapido al PDF e alle
  esportazioni JSON.
* Tutti i passi della pipeline (disassemblaggio, ML, IOC, report) vengono
  tracciati e salvati nell’artefatto.

### Script YARA (`scripts/evaluate_yara_rules.py`)
* Compila (opzionalmente forzando l’aggiornamento delle sorgenti) e riporta:
  numero di regole uniche, conteggio per sorgente, warning di compilazione con
  classificazione (performance, deprecated, ecc.).
* Output opzionale in JSON.

---

## Dipendenze principali
* **Python 3.9+**
* **Radare2** (>=5.x) con `r2pipe`
* **yara/yarac** CLI installati nel PATH
* **Jinja2**, **WeasyPrint** (per PDF)
* **pefile**, **python-magic**, **pyzipper**, **requests**
* **capstone**, **numpy**, **scikit-learn**, **joblib**
* (opzionale) **FLOSS** per stringhe offuscate

Su macOS ARM può essere necessario esportare variabili `PKG_CONFIG_PATH`,
`GI_TYPELIB_PATH` e `DYLD_FALLBACK_LIBRARY_PATH`. Lo script
`scripts/env.darwin.sh` automatizza l’operazione.

---

## Utilizzo rapido
```bash
# 1. Disassembla (o copia) il JSON Radare2 in disassembler/disassembled/json/<sha>.json
python cli.py assemble <sha256>
python cli.py predict <sha256>
python cli.py iocs <sha256>
python cli.py report <sha256>

# Pipeline completa
python cli.py pipeline <sha256>
```

### Interfaccia web
```bash
export FLASK_APP=webapp:create_app
flask run --host 0.0.0.0 --port 5000
```
Carica un campione dal browser e segui l’avanzamento in tempo reale. Al termine
sono disponibili report HTML/PDF e export JSON strutturati.

### Script valutazione YARA
```bash
python scripts/evaluate_yara_rules.py --force-update --json yara_summary.json
```

---

## Artefatti prodotti
* `artifacts/<sha>.json` – artefatto unificato con static, prediction, IoC.
* `artifacts/<sha>.pdf` e `artifacts/<sha>.html` – report per analisti.
* `artifacts/structured/<sha>/` – esportazioni JSON (scan + network).
* `predictor_artifacts/` – modello ML addestrato e summary.

---

## Licenza e contributi
Il progetto è destinato a scopi di ricerca e formazione. Si consiglia di
utilizzare il framework in ambienti isolati e rispettare le policy delle fonti
OSINT dai quali vengono scaricati i campioni.
