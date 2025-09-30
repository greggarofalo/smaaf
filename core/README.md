# Static Malware Analysis Automation Framework — Core Modules

This document describes the main core modules of the framework:  
Questo documento descrive i moduli principali del core del framework:
- `core/db.py`
- `core/artifacts.py`
- `core/settings.py`

---

# 📄 core/db.py — Pipeline State (SQLite) / Stato della pipeline (SQLite)

This module manages the **pipeline state** through a local SQLite database.  
Il modulo gestisce lo **stato della pipeline** tramite un database SQLite locale.

It is used to monitor the progress of each sample (`sha256`) along the various stages:  
Serve per monitorare il progresso di ogni sample (`sha256`) lungo le varie fasi:  
`collected → disassembled → iocs → reported`.

## 📦 Main Features / Funzionalità principali

- Automatic creation of the `samples` table (if it does not exist).  
  Creazione automatica della tabella `samples` (se non esiste).
- Timestamp tracking (ISO 8601 UTC) for each pipeline step.  
  Tracciamento di timestamp (ISO 8601 UTC) per ogni step della pipeline.
- Minimal API:  
  API minimale:
  - `mark()` → updates/initializes sample state.  
    Aggiorna/inizializza lo stato di un sample.
  - `get()` → returns sample metadata.  
    Ritorna i metadati di un sample.
  - `list_recent()` → lists most recent samples, filterable by state.  
    Elenca i sample più recenti, filtrabili per stato.
- Resilient to SQLite locks thanks to WAL + exponential retry.  
  Resistente ai lock SQLite grazie a WAL + retry esponenziale.

## 🗄️ Table Schema / Schema della tabella

```sql
samples(
  sha256 TEXT PRIMARY KEY,
  filename TEXT,
  collected_at TEXT,
  disassembled_at TEXT,
  iocs_at TEXT,
  reported_at TEXT,
  status TEXT
);
```

- `sha256` → unique sample identifier.  
  Identificatore univoco del sample.
- `filename` → analyzed filename.  
  Nome del file analizzato.
- `status` → current pipeline state.  
  Stato corrente della pipeline.
- `*_at` → ISO UTC timestamp of completed steps.  
  Timestamp ISO UTC degli step completati.

## 🔧 API

```python
from core import db

# Update sample state / Aggiorna lo stato di un sample
db.mark("abc123...", filename="malware.exe", field="disassembled_at", status="disassembled")

# Retrieve sample info / Recupera le informazioni di un sample
info = db.get("abc123...")
print(info)

# List last analyzed samples / Lista ultimi sample analizzati
recent = db.list_recent(limit=10, status="reported")
```

---

# 📄 core/artifacts.py — Unified Artifact per Sample / Artefatto unificato per sample

This module manages the **JSON artifacts** generated during the pipeline.  
Questo modulo gestisce gli **artefatti JSON** generati durante la pipeline.

Each sample has a dedicated file (`artifacts/<sha256>.json`) containing all collected information.  
Ogni sample ha un file dedicato (`artifacts/<sha256>.json`) che contiene tutte le informazioni raccolte.

## 📦 Main Features / Funzionalità principali

- Management of one JSON file per sample.  
  Gestione di un file JSON per sample.
- **Atomic** writes via `tempfile` → no corrupted files.  
  Scrittura **atomica** tramite `tempfile` → mai file corrotti.
- **Idempotent merge**:  
  Merge **idempotente**:
  - Dictionaries → recursive union (deep merge).  
    Dizionari → unione ricorsiva (deep merge).
  - Lists/values → overwritten.  
    Liste / valori → sovrascritti.
- Automatic update of `updated_at` field.  
  Aggiornamento automatico del campo `updated_at`.

## 📂 Typical Artifact Structure / Struttura tipica di un artefatto

```json
{
  "file": {
    "sha256": "abc123...",
    "name": "sample.exe"
  },
  "static": { ... },
  "iocs": { ... },
  "signatures": { ... },
  "report_ready": { ... },
  "updated_at": "2025-09-24T12:34:56Z"
}
```

## 🔧 API

```python
from core.artifacts import merge_artifact, read_artifact

# Update artifact with static info / Aggiorna un artefatto con info statiche
merge_artifact("abc123...", static={"arch": "x86", "bits": 32})

# Add IOC / Aggiunge IOC
merge_artifact("abc123...", iocs={"domains": ["evil.com"]})

# Read artifact / Legge l’artefatto
data = read_artifact("abc123...")
print(data["iocs"])
```

---

# 📄 core/settings.py — Centralized Configuration / Configurazione centralizzata

This module defines the centralized configuration of the framework.  
Questo modulo definisce la configurazione centrale del framework.

It keeps paths and environment variables in one place, avoiding hard-coded values across modules.  
Serve a mantenere i percorsi e le variabili d’ambiente in un unico punto, evitando hard-code nei moduli.

## 📦 Main Features / Funzionalità principali

- Definition of main folders (`data/`, `collector/malware_samples/`, `disassembler/`, `artifacts/`).  
  Definizione di cartelle principali (`data/`, `collector/malware_samples/`, `disassembler/`, `artifacts/`).
- Load variables from `.env` (if present).  
  Caricamento di variabili da `.env` (se presente).
- Automatic creation of missing directories.  
  Creazione automatica delle directory mancanti.
- Access to API keys via environment variables.  
  Accesso a chiavi API tramite variabili d’ambiente.

## 📂 Folder Structure / Struttura cartelle

- `DATA_DIR` → global data folder.  
  Cartella dati globale.
- `SAMPLES_DIR` → unique folder for samples.  
  Cartella unica per i sample.
- `DISASM_DIR` → disassembler output.  
  Output del disassembler.
  - `DISASM_JSON` → static JSON files.  
    File JSON statici.
  - `DISASM_ASM` → ASM files.  
    Eventuali file ASM.
- `ARTIFACTS` → artifacts and PDF reports.  
  Artefatti e report PDF.
- `DB_PATH` → SQLite database (pipeline state).  
  Database SQLite (stato pipeline).
- `META_CSV` → sample metadata (single CSV).  
  Metadati dei sample (CSV unico).

## 🔧 API

```python
from core import settings

print(settings.SAMPLES_DIR)
# /path/to/repo/collector/malware_samples
```

## 📝 Notes / Note

- All paths can be overridden through environment variables.  
  Tutti i path possono essere sovrascritti tramite variabili d’ambiente.
- Directories are automatically created at startup.  
  Le directory vengono create automaticamente all’avvio.
