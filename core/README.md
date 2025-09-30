# Static Malware Analysis Automation Framework — Core Modules

Questo documento descrive i moduli principali del core del framework:
- `core/db.py`
- `core/artifacts.py`
- `core/settings.py`

---

# 📄 core/db.py — Stato della pipeline (SQLite)

Questo modulo gestisce lo **stato della pipeline** tramite un database SQLite locale.  
Serve per monitorare il progresso di ogni sample (`sha256`) lungo le varie fasi:  
`collected → disassembled → iocs → reported`.

## 📦 Funzionalità principali

- Creazione automatica della tabella `samples` (se non esiste).
- Tracciamento di timestamp (ISO 8601 UTC) per ogni step della pipeline.
- API minimale:
  - `mark()` → aggiorna/inizializza lo stato di un sample.
  - `get()` → ritorna i metadati di un sample.
  - `list_recent()` → elenca i sample più recenti, filtrabili per stato.
- Resistente ai lock SQLite grazie a WAL + retry esponenziale.

## 🗄️ Schema della tabella

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

- `sha256` → identificatore univoco del sample.
- `filename` → nome del file analizzato.
- `status` → stato corrente della pipeline.
- `*_at` → timestamp ISO UTC degli step completati.

## 🔧 API

```python
from core import db

# Aggiorna lo stato di un sample
db.mark("abc123...", filename="malware.exe", field="disassembled_at", status="disassembled")

# Recupera le informazioni di un sample
info = db.get("abc123...")
print(info)

# Lista ultimi sample analizzati
recent = db.list_recent(limit=10, status="reported")
```

---

# 📄 core/artifacts.py — Artefatto unificato per sample

Questo modulo gestisce gli **artefatti JSON** generati durante la pipeline.  
Ogni sample ha un file dedicato (`artifacts/<sha256>.json`) che contiene tutte le informazioni raccolte.

## 📦 Funzionalità principali

- Gestione di un file JSON per sample.
- Scrittura **atomica** tramite `tempfile` → mai file corrotti.
- Merge **idempotente**:
  - Dizionari → unione ricorsiva (deep merge).
  - Liste / valori → sovrascritti.
- Aggiornamento automatico del campo `updated_at`.

## 📂 Struttura tipica di un artefatto

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

# Aggiorna un artefatto con info statiche
merge_artifact("abc123...", static={"arch": "x86", "bits": 32})

# Aggiunge IOC
merge_artifact("abc123...", iocs={"domains": ["evil.com"]})

# Legge l’artefatto
data = read_artifact("abc123...")
print(data["iocs"])
```

---

# 📄 core/settings.py — Configurazione centralizzata

Questo modulo definisce la configurazione centrale del framework.  
Serve a mantenere i percorsi e le variabili d’ambiente in un unico punto, evitando hard-code nei moduli.

## 📦 Funzionalità principali

- Definizione di cartelle principali (`data/`, `collector/malware_samples/`, `disassembler/`, `artifacts/`).
- Caricamento di variabili da `.env` (se presente).
- Creazione automatica delle directory mancanti.
- Accesso a chiavi API tramite variabili d’ambiente.

## 📂 Struttura cartelle

- `DATA_DIR` → cartella dati globale.
- `SAMPLES_DIR` → cartella unica per i sample.
- `DISASM_DIR` → output del disassembler.
  - `DISASM_JSON` → file JSON statici.
  - `DISASM_ASM` → eventuali file ASM.
- `ARTIFACTS` → artefatti e report PDF.
- `DB_PATH` → database SQLite (stato pipeline).
- `META_CSV` → metadati dei sample (CSV unico).

## 🔧 API

```python
from core import settings

print(settings.SAMPLES_DIR)
# /path/to/repo/collector/malware_samples
```

## 📝 Note

- Tutti i path possono essere sovrascritti tramite variabili d’ambiente.
- Le directory vengono create automaticamente all’avvio.