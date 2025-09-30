# collector/download.py — MalwareBazaar Sample Collector

This module implements a **sample collector** from [MalwareBazaar](https://bazaar.abuse.ch/).  
It downloads malicious binaries (Windows/PE executables), verifies validity, extracts metadata, and saves them locally.

Questo modulo implementa un **collettore di sample** da [MalwareBazaar](https://bazaar.abuse.ch/).  
Serve a scaricare binari malevoli (eseguibili Windows/PE), verificarne la validità ed estrarre metadati, salvandoli localmente.

---

## 📦 Main Features / Funzionalità principali

- **Sample collection** from MalwareBazaar:  
  **Raccolta sample** da MalwareBazaar:
  - `fetch_hashes_by_type()` → gets recent hashes for a given file_type (e.g., `exe`, `dll`, `pe`).  
    Ottiene hash recenti per un dato file_type (es. `exe`, `dll`, `pe`).
  - `download_sample()` → downloads a sample, extracts it if compressed (ZIP with password `infected`), and validates it.  
    Scarica un sample, lo estrae se compresso (ZIP con password `infected`), e lo valida.
  - `collect_dataset(target)` → populates `SAMPLES_DIR` until the requested number of valid binaries is reached.  
    Popola `SAMPLES_DIR` fino al numero richiesto di binari validi.

- **Metadata / Metadati**:
  - Hash calculation (`sha256`, `md5`).  
    Calcolo hash (`sha256`, `md5`).
  - PE architecture (`x86`, `x86_64`).  
    Architettura PE (`x86`, `x86_64`).
  - Authenticode signature presence.  
    Presenza firma Authenticode.
  - Other API fields (file_name, file_type, file_size, signature, tags, clamav).  
    Altri campi dall’API (file_name, file_type, file_size, signature, tags, clamav).

- **Persistent storage / Salvataggio persistente**:
  - Unified CSV (`META_CSV`), incrementally and idempotently updated.  
    CSV unificato (`META_CSV`), aggiornato in modo incrementale e idempotente.

- **Dataset statistics / Statistiche dataset**:
  - `dataset_stats()` → produces a JSON with:  
    Produce un JSON con:
    - Total samples / Totale sample,
    - Distribution by `signature` and `file_type` / Distribuzione per `signature` e `file_type`,
    - Size statistics (`min`, `p50`, `mean`, `p90`, `max`) / Statistiche sulle dimensioni (`min`, `p50`, `mean`, `p90`, `max`),
    - Time range (`first`, `last`) / Intervallo temporale (`first`, `last`),
    - Average samples collected per day (`avg_per_day`) / Media di sample raccolti al giorno (`avg_per_day`).

---

## 📂 File and Directory Structure / Struttura file e directory

- **Samples** → saved in `collector/malware_samples/` (`SAMPLES_DIR`).  
  **Samples** → salvati in `collector/malware_samples/` (`SAMPLES_DIR`).
- **Metadata** → single CSV in `collector/metadata.csv` (`META_CSV`).  
  **Metadati** → CSV unico in `collector/metadata.csv` (`META_CSV`).
- **Statistics** → JSON in `data/dataset_stats.json`.  
  **Statistiche** → JSON in `data/dataset_stats.json`.

---

## 🔧 Main API / API principale

```python
from collector import download

# Download a specific sample / Scarica un sample specifico
path = download.download_sample("sha256hash...", "collector/malware_samples")

# Collect up to 50 PE samples / Colleziona fino a 50 sample PE
download.collect_dataset(50, file_type="exe")

# Compute statistics on the collected dataset / Calcola statistiche sul dataset raccolto
stats = download.dataset_stats()
print(stats["totals"])
```

---

## 🚀 CLI

The module can also be run from the command line:  
Il modulo può essere eseguito anche da riga di comando:

```bash
python collector/download.py --help
```

### Options / Opzioni

- **Download dataset / Scaricare dataset**:
  ```bash
  python collector/download.py --target 100 --file-type exe
  ```
  Downloads up to 100 Windows executables (`.exe`) and saves them in `SAMPLES_DIR`.  
  Scarica fino a 100 eseguibili Windows (`.exe`) e li salva in `SAMPLES_DIR`.

- **Compute statistics / Calcolare statistiche**:
  ```bash
  python collector/download.py --stats-only
  ```
  Generates `data/dataset_stats.json` with updated statistics.  
  Genera `data/dataset_stats.json` con statistiche aggiornate.

---

## 📝 Operational Notes / Note operative

- Requires a **MalwareBazaar API key** in `.env`:  
  Richiede una **API key di MalwareBazaar** in `.env`:
  ```
  MALWAREBAZAAR_API_KEY=your_api_key_here
  ```
- Uses `pyzipper` to extract encrypted compressed files.  
  Per estrarre file compressi cifrati usa `pyzipper`.
- Some optional dependencies improve validation:  
  Alcune dipendenze opzionali migliorano la validazione:
  - `pefile` → verifies PE structure and architecture.  
    `pefile` → verifica struttura PE e architettura.
  - `python-magic` → identifies binaries via MIME signature.  
    `python-magic` → identifica file binari via signature MIME.
- Invalid samples are discarded and not counted toward the target.  
  I sample non validi vengono scartati senza contare nel target.
- Temporary `.bin` files are always removed after validation (avoids clutter).  
  File temporanei `.bin` vengono sempre rimossi dopo la validazione (evita spazzatura).

---

© 2025 — Gregorio Garofalo
