# collector/download.py — MalwareBazaar Sample Collector

Questo modulo implementa un **collettore di sample** da [MalwareBazaar](https://bazaar.abuse.ch/).  
Serve a scaricare binari malevoli (eseguibili Windows/PE), verificarne la validità ed estrarre metadati, salvandoli localmente.

---

## 📦 Funzionalità principali

- **Raccolta sample** da MalwareBazaar:
  - `fetch_hashes_by_type()` → ottiene hash recenti per un dato file_type (es. `exe`, `dll`, `pe`).
  - `download_sample()` → scarica un sample, lo estrae se compresso (ZIP con password `infected`), e lo valida.
  - `collect_dataset(target)` → popola `SAMPLES_DIR` fino al numero richiesto di binari validi.
- **Metadati**:
  - Calcolo hash (`sha256`, `md5`).
  - Architettura PE (`x86`, `x86_64`).
  - Presenza firma Authenticode.
  - Altri campi dall’API (file_name, file_type, file_size, signature, tags, clamav).
- **Salvataggio persistente**:
  - CSV unificato (`META_CSV`), aggiornato in modo incrementale e idempotente.
- **Statistiche dataset**:
  - `dataset_stats()` → produce un JSON con:
    - Totale sample,
    - Distribuzione per `signature` e `file_type`,
    - Statistiche sulle dimensioni (`min`, `p50`, `mean`, `p90`, `max`),
    - Intervallo temporale (`first`, `last`),
    - Media di sample raccolti al giorno (`avg_per_day`).

---

## 📂 Struttura file e directory

- **Samples** → salvati in `collector/malware_samples/` (`SAMPLES_DIR`).
- **Metadati** → CSV unico in `collector/metadata.csv` (`META_CSV`).
- **Statistiche** → JSON in `data/dataset_stats.json`.

---

## 🔧 API principale

```python
from collector import download

# Scarica un sample specifico
path = download.download_sample("sha256hash...", "collector/malware_samples")

# Colleziona fino a 50 sample PE
download.collect_dataset(50, file_type="exe")

# Calcola statistiche sul dataset raccolto
stats = download.dataset_stats()
print(stats["totals"])
```

---

## 🚀 CLI

Il modulo può essere eseguito anche da riga di comando:

```bash
python collector/download.py --help
```

### Opzioni

- **Scaricare dataset**:
  ```bash
  python collector/download.py --target 100 --file-type exe
  ```
  Scarica fino a 100 eseguibili Windows (`.exe`) e li salva in `SAMPLES_DIR`.

- **Calcolare statistiche**:
  ```bash
  python collector/download.py --stats-only
  ```
  Genera `data/dataset_stats.json` con statistiche aggiornate.

---

## 📝 Note operative

- Richiede una **API key di MalwareBazaar** in `.env`:
  ```
  MALWAREBAZAAR_API_KEY=your_api_key_here
  ```
- Per estrarre file compressi cifrati usa `pyzipper`.
- Alcune dipendenze opzionali migliorano la validazione:
  - `pefile` → verifica struttura PE e architettura.
  - `python-magic` → identifica file binari via signature MIME.
- I sample non validi vengono scartati senza contare nel target.
- File temporanei `.bin` vengono sempre rimossi dopo la validazione (evita spazzatura).

---

© 2025 — Gregorio Garofalo
