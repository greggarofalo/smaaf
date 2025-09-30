# Predictor Module

Il pacchetto `predictor/` fornisce feature engineering, pipeline di training e
motore di inferenza per il classificatore ML di SMAAF. Le feature PE e lo schema
numerico sono compatibili con dataset legacy così da poter riutilizzare corpora
già esistenti.

---

## Dataset atteso
Il trainer lavora su due directory parallele contenenti campioni Windows PE
(non compressi):
```
<repo-root>/
├── samples/malicious/   # eseguibili malevoli
└── samples/benign/      # eseguibili benigni
```
I percorsi possono essere personalizzati con le opzioni CLI `--malicious-dir`
 e `--benign-dir`.

---

## Dipendenze
Esegui una sola volta:
```bash
pip install -r requirements.txt
```
Sono richiesti `numpy`, `scikit-learn`, `joblib`, `pefile` e `python-magic`.

---

## Addestramento
```bash
python cli.py train-predictor \
  --malicious-dir samples/malicious \
  --benign-dir samples/benign \
  --output-dir predictor_artifacts
```

Opzioni utili:
| Opzione | Default | Descrizione |
| --- | --- | --- |
| `--max-samples` | `None` | Limita il numero di eseguibili processati (utile per test rapidi). |
| `--persist-raw-features/--no-persist-raw-features` | `True` | Salva/evita il JSON delle feature raw. |
| `--test-size` | `0.2` | Percentuale del dataset riservata al test set. |
| `--random-state` | `42` | Seed deterministico per train/test. |

### Output
Gli artefatti vengono salvati in `--output-dir` (default `predictor_artifacts/`):
* `predictor_model.joblib` – pipeline `StandardScaler + RandomForest` pronta per
  l’inferenza.
* `training_summary.json` – metriche, confusion matrix, dettagli dataset.
* `ml_vectors.bin` + `ml_index.jsonl` – archivio vettori `float32` compatibile
  con il formato storico.
* `features/<sha256>.json` – feature raw (se l’opzione è abilitata).

---

## Inferenza
```bash
python cli.py predict <sha256> \
  --model-path predictor_artifacts/predictor_model.joblib \
  --threshold 0.5
```
Il comando risolve il percorso del sample, estrae le feature e aggiorna
`artifacts/<sha256>.json` con label, probabilità, soglia e percentuale di
confidenza.

La pipeline completa (`pipeline`/`pipeline-all`) esegue automaticamente il
modello tra la fase di assemblaggio e quella IOC.

### Uso programmatico
```python
from pathlib import Path
from predictor import PredictorEngine

engine = PredictorEngine(model_path="predictor_artifacts/predictor_model.joblib")
result = engine.predict(Path("samples/<sha256>.exe"))
print(result["label"], result["score"], result["probabilities"])
```

---

## Integrazione webapp
La webapp Flask carica `PredictorEngine` alla prima richiesta utilizzando le
stesse variabili d’ambiente della CLI (`SMAAF_PREDICTOR_MODEL`,
`SMAAF_PREDICT_THRESHOLD`). Durante l’upload la pipeline esegue in ordine:
1. Analisi Radare2.
2. Predizione ML e salvataggio confidenza.
3. Estrazione IOC/YARA.
4. Generazione report HTML/PDF e export JSON strutturati.

---

## Aggiornamento del modello
1. Raccogli nuovi sample benigni/malevoli.
2. Esegui `train-predictor` puntando alle directory aggiornate.
3. Distribuisci `predictor_model.joblib`, `training_summary.json` e (se utile)
   `ml_vectors.bin`/`ml_index.jsonl` sulle postazioni di analisi.
4. Riavvia CLI/webapp per caricare automaticamente il nuovo modello.

© 2025 — Gregorio Garofalo
