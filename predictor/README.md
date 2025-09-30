# Predictor Module

The `predictor/` package provides feature engineering, training pipeline, and inference engine for SMAAF's ML classifier.  
The PE features and numeric schema are compatible with legacy datasets, allowing reuse of existing corpora.

Il pacchetto `predictor/` fornisce feature engineering, pipeline di training e motore di inferenza per il classificatore ML di SMAAF.  
Le feature PE e lo schema numerico sono compatibili con dataset legacy così da poter riutilizzare corpora già esistenti.

---

## Expected Dataset / Dataset atteso
The trainer works on two parallel directories containing Windows PE samples (uncompressed):  
Il trainer lavora su due directory parallele contenenti campioni Windows PE (non compressi):
```
<repo-root>/
├── samples/malicious/   # malicious executables / eseguibili malevoli
└── samples/benign/      # benign executables / eseguibili benigni
```
Paths can be customized via CLI options `--malicious-dir` and `--benign-dir`.  
I percorsi possono essere personalizzati con le opzioni CLI `--malicious-dir` e `--benign-dir`.

---

## Dependencies / Dipendenze
Run once / Esegui una sola volta:
```bash
pip install -r requirements.txt
```
Required: `numpy`, `scikit-learn`, `joblib`, `pefile`, `python-magic`.  
Sono richiesti `numpy`, `scikit-learn`, `joblib`, `pefile` e `python-magic`.

---

## Training / Addestramento
```bash
python cli.py train-predictor   --malicious-dir samples/malicious   --benign-dir samples/benign   --output-dir predictor_artifacts
```

Useful options / Opzioni utili:
| Option / Opzione | Default | Description / Descrizione |
| --- | --- | --- |
| `--max-samples` | `None` | Limits number of executables processed (useful for quick tests). / Limita il numero di eseguibili processati (utile per test rapidi). |
| `--persist-raw-features/--no-persist-raw-features` | `True` | Save/avoid saving raw features JSON. / Salva/evita il JSON delle feature raw. |
| `--test-size` | `0.2` | Percentage of dataset reserved for test set. / Percentuale del dataset riservata al test set. |
| `--random-state` | `42` | Deterministic seed for train/test. / Seed deterministico per train/test. |

### Output
Artifacts are saved in `--output-dir` (default `predictor_artifacts/`):  
Gli artefatti vengono salvati in `--output-dir` (default `predictor_artifacts/`):
* `predictor_model.joblib` – `StandardScaler + RandomForest` pipeline ready for inference.  
  Pipeline `StandardScaler + RandomForest` pronta per l’inferenza.
* `training_summary.json` – metrics, confusion matrix, dataset details.  
  Metriche, confusion matrix, dettagli dataset.
* `ml_vectors.bin` + `ml_index.jsonl` – `float32` vector archive compatible with historical format.  
  Archivio vettori `float32` compatibile con il formato storico.
* `features/<sha256>.json` – raw features (if option enabled).  
  Feature raw (se l’opzione è abilitata).

---

## Inference / Inferenza
```bash
python cli.py predict <sha256>   --model-path predictor_artifacts/predictor_model.joblib   --threshold 0.5
```
The command resolves the sample path, extracts features, and updates `artifacts/<sha256>.json` with label, probabilities, threshold, and confidence percentage.  
Il comando risolve il percorso del sample, estrae le feature e aggiorna `artifacts/<sha256>.json` con label, probabilità, soglia e percentuale di confidenza.

The full pipeline (`pipeline`/`pipeline-all`) automatically runs the model between assemble and IOC phases.  
La pipeline completa (`pipeline`/`pipeline-all`) esegue automaticamente il modello tra la fase di assemblaggio e quella IOC.

### Programmatic Usage / Uso programmatico
```python
from pathlib import Path
from predictor import PredictorEngine

engine = PredictorEngine(model_path="predictor_artifacts/predictor_model.joblib")
result = engine.predict(Path("samples/<sha256>.exe"))
print(result["label"], result["score"], result["probabilities"])
```

---

## Webapp Integration / Integrazione webapp
The Flask webapp loads `PredictorEngine` at first request using the same environment variables as the CLI (`SMAAF_PREDICTOR_MODEL`, `SMAAF_PREDICT_THRESHOLD`).  
La webapp Flask carica `PredictorEngine` alla prima richiesta utilizzando le stesse variabili d’ambiente della CLI (`SMAAF_PREDICTOR_MODEL`, `SMAAF_PREDICT_THRESHOLD`).

During upload, the pipeline executes in order:  
Durante l’upload la pipeline esegue in ordine:
1. Radare2 analysis. / Analisi Radare2.
2. ML prediction and confidence saving. / Predizione ML e salvataggio confidenza.
3. IOC/YARA extraction. / Estrazione IOC/YARA.
4. Report generation (HTML/PDF) and structured JSON export. / Generazione report HTML/PDF e export JSON strutturati.

---

## Model Update / Aggiornamento del modello
1. Collect new benign/malicious samples. / Raccogli nuovi sample benigni/malevoli.
2. Run `train-predictor` pointing to updated directories. / Esegui `train-predictor` puntando alle directory aggiornate.
3. Distribute `predictor_model.joblib`, `training_summary.json`, and optionally `ml_vectors.bin`/`ml_index.jsonl` to analysis workstations.  
   Distribuisci `predictor_model.joblib`, `training_summary.json` e (se utile) `ml_vectors.bin`/`ml_index.jsonl` sulle postazioni di analisi.
4. Restart CLI/webapp to automatically load the new model.  
   Riavvia CLI/webapp per caricare automaticamente il nuovo modello.

© 2025 — Gregorio Garofalo
