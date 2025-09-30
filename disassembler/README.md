# Modulo `r2_scan.py` — Batch Disassembler e Feature Extractor

## Introduzione
Il modulo `r2_scan.py` implementa la fase di **disassemblaggio e feature extraction** per campioni binari
utilizzando **Radare2** tramite `r2pipe`. Questo componente costituisce la base del framework di analisi statica,
fornendo una rappresentazione normalizzata in JSON e ASM di ciascun sample.

---

## Obiettivi progettuali
- Automatizzare il disassemblaggio di eseguibili (Windows PE in primis).
- Estrarre feature strutturate utili a successive fasi di analisi (IOC, YARA, reporting).
- Garantire **idempotenza**: se l’output esiste già, il sample non viene riesaminato.
- Fornire output coerenti e uniformi:
  - `disassembler/disassembled/json/<sha256>.json`
  - `disassembler/disassembled/asm/<sha256>.asm`
- Arricchire i metadati con hash, entropia, sezioni PE e hint da packer.

---

## Architettura del modulo

### 1. Raccolta campioni
La funzione `collect_candidates_recursive()` scandisce ricorsivamente la cartella `SAMPLES_DIR`, 
riconoscendo file eseguibili validi tramite estensione, `python-magic` e opzionalmente `pefile`.

### 2. Analisi con Radare2
La funzione principale `analyze_with_r2(path)`:
- Esegue `aaa` (analisi automatica) su Radare2.
- Estrae informazioni:
  - Architettura, formato, entrypoint.
  - Import/Export.
  - Strings (≥ 4 caratteri).
  - Funzioni con relativo flusso di istruzioni.
  - Istogramma mnemonici.
- Genera ASM testuale annotato per ciascuna funzione.

### 3. Enrichment PE
Con `pefile`, quando disponibile:
- `pe_meta`: machine, subsystem, compile_time.
- `imphash` e `rich_header_md5`.
- Presenza di firme Authenticode.
- Dimensione overlay e TLS callbacks.
- Entropia delle sezioni + hint packer (UPX, Themida, ecc.).

### 4. Output
La funzione `write_outputs()` salva:
- JSON strutturato con tutte le feature.
- ASM testuale.
- Aggiornamento di `metadata.csv` con campi:
  - `filename, sha256, md5, arch, bits, filesize, timestamp`

---

## Criteri di robustezza
- **Entropia** calcolata a chunk (default 1MB) per scalare su file grandi.
- **Idempotenza**: skip dei campioni già analizzati.
- **Gestione errori**: errori in Radare2 o `pefile` non bloccano la pipeline.
- **Limite artificiale su funzioni**: configurabile via `R2_MAX_FUN_OPS` per prevenire disassemblaggio infinito su funzioni offuscate.
- **Warning ASM vuoto**: log dedicato se nessuna funzione viene disassemblata.

---

## Output JSON — Struttura principale
```json
{
  "path": "...",
  "sha256": "...",
  "md5": "...",
  "info": {
    "arch": "x86",
    "bits": 32,
    "format": "pe",
    "endian": "little",
    "entrypoint": "0x401000"
  },
  "imports": [...],
  "exports": [...],
  "sections": [...],
  "strings": [...],
  "functions": [...],
  "mnemonics_hist": {...},
  "entropy_file": 6.87,
  "asm_text": "...",
  "pe_meta": {...},
  "imphash": "...",
  "rich_header_md5": "...",
  "signed": false,
  "overlay_size": 4096,
  "tls_callbacks": [...],
  "packer_hints": [...]
}
```

---

## Valore accademico
Questo modulo permette di:
- Studiare la correlazione tra caratteristiche binarie (entropia, API, sezioni) e tipologie di malware.
- Fornire dataset strutturati per pipeline di Machine Learning o euristiche di scoring.
- Evidenziare indicatori di offuscamento (overlay, packer hints) e firme digitali.

---

## Conclusione
Il modulo `r2_scan.py` costituisce un **pilastro centrale** del framework di analisi,
producendo una rappresentazione ricca e normalizzata dei campioni binari.  
Tale rappresentazione alimenta i successivi moduli di **estrazione IOC**, **scansione YARA** e **reporting**,
consentendo uno studio accurato delle caratteristiche statiche dei malware.
