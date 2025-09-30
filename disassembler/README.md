# Module `r2_scan.py` — Batch Disassembler and Feature Extractor

## Introduction / Introduzione
The `r2_scan.py` module implements the **disassembly and feature extraction** phase for binary samples using **Radare2** via `r2pipe`.  
This component is the foundation of the static analysis framework, providing a normalized JSON and ASM representation of each sample.

Il modulo `r2_scan.py` implementa la fase di **disassemblaggio e feature extraction** per campioni binari utilizzando **Radare2** tramite `r2pipe`.  
Questo componente costituisce la base del framework di analisi statica, fornendo una rappresentazione normalizzata in JSON e ASM di ciascun sample.

---

## Design Goals / Obiettivi progettuali
- Automate disassembly of executables (primarily Windows PE).  
  Automatizzare il disassemblaggio di eseguibili (Windows PE in primis).
- Extract structured features useful for later analysis phases (IOC, YARA, reporting).  
  Estrarre feature strutturate utili a successive fasi di analisi (IOC, YARA, reporting).
- Guarantee **idempotency**: if the output already exists, the sample is not reprocessed.  
  Garantire **idempotenza**: se l’output esiste già, il sample non viene riesaminato.
- Provide consistent, uniform outputs:  
  Fornire output coerenti e uniformi:
  - `disassembler/disassembled/json/<sha256>.json`
  - `disassembler/disassembled/asm/<sha256>.asm`
- Enrich metadata with hashes, entropy, PE sections, and packer hints.  
  Arricchire i metadati con hash, entropia, sezioni PE e hint da packer.

---

## Module Architecture / Architettura del modulo

### 1. Sample Collection / Raccolta campioni
The function `collect_candidates_recursive()` recursively scans `SAMPLES_DIR`, identifying valid executables via extension, `python-magic`, and optionally `pefile`.  
La funzione `collect_candidates_recursive()` scandisce ricorsivamente la cartella `SAMPLES_DIR`, riconoscendo file eseguibili validi tramite estensione, `python-magic` e opzionalmente `pefile`.

### 2. Radare2 Analysis / Analisi con Radare2
The main function `analyze_with_r2(path)`:
- Executes `aaa` (automatic analysis) in Radare2.  
  Esegue `aaa` (analisi automatica) su Radare2.
- Extracts information:  
  Estrae informazioni:
  - Architecture, format, entrypoint. / Architettura, formato, entrypoint.
  - Imports/Exports. / Import/Export.
  - Strings (≥ 4 characters). / Strings (≥ 4 caratteri).
  - Functions with instruction flow. / Funzioni con relativo flusso di istruzioni.
  - Mnemonic histogram. / Istogramma mnemonici.
- Generates annotated textual ASM per function.  
  Genera ASM testuale annotato per ciascuna funzione.

### 3. PE Enrichment / Enrichment PE
With `pefile`, when available:  
Con `pefile`, quando disponibile:
- `pe_meta`: machine, subsystem, compile_time.  
- `imphash` and `rich_header_md5`.  
- Presence of Authenticode signatures. / Presenza di firme Authenticode.
- Overlay size and TLS callbacks. / Dimensione overlay e TLS callbacks.
- Section entropy + packer hints (UPX, Themida, etc.).  
  Entropia delle sezioni + hint packer (UPX, Themida, ecc.).

### 4. Output
The function `write_outputs()` saves:  
La funzione `write_outputs()` salva:
- Structured JSON with all features. / JSON strutturato con tutte le feature.
- Textual ASM. / ASM testuale.
- Updates `metadata.csv` with fields: / Aggiornamento di `metadata.csv` con campi:
  - `filename, sha256, md5, arch, bits, filesize, timestamp`

---

## Robustness Criteria / Criteri di robustezza
- **Entropy** computed in chunks (default 1MB) to scale on large files.  
  **Entropia** calcolata a chunk (default 1MB) per scalare su file grandi.
- **Idempotency**: skips already analyzed samples.  
  **Idempotenza**: skip dei campioni già analizzati.
- **Error handling**: Radare2 or `pefile` errors do not block the pipeline.  
  **Gestione errori**: errori in Radare2 o `pefile` non bloccano la pipeline.
- **Artificial function limit**: configurable via `R2_MAX_FUN_OPS` to prevent infinite disassembly on obfuscated functions.  
  **Limite artificiale su funzioni**: configurabile via `R2_MAX_FUN_OPS` per prevenire disassemblaggio infinito su funzioni offuscate.
- **Empty ASM warning**: dedicated log if no functions are disassembled.  
  **Warning ASM vuoto**: log dedicato se nessuna funzione viene disassemblata.

---

## JSON Output — Main Structure / Output JSON — Struttura principale
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

## Academic Value / Valore accademico
This module allows:  
Questo modulo permette di:
- Studying correlation between binary characteristics (entropy, APIs, sections) and malware families.  
  Studiare la correlazione tra caratteristiche binarie (entropia, API, sezioni) e tipologie di malware.
- Providing structured datasets for Machine Learning pipelines or heuristic scoring.  
  Fornire dataset strutturati per pipeline di Machine Learning o euristiche di scoring.
- Highlighting obfuscation indicators (overlay, packer hints) and digital signatures.  
  Evidenziare indicatori di offuscamento (overlay, packer hints) e firme digitali.

---

## Conclusion / Conclusione
The `r2_scan.py` module is a **central pillar** of the analysis framework, producing a rich, normalized representation of binary samples.  
Il modulo `r2_scan.py` costituisce un **pilastro centrale** del framework di analisi, producendo una rappresentazione ricca e normalizzata dei campioni binari.

This representation powers subsequent modules for **IOC extraction**, **YARA scanning**, and **reporting**, enabling detailed study of malware static characteristics.  
Tale rappresentazione alimenta i successivi moduli di **estrazione IOC**, **scansione YARA** e **reporting**, consentendo uno studio accurato delle caratteristiche statiche dei malware.
