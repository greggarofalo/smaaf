# Analyzer Module — IOC Extraction & YARA Correlation

The `analyzer/` package enriches a static sample with Indicators of Compromise (IoCs), correlation with threat intelligence feeds, YARA results, and signals useful for reporting.

Il package `analyzer/` arricchisce un campione statico con Indicatori di Compromissione, correlazione con feed di threat intelligence, risultati YARA e segnali utili al reporting.

---

## Architecture / Architettura
```
analyzer/
├── ioc/
│   ├── common.py          # utilities (HTTP, cache, subprocess) / utility (HTTP, cache, subprocess)
│   ├── extraction.py      # string normalization → IOC / normalizzazione stringhe → IOC
│   ├── feeds.py           # URLhaus/Feodo feeds / feed URLhaus/Feodo
│   ├── orchestrator.py    # end-to-end coordination / coordinamento end-to-end
│   ├── scanner.py         # YARA execution / esecuzione YARA
│   ├── static_loader.py   # static artifact loading / lettura artefatti statici
│   └── yara_sources.py    # YARA rules download & cache / download e cache delle regole YARA
├── ioc_signatures.py      # legacy compat layer / compat layer storico
└── README.md
```
Main API / API principale:
```python
from analyzer.ioc import extract_iocs_and_yara
result = extract_iocs_and_yara(sha256)
```

---

## TI & YARA Sources / Fonti TI e YARA
Feeds are downloaded and cached.  
I feed vengono scaricati e memorizzati in cache.

* **YARA**
  * [HydraDragonAntivirus/hydradragon/yara](https://github.com/HydraDragonAntivirus/HydraDragonAntivirus)
  * [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)
  * [Yara-Rules/rules](https://github.com/Yara-Rules/rules) (Windows subset / subset Windows)
  * Optional support for YARA-Forge bundle (`YARAFORGE_ZIP_URL`).  
    Supporto opzionale a bundle YARA-Forge (`YARAFORGE_ZIP_URL`).

* **IOC**
  * URLhaus (CSV “online” dump)  
    URLhaus (dump CSV “online”)
  * Feodo Tracker (C2 IP list)  
    Feodo Tracker (lista IP C2)

`YARA_SOURCES`, `YARARULES_INCLUDE_GLOBS`, `IOC_CACHE_DIR`, `SAFE_DOMAINS` are configurable via environment variables.  
`YARA_SOURCES`, `YARARULES_INCLUDE_GLOBS`, `IOC_CACHE_DIR`, `SAFE_DOMAINS` sono configurabili via variabili d’ambiente.

---

## Local IOC Extraction / Estrazione locale IOC
`extraction.py` performs refang, normalization, and deduplication of:  
`extraction.py` esegue refang, normalizzazione e deduplicazione di:
* URLs/domains (with IDNA support + Tranco/safelist filter)  
  URL/domìni (con supporto IDNA + filtro Tranco/safelist)
* IPv4/IPv6 (public addresses only)  
  IPv4/IPv6 (solo indirizzi pubblici)
* Emails, registry keys, Windows paths, hashes (MD5/SHA-256)  
  Email, registry keys, percorsi Windows, hash (MD5/SHA-256)
* Suspicious APIs extracted from import tables  
  API sospette ricavate dalle tabelle import

“Confirmed” and “suspected” lists are computed, with the latter based on safelist and Tranco ranking to reduce false positives.  
Vengono calcolate liste “confirmed” e “suspected”, quest’ultime basate su safelist e ranking Tranco per ridurre i falsi positivi.

---

## Correlation & Signals / Correlazione & segnali
`orchestrator.py` coordinates the entire phase:  
`orchestrator.py` coordina l’intera fase:
1. Load static artifact. / Caricamento artefatto statico.
2. Extract local IoCs. / Estrazione IOC locali.
3. Compile YARA bundle (with per-file fallback if `yarac` is unavailable). / Compilazione bundle YARA (con fallback per-file se `yarac` non è disponibile).
4. Run YARA scan and collect significant warnings. / Scansione YARA e raccolta warning significativi.
5. Correlate with TI feeds and normalize indicators. / Correlazione con feed TI e normalizzazione indicatori.
6. Retrieve ML verdict saved in the artifact to compute confidence. / Recupero del verdetto ML salvato nell’artefatto per calcolare la confidenza.

### Output
The orchestrator returns a dictionary with keys `iocs`, `signatures`, `stats`, and `report_ready`.  
L’orchestratore restituisce un dizionario con chiavi `iocs`, `signatures`, `stats` e `report_ready`.

The latter is ready to be serialized into reports. Example:  
Quest’ultimo è già pronto per essere serializzato nei report. Esempio:
```json
{
  "summary": ["ML classifier: malicious verdict (confidence 96.4%)"],
  "confidence": {
    "label": "malicious",
    "score": 0.964,
    "threshold": 0.5,
    "confidence": 96.4
  },
  "signals": ["ml_verdict_malicious", "ioc_confirmed_by_ti"],
  "intel_overview": {
    "confirmed": {"domains": ["evil.example"], "ips": [], "urls": []},
    "suspected": {"domains": [], "ips": [], "urls": []},
    "sources": {"urlhaus": "https://urlhaus.abuse.ch/...", "feodo": "https://feodotracker.abuse.ch..."}
  },
  "notable_iocs": {
    "filesystem": ["C:/Users/Public/payload.exe"],
    "public_ipv4": ["203.0.113.10"],
    "suspicious_apis": ["CreateRemoteThread", "WriteProcessMemory"]
  },
  "detection": {
    "yara_hits": ["APT_Family_Rule"],
    "yara_weak_only": false,
    "rules_cached": 1875,
    "yara_compile_warnings": []
  }
}
```

YARA warnings related only to performance or deprecated notes are filtered and do not pollute the final report.  
I warning YARA legati esclusivamente a performance o note deprecate vengono filtrati e non inquinano il report finale.

---

## Quick Configuration / Configurazione rapida
| Variable / Variabile | Default | Description / Descrizione |
| --- | --- | --- |
| `YARA_SOURCES` | `hydra,neo23x0,yararules` | Enabled YARA sources / Sorgenti YARA abilitate |
| `YARA_CACHE_DIR` | `.yaracache` | YARA bundle cache / Cache bundle YARA |
| `YARA_UPDATE_SECS` | `86400` | Rule refresh frequency / Frequenza refresh regole |
| `IOC_CACHE_DIR` | `.iocache` | IOC feed cache / Cache feed IOC |
| `IOC_UPDATE_SECS` | `21600` | Feed refresh frequency / Frequenza refresh feed |
| `SAFE_DOMAINS` / `SAFE_DOMAINS_FILE` | – | Additional safelist / Safelist aggiuntiva |
| `TRANCO_LIST_DATE` | latest available / ultimo disponibile | Tranco list to use / Lista Tranco da utilizzare |

---

## Artifacts / Artefatti
The result of `extract_iocs_and_yara` is serialized into `artifacts/<sha>.json` and consumed by the reporting engine (HTML/PDF and structured JSON).  
Il risultato di `extract_iocs_and_yara` viene serializzato in `artifacts/<sha>.json` e consumato dal motore di reporting (HTML/PDF e JSON strutturato).

---

© 2025 — Gregorio Garofalo
