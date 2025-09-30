# Analyzer Module — IOC Extraction & YARA Correlation

Il package `analyzer/` arricchisce un campione statico con Indicatori di
Compromissione, correlazione con feed di threat intelligence, risultati YARA e
segnali utili al reporting.

---

## Architettura
```
analyzer/
├── ioc/
│   ├── common.py          # utility (HTTP, cache, subprocess)
│   ├── extraction.py      # normalizzazione stringhe → IOC
│   ├── feeds.py           # feed URLhaus/Feodo
│   ├── orchestrator.py    # coordinamento end-to-end
│   ├── scanner.py         # esecuzione YARA
│   ├── static_loader.py   # lettura artefatti statici
│   └── yara_sources.py    # download e cache delle regole YARA
├── ioc_signatures.py      # compat layer storico
└── README.md
```
API principale:
```python
from analyzer.ioc import extract_iocs_and_yara
result = extract_iocs_and_yara(sha256)
```

---

## Fonti TI e YARA
I feed vengono scaricati e memorizzati in cache.
* **YARA**
  * [HydraDragonAntivirus/hydradragon/yara](https://github.com/HydraDragonAntivirus/HydraDragonAntivirus)
  * [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base)
  * [Yara-Rules/rules](https://github.com/Yara-Rules/rules) (subset Windows)
  * Supporto opzionale a bundle YARA-Forge (`YARAFORGE_ZIP_URL`).
* **IOC**
  * URLhaus (dump CSV “online”)
  * Feodo Tracker (lista IP C2)

`YARA_SOURCES`, `YARARULES_INCLUDE_GLOBS`, `IOC_CACHE_DIR`, `SAFE_DOMAINS` sono
configurabili via variabili d’ambiente.

---

## Estrazione locale IOC
`extraction.py` esegue refang, normalizzazione e deduplicazione di:
* URL/domìni (con supporto IDNA + filtro Tranco/safelist)
* IPv4/IPv6 (solo indirizzi pubblici)
* Email, registry keys, percorsi Windows, hash (MD5/SHA-256)
* API sospette ricavate dalle tabelle import

Vengono calcolate liste “confirmed” e “suspected”, quest’ultime basate su
safelist e ranking Tranco per ridurre i falsi positivi.

---

## Correlazione & segnali
`orchestrator.py` coordina l’intera fase:
1. Caricamento artefatto statico.
2. Estrazione IOC locali.
3. Compilazione bundle YARA (con fallback per-file se `yarac` non è disponibile).
4. Scansione YARA e raccolta warning significativi.
5. Correlazione con feed TI e normalizzazione indicatori.
6. Recupero del verdetto ML salvato nell’artefatto per calcolare la confidenza.

### Output
L’orchestratore restituisce un dizionario con chiavi `iocs`, `signatures`,
`stats` e `report_ready`. Quest’ultimo è già pronto per essere serializzato nei
report. Esempio semplificato:
```json
{
  "summary": ["Classificatore ML: verdetto malicious (confidenza 96.4%)"],
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
    "sources": {"urlhaus": "https://urlhaus.abuse.ch/...", "feodo": "https://feodotracker.abuse.ch/..."}
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

I warning YARA legati esclusivamente a performance o note deprecate vengono
filtrati e non inquinano il report finale.

---

## Configurazione rapida
| Variabile | Default | Descrizione |
| --- | --- | --- |
| `YARA_SOURCES` | `hydra,neo23x0,yararules` | Sorgenti YARA abilitate |
| `YARA_CACHE_DIR` | `.yaracache` | Cache bundle YARA |
| `YARA_UPDATE_SECS` | `86400` | Frequenza refresh regole |
| `IOC_CACHE_DIR` | `.iocache` | Cache feed IOC |
| `IOC_UPDATE_SECS` | `21600` | Frequenza refresh feed |
| `SAFE_DOMAINS` / `SAFE_DOMAINS_FILE` | – | Safelist aggiuntiva |
| `TRANCO_LIST_DATE` | ultimo disponibile | Lista Tranco da utilizzare |

---

## Artefatti
Il risultato di `extract_iocs_and_yara` viene serializzato in
`artifacts/<sha>.json` e consumato dal motore di reporting (HTML/PDF e JSON
strutturato).

© 2025 — Gregorio Garofalo
