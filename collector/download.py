# collector/download.py
# -*- coding: utf-8 -*-
"""
MalwareBazaar Sample Collector (semplificato, unica cartella SAMPLES_DIR).

Funzioni:
- `fetch_hashes_by_type(limit)` → ultimi hash (batch)
- `download_sample(sha, dest_dir)` → salva binario (riconoscimento ZIP, libmagic)
- `collect_dataset(target)` → popola un'unica cartella fino al numero richiesto
- `dataset_stats()` → statistiche sul dataset unico

Note:
- Se un candidato non è binario → skip (NON conta ai fini del target).
- Scrive metadata in un CSV unico (META_CSV).
"""

import argparse
import csv
import hashlib
import logging
import os
import time
from datetime import datetime, timezone
from typing import Dict, Optional, Set, Tuple, List, Any
import pyzipper
import requests
import json

try:
    import pefile
    _pefile = True
except ImportError:  # pragma: no cover
    _pefile = False


try:
    import magic
    _magic = True
except ImportError:  # pragma: no cover
    logging.warning("python-magic mancante: filtro binarietà basato solo sull'estensione.")
    _magic = False

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

from core.settings import (
    MALWAREBAZAAR_API_KEY as API_KEY,
    ROOT, SAMPLES_DIR, META_CSV
)


BASE_URL      = "https://mb-api.abuse.ch/api/v1/"
PASSWORD      = b"infected"
RATE_DELAY    = 1.2   # throttling anti-ban
BATCH_LIMIT   = 100   # n hash per chiamata (affidabile per l'API)
_MAX_IDLE_LOOPS = 300 # safety cap per evitare loop infiniti
TYPE_LIMIT_MAX = 100   # get_file_type: massimo per richiesta
# Estensioni PE comuni (Windows)
_BIN_EXTS = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".drv", ".msi"}

# Default corretto per MalwareBazaar Windows (vedi log: file_type='exe')
DEFAULT_FILE_TYPE = "exe"

USER_AGENT = "StaticMAF-Collector/1.0 (+academic; Windows-PE)"


# ────────────────────────────────────── utils
def is_binary_file(path: str) -> bool:
    """
    Ritorna True se `path` è verosimilmente un PE valido.
    Priorità: estensione → pefile (se presente) → python-magic → False.
    """
    ext = os.path.splitext(path)[1].lower()

    # Fast-path su estensioni PE
    if ext in _BIN_EXTS:
        if _pefile:
            try:
                p = pefile.PE(path, fast_load=True)
                # Un PE sensato ha almeno una sezione
                return bool(getattr(p, "sections", []))
            except pefile.PEFormatError:
                return False
            except Exception:
                # incertezza: consideriamo comunque valido sul canale estensioni
                return True
        # senza pefile: accettiamo sulla base dell'estensione
        return True

    # Fallback: magic
    if _magic:
        try:
            ftype = magic.from_file(path, mime=False).lower()
            return ("portable executable" in ftype) or ("pe32" in ftype) or ("executable" in ftype)
        except Exception:
            return False

    return False


def pe_architecture(path: str) -> str:
    """
    Ritorna 'x86', 'x86_64' oppure hex(machine) / 'unknown'.
    """
    if not _pefile:
        return "unknown"
    try:
        p = pefile.PE(path, fast_load=True)
        machine = p.FILE_HEADER.Machine
        if machine == 0x14C:   # IMAGE_FILE_MACHINE_I386
            return "x86"
        if machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
            return "x86_64"
        return hex(machine)
    except Exception:
        return "unknown"
def has_authenticode_signature(path: str) -> bool:
    """
    True se il PE ha una directory di sicurezza (Authenticode presente).
    Non verifica la chain-of-trust; indica solo la presenza del blob PKCS#7.
    """
    if not _pefile:
        return False
    try:
        p = pefile.PE(path, fast_load=True)
        dd = p.OPTIONAL_HEADER.DATA_DIRECTORY
        # 4 = IMAGE_DIRECTORY_ENTRY_SECURITY
        entry = dd[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        return getattr(entry, "Size", 0) > 0
    except Exception:
        return False




def _sanitize_filename(name: str) -> str:
    return "".join(ch for ch in name if ch.isalnum() or ch in (".", "-", "_"))

import shutil  # assicurati di avere questo import in cima

def _safe_member_name(name: str) -> str:
    """
    Riduce il percorso interno allo ZIP al solo basename e lo sanifica.
    Esempio: 'DLLs/libcrypto-3.dll' -> 'libcrypto-3.dll' -> 'libcrypto-3.dll'
    """
    base = os.path.basename(name)
    return _sanitize_filename(base)

def extract_recursive(zip_path: str, dest: str, pwd: bytes = PASSWORD) -> Optional[str]:
    """
    Estrae ricorsivamente da uno ZIP cifrato finché non trova un binario PE valido.

    Policy:
    - Appiattisce sempre i percorsi interni (ignora sottocartelle).
    - NON cancella zip_path; chi la chiama decide la pulizia.
    - Se trova ZIP annidati, li salva con nome sanificato e ricorre.
    - Limite dimensione: 200MB per file estratto.
    - Restituisce il path del binario estratto, altrimenti None.
    """
    MAX_SIZE = 200 * 1024 * 1024  # 200 MB

    try:
        with pyzipper.AESZipFile(zip_path) as zf:
            zf.pwd = pwd
            members = [m for m in zf.infolist() if not m.is_dir()]
            if not members:
                return None

            for info in members:
                safe_name = _safe_member_name(info.filename)
                out_path = os.path.join(dest, safe_name)

                # Estrazione streaming → file piatto
                with zf.open(info, "r") as src, open(out_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)

                # Hard cap dimensione
                try:
                    if os.path.getsize(out_path) > MAX_SIZE:
                        os.remove(out_path)
                        continue
                except Exception:
                    pass

                # ZIP annidato?
                if out_path.lower().endswith(".zip"):
                    nested = extract_recursive(out_path, dest, pwd)
                    try: os.remove(out_path)
                    except Exception: pass
                    if nested:
                        logging.info(f"✓ Binario estratto: {nested}")
                        return nested
                    # altrimenti continua

                # Verifica binario PE
                if is_binary_file(out_path):
                    logging.info(f"✓ Binario estratto: {out_path}")
                    return out_path

                # Non binario → rimuovi
                try:
                    os.remove(out_path)
                except IsADirectoryError:
                    try:
                        shutil.rmtree(out_path)
                    except Exception:
                        pass
                except Exception:
                    pass

    except (pyzipper.BadZipFile, RuntimeError) as exc:
        logging.debug(f"Non ZIP valido {zip_path}: {exc}")
        return None
    except Exception as exc:
        logging.warning(f"Errore durante estrazione ZIP {zip_path}: {exc}")
        return None

    return None


def fetch_hashes_by_type(file_type: str = "pe", limit: int = TYPE_LIMIT_MAX) -> List[str]:
    """
    Ottiene fino a `limit` hash recenti per un certo file_type (es. 'pe').
    Ritorna una lista di SHA-256. Dedup a carico del chiamante.
    """
    if not API_KEY:
        logging.error("MALWAREBAZAAR_API_KEY non impostata.")
        return []
    if limit > TYPE_LIMIT_MAX:
        limit = TYPE_LIMIT_MAX  # l'API non consente oltre 1000

    headers = {"Auth-Key": API_KEY}
    data    = {"query": "get_file_type", "file_type": file_type, "limit": str(limit)}
    try:
        res = requests.post(BASE_URL, headers=headers, data=data, timeout=25)
        res.raise_for_status()
        j = res.json()
        if j.get("query_status") == "ok":
            return [item["sha256_hash"] for item in j.get("data", []) if "sha256_hash" in item]
        msg = j.get("query_status", "unknown")
        logging.warning(f"[get_file_type] Risposta: {msg}")
    except Exception as exc:  # pragma: no cover
        logging.error(f"Errore get_file_type({file_type}): {exc}")
    return []


def download_sample(sha256: str, dest_dir: str) -> Optional[str]:
    """
    Scarica il sample (zip cifrato o file raw) nella cartella di destinazione,
    prova ad estrarre ricorsivamente un binario PE e rimuove i wrapper SOLO se abbiamo un risultato.
    """
    headers = {"Auth-Key": API_KEY, "User-Agent": USER_AGENT}
    data    = {"query": "get_file", "sha256_hash": sha256}

    # piccoli timeout separati
    connect_to = 10
    read_to    = 30

    try:
        res = requests.post(
            BASE_URL, headers=headers, data=data,
            stream=True, timeout=(connect_to, read_to)
        )
        res.raise_for_status()

        os.makedirs(dest_dir, exist_ok=True)
        tmp_path = os.path.join(dest_dir, f"{sha256}.bin")

        with open(tmp_path, "wb") as fh:
            for chunk in res.iter_content(8192):
                if not chunk:
                    continue
                fh.write(chunk)

        # 1) Se è ZIP (o simil-zip), prova estrazione ricorsiva
        extracted = extract_recursive(tmp_path, str(dest_dir))
        if extracted:
            try:
                os.remove(tmp_path)
            except Exception:
                pass
            return extracted

        # 2) Fallback: se il wrapper stesso è un PE valido, tienilo
        if is_binary_file(tmp_path):
            logging.info(f"✓ Binario salvato: {tmp_path}")
            return tmp_path

        # 3) Niente di utile → pulizia
        logging.info(f"✗ {tmp_path} ignorato (non PE).")
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    except Exception as exc:  # pragma: no cover
        logging.error(f"Errore download {sha256}: {exc}")

    # cleanup extra: rimuovi sempre tmp_path se rimasto
    try:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    except Exception:
        pass

    return None


def calculate_hashes(path: str) -> Tuple[str, str]:
    sha256 = hashlib.sha256()
    md5    = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()

def fetch_sample_info(sha256: str) -> Dict:
    headers = {"Auth-Key": API_KEY}
    data    = {"query": "get_info", "hash": sha256}
    try:
        res = requests.post(BASE_URL, headers=headers, data=data, timeout=15)
        res.raise_for_status()
        j = res.json()
        if j.get("query_status") == "ok" and j.get("data"):
            return j["data"][0]
    except Exception as exc:  # pragma: no cover
        logging.warning(f"Metadati non disponibili per {sha256}: {exc}")
    return {}

def _append_row(csv_path: str, header: List[str], row: Dict) -> None:
    """
    Appende una riga a csv_path.
    - Se il file non esiste → scrive header (eventualmente esteso con nuovi campi).
    - Se esiste ma l'header è diverso → migra il file all'header nuovo (superset) preservando le righe.
    - Usa extrasaction="ignore" per ignorare eventuali chiavi extra non in header.
    """
    # Estendi header con eventuali chiavi presenti nella row (pe_arch/signed, ecc.)
    header_ext = header[:]
    for k in ("pe_arch", "signed"):
        if (k in row) and (k not in header_ext):
            header_ext.append(k)

    file_exists = os.path.isfile(csv_path)

    # Se il file esiste, controlla l'header attuale
    if file_exists:
        with open(csv_path, newline="", encoding="utf-8") as fh:
            try:
                rdr = csv.DictReader(fh)
                existing_header = list(rdr.fieldnames or [])
            except Exception:
                existing_header = []

        # Se l'header è diverso, migra al nuovo header (superset)
        if set(existing_header) != set(header_ext):
            # leggi tutte le righe esistenti
            with open(csv_path, newline="", encoding="utf-8") as fh:
                rdr = csv.DictReader(fh)
                old_rows = list(rdr)

            # riscrivi con header esteso
            with open(csv_path, "w", newline="", encoding="utf-8") as fw:
                w = csv.DictWriter(fw, fieldnames=header_ext, extrasaction="ignore")
                w.writeheader()
                for r in old_rows:
                    w.writerow(r)

    # Append della riga corrente con header_ext garantito
    # (se il file non esisteva, ora lo creiamo con header_ext)
    create_header = not file_exists
    if create_header:
        with open(csv_path, "w", newline="", encoding="utf-8") as fw:
            w = csv.DictWriter(fw, fieldnames=header_ext, extrasaction="ignore")
            w.writeheader()
            w.writerow(row)
    else:
        with open(csv_path, "a", newline="", encoding="utf-8") as fw:
            w = csv.DictWriter(fw, fieldnames=header_ext, extrasaction="ignore")
            w.writerow(row)


def save_metadata(row: Dict) -> None:
    base_header = [
        "filename", "sha256", "md5", "timestamp",
        "file_name", "file_type", "file_size", "signature", "tags", "clamav"
    ]
    _append_row(str(META_CSV), base_header, row)


# ────────────────────────────────────── dataset builder
def _load_existing_shas() -> Set[str]:
    """Raccoglie gli SHA già presenti nel metadata CSV unico."""
    out: Set[str] = set()
    if not os.path.isfile(META_CSV):
        return out
    with open(META_CSV, newline="") as fh:
        for row in csv.DictReader(fh):
            if row.get("sha256"):
                out.add(row["sha256"])
    return out

def collect_dataset(target: int, file_type: str = DEFAULT_FILE_TYPE) -> None:
    """
    Popola samples con eseguibili Windows (default: file_type='exe'),
    fino a raggiungere il target (binari validi)
    I candidati sono presi da query=get_file_type(file_type=...).
    """
    if not API_KEY:
        logging.critical("MALWAREBAZAAR_API_KEY non impostata.")
        return

    os.makedirs(SAMPLES_DIR, exist_ok=True)

    seen = _load_existing_shas()
    n = len(seen)
    logging.info(f"[dataset] Stato iniziale → samples={n}, type={file_type}")

    idle_loops = 0
    while n < target:
        if idle_loops > _MAX_IDLE_LOOPS:
            logging.error("[dataset] Troppi cicli senza progresso. Interrompo.")
            break

        cands = fetch_hashes_by_type(file_type=file_type, limit=TYPE_LIMIT_MAX)
        if not cands:
            logging.warning("[dataset] Nessun candidato da API. Attesa e retry…")
            time.sleep(5)
            idle_loops += 1
            continue

        progressed = False
        for sha in cands:
            if sha in seen:
                continue

            bin_path = download_sample(sha, str(SAMPLES_DIR))
            if not bin_path:
                continue

            sha256, md5 = calculate_hashes(bin_path)

            if sha256 in seen:
                try: os.remove(bin_path)
                except Exception: pass
                continue

            info = fetch_sample_info(sha)
            row = {
                "filename": os.path.basename(bin_path),
                "sha256": sha256,
                "md5": md5,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "file_name": info.get("file_name", ""),
                "file_type": info.get("file_type", ""),
                "file_size": info.get("file_size", ""),
                "signature": info.get("signature", ""),
                "tags": ",".join(info.get("tags", [])),
                "clamav": info.get("clamav", ""),
                "pe_arch": pe_architecture(bin_path),
                "signed": "true" if has_authenticode_signature(bin_path) else "false",
            }
            save_metadata(row)

            seen.add(sha256)
            n += 1
            logging.info(f"[dataset] +1 → {n}/{target}")
            progressed = True
            time.sleep(RATE_DELAY)

            if n >= target:
                break

        idle_loops = 0 if progressed else (idle_loops + 1)

    logging.info(f"[dataset] COMPLETATO → samples={n} (type={file_type})")




def dataset_stats(out_json: str = str(ROOT / "data" / "dataset_stats.json")) -> Dict[str, Any]:
    """
    Calcola statistiche sul dataset raccolto (unico, senza split train/test).
    Salva i risultati in formato JSON.
    """
    os.makedirs(ROOT / "data", exist_ok=True)
    rows_all = _read_csv_rows(str(META_CSV))

    def _dist(rows: List[Dict], key: str, top: int = 15):
        freq: Dict[str, int] = {}
        for r in rows:
            k = (r.get(key) or "unknown").strip() or "unknown"
            freq[k] = freq.get(k, 0) + 1
        items = sorted(freq.items(), key=lambda x: x[1], reverse=True)
        return {"top": items[:top], "n_unique": len(freq)}

    def _sizes(rows: List[Dict]):
        vals = []
        for r in rows:
            try:
                s = int(r.get("file_size") or 0)
                if s > 0:
                    vals.append(s)
            except Exception:
                pass
        if not vals:
            return {}
        return {
            "n": len(vals),
            "min": min(vals),
            "p50": int(sorted(vals)[len(vals)//2]),
            "mean": int(sum(vals) / len(vals)),
            "p90": int(sorted(vals)[int(len(vals) * 0.9)]),
            "max": max(vals),
        }

    def _time_span(rows: List[Dict]):
        ts = []
        for r in rows:
            t = r.get("timestamp")
            if t:
                ts.append(t)
        if not ts:
            return {}
        return {"first": min(ts), "last": max(ts)}

    def _avg_per_day(rows: List[Dict]):
        ts = [r.get("timestamp") for r in rows if r.get("timestamp")]
        if len(ts) < 2:
            return {}
        first, last = min(ts), max(ts)
        try:
            from datetime import datetime
            dt_first = datetime.fromisoformat(first.replace("Z", "+00:00"))
            dt_last = datetime.fromisoformat(last.replace("Z", "+00:00"))
            days = max(1, (dt_last - dt_first).days)
            return {"avg_per_day": len(ts) / days}
        except Exception:
            return {}

    rep = {
        "totals": {"all": len(rows_all)},
        "signature": {"all": _dist(rows_all, "signature")},
        "file_type": {"all": _dist(rows_all, "file_type")},
        "sizes": {"all": _sizes(rows_all)},
        "time_span": {"all": _time_span(rows_all)},
        "rate": _avg_per_day(rows_all)
    }

    with open(out_json, "w") as fh:
        json.dump(rep, fh, indent=2)
    logging.info(f"[stats] scritto {out_json}")
    return rep


def _read_csv_rows(csv_path: str) -> List[Dict]:
    if not os.path.isfile(csv_path):
        return []
    with open(csv_path, newline="") as fh:
        return list(csv.DictReader(fh))

def _write_csv_rows(csv_path: str, rows: List[Dict], header: List[str]) -> None:
    with open(csv_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=header)
        w.writeheader()
        for r in rows:
            w.writerow(r)


# ────────────────────────────────────── entrypoint
def main() -> None:
    parser = argparse.ArgumentParser(description="MalwareBazaar collector")
    parser.add_argument("--target", type=int, default=100,
                        help="Numero di sample da collezionare")
    parser.add_argument("--file-type", type=str, default="pe",
                        help="file_type per enumerazione (default: pe)")
    parser.add_argument("--stats-only", action="store_true",
                        help="Calcola statistiche dataset e salva JSON.")
    args = parser.parse_args()

    if args.stats_only:
        dataset_stats()
        return

    collect_dataset(args.target, file_type=args.file_type)



if __name__ == "__main__":
    main()
