#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
r2_scan.py — Batch disassembler/feature-extractor basato su Radare2

Aggiornamenti:
- Usa `core.settings` per percorsi di input/output (coerenza repo-wide).
- Normalizza output in `disassembler/disassembled/{json,asm}`.
- Commenti estesi per esplicitare contratti e failure-mode.
"""
import json
import csv
import math
import hashlib
import logging
import os
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone

import r2pipe

try:
    import magic
    _MAGIC = True
except Exception:  # pragma: no cover
    _MAGIC = False

from pathlib import Path
from core.settings import SAMPLES_DIR, DISASM_JSON, DISASM_ASM

MIN_STR_LEN = 4
MAX_FUN_OPS = int(os.getenv("R2_MAX_FUN_OPS", "0")) or None
FALLBACK_BIN_EXT = {".exe", ".dll", ".sys", ".bin", ".elf", ".so", ".dylib", ".apk"}

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# ───────────────────────────────────────── Helper: CSV minimal log
META_CSV = DISASM_JSON.parent / "metadata.csv"

def _utc_iso(ts) -> str:
    if not ts:
        return ""
    try:
        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
        # niente microsecondi e suffisso Z
        return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except Exception:
        return ""

def collect_candidates_recursive() -> List[Path]:
    """Raccoglie eseguibili validi ricorsivamente in SAMPLES_DIR."""

    out: List[Path] = []
    base = Path(SAMPLES_DIR)
    if not base.exists():
        return out
    for p in base.rglob("*"):
        if p.is_file() and is_executable(p):
            out.append(p)
    return out


def sha256_of(path: Path) -> str:
    """SHA-256 veloce per decidere se esiste già l'output JSON target."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def append_csv(row: List[str]) -> None:
    header = not META_CSV.exists()
    with open(META_CSV, "a", newline="") as fh:
        w = csv.writer(fh)
        if header:
            w.writerow(["filename", "sha256", "md5", "arch", "bits", "filesize", "timestamp"])
        w.writerow(row)



# ───────────────────────────────────────── Helper: hashing/entropy

def file_hashes(path: Path) -> Tuple[str, str]:
    sha256 = hashlib.sha256()
    md5    = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()

def shannon_entropy(path: Path, chunk_size: int = 1 << 20) -> float:
    """
    Calcola entropia Shannon leggendo a chunk (default: 1MB).
    Robusto anche per file molto grandi.
    """
    try:
        freq = [0] * 256
        total = 0
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                total += len(chunk)
                for b in chunk:
                    freq[b] += 1
        if total == 0:
            return 0.0
        ent = 0.0
        for c in freq:
            if c:
                p = c / total
                ent -= p * math.log(p, 2)
        return round(ent, 4)
    except Exception:  # pragma: no cover
        return -1.0


# ───────────────────────────────────────── Helper: riconoscimento binari

def is_executable(path: Path) -> bool:
    """
    Riconosce eseguibili/loader PE Windows (EXE/DLL/SYS/OCX/…).
    Priorità: estensione → python-magic → pefile (header valido).
    Evita script/archivi/documenti.
    """
    pe_exts = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".drv"}
    ext_ok = path.suffix.lower() in pe_exts

    # Se abbiamo magic, facciamo un controllo rapido sul tipo PE/EXE
    if _MAGIC:
        try:
            ftype = magic.from_file(str(path), mime=False).lower()
            if any(t in ftype for t in ("portable executable", "pe32", "pe32+", "application/x-dosexec")):
                return True
            # se magic lo marca come script/text/archive → non valido
            if any(t in ftype for t in ("script", "text", "archive", "zip", "pdf", "office")):
                return False
        except Exception:
            pass

    if not ext_ok:
        return False

    # Validazione extra con pefile (se disponibile)
    try:
        import pefile  # lazy import
        try:
            pe = pefile.PE(str(path), fast_load=True)
            return bool(getattr(pe, "sections", []))
        except pefile.PEFormatError:
            return False
        except Exception:
            # incertezza: consideralo valido se estensione è PE
            return True
    except Exception:
        # pefile non disponibile: ci basiamo su estensione/magic
        return True

# ───────────────────────────────────────── Radare2: utilità

def _mnemonic(op: Dict[str, Any]) -> Optional[str]:
    m = op.get("mnemonic")
    if m:
        return m
    opc = op.get("opcode", "")
    return opc.split()[0] if opc else None


def _cap_ops(ops: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if MAX_FUN_OPS is None:
        return ops
    return ops[:MAX_FUN_OPS]

# ───────────────────────────────────────── Radare2: analisi per campione
def analyze_with_r2(path: Path) -> Optional[Dict[str, Any]]:
    """
    Disassembla con r2 e, se PE, arricchisce con metadati tipici:
    - pe_meta: machine, subsystem, compile_time (UTC), entrypoint
    - imphash, rich_header_md5, signed (presence), overlay_size
    - sections: nome/virtual_size/raw_size/entropy/characteristics
    - imports/exports (r2), TLS callbacks se presenti (best-effort)
    - entropy_file (Shannon) e istogramma mnemonici
    """
    r2 = None
    try:
        # ── r2: analisi base
        r2 = r2pipe.open(str(path), flags=["-2"])  # -2 = quiet
        r2.cmd("aaa")

        infoj = r2.cmdj("ij") or {}
        binj  = infoj.get("bin", {}) or {}
        arch  = binj.get("arch", "n/a")
        bits  = binj.get("bits", "n/a")
        fmt   = binj.get("format", "")
        endian= binj.get("endian", "")
        entry = binj.get("baddr") or binj.get("entry")

        imports  = r2.cmdj("iij") or []
        exports  = r2.cmdj("iEj") or []
        sections_r2 = r2.cmdj("iSj") or []

        # Strings
        r2.cmd("izz")
        strj = r2.cmdj("izj") or []
        strings = [
            {"vaddr": s.get("vaddr"), "len": s.get("length"), "str": s.get("string")}
            for s in strj
            if s.get("string") and (s.get("length") or 0) >= MIN_STR_LEN
        ]

        # Funzioni e mnemonici
        funs = r2.cmdj("aflj") or []
        functions = []
        mnemonic_hist: Dict[str, int] = {}
        for f in funs:
            faddr = f.get("offset")
            fname = f.get("name", f"func_0x{faddr:x}" if faddr is not None else "unk")
            if faddr is None:
                logging.debug("Funzione senza offset saltata.")
                continue
            fj = r2.cmdj(f"pdfj @ 0x{faddr:x}") or {}
            ops = _cap_ops(fj.get("ops", []) or [])
            cleaned_ops = []
            for op in ops:
                m = _mnemonic(op)
                if m:
                    mnemonic_hist[m] = mnemonic_hist.get(m, 0) + 1
                cleaned_ops.append({
                    "offset": op.get("offset"),
                    "mnemonic": m,
                    "opcode": op.get("opcode")
                })
            functions.append({"name": fname, "addr": faddr, "size": f.get("size"), "ops": cleaned_ops})

        # ASM leggibile (tutte le funzioni)
        asm_chunks: List[str] = []
        for f in functions:
            asm_chunks.append(f"\n; ===== FUNCTION {f['name']} @ 0x{f['addr']:x} =====\n")
            asm_chunks.append(r2.cmd(f"pdf @ 0x{f['addr']:x}"))
        asm_text = "".join(asm_chunks)
        if not asm_text:
            logging.warning(f"[{path.name}] Nessuna funzione disassemblata (asm vuoto).")

        # Hash ed entropia globale
        entropy = shannon_entropy(path)
        sha256, md5 = file_hashes(path)

        # ── Enrichment PE (best-effort)
        pe_meta: Dict[str, Any] = {}
        sections_pe: List[Dict[str, Any]] = []
        imphash = None
        rich_md5 = None
        signed = False
        overlay_size = None
        tls_callbacks: List[str] = []
        packer_hints: List[str] = []

        try:
            import pefile
            pe = pefile.PE(str(path), fast_load=True)
            # Machine / Subsystem
            pe_meta["machine"]   = hex(getattr(pe.FILE_HEADER, "Machine", 0))
            pe_meta["subsystem"] = hex(getattr(pe.OPTIONAL_HEADER, "Subsystem", 0))
            # Compile time
            ts = getattr(pe.FILE_HEADER, "TimeDateStamp", 0)
            pe_meta["compile_time"] = _utc_iso(ts)
            # Entry point (preferisci quello di PE se disponibile)
            try:
                ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                pe_meta["entrypoint"] = hex(ep)
                if not entry:
                    entry = ep
            except Exception:
                pass

            # imphash
            try:
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
                imphash = pe.get_imphash()
            except Exception:
                imphash = None

            # Rich header hash
            try:
                rich = pe.parse_rich_header()
                if rich and "data" in rich and rich["data"]:
                    import hashlib as _hl
                    rich_md5 = _hl.md5(rich["data"]).hexdigest()
            except Exception:
                rich_md5 = None

            # Firma presente?
            try:
                dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY
                sec = dd[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
                signed = bool(getattr(sec, "Size", 0))
            except Exception:
                signed = False

            # Overlay size (dati oltre l'ultima sezione)
            try:
                file_sz = path.stat().st_size
                last_end = 0
                for s in pe.sections or []:
                    end = s.PointerToRawData + s.SizeOfRawData
                    if end > last_end:
                        last_end = end
                overlay_size = max(0, file_sz - last_end)
            except Exception:
                overlay_size = None

            # TLS callbacks
            try:
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]])
                tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
                if tls and getattr(tls, "struct", None):
                    addr = getattr(tls.struct, "AddressOfCallBacks", 0)
                    if addr:
                        # Risoluzione simbolica best-effort via r2 (se mappabile)
                        tls_callbacks.append(hex(addr))
            except Exception:
                pass

            # Sezioni con entropia
            try:
                for s in pe.sections or []:
                    try:
                        data = s.get_data()
                        # entropia sezione
                        if data:
                            freq = [0] * 256
                            for b in data:
                                freq[b] += 1
                            total = float(len(data))
                            ent = 0.0
                            for c in freq:
                                if c:
                                    p = c / total
                                    ent -= p * math.log(p, 2)
                            ent = round(ent, 4)
                        else:
                            ent = 0.0
                    except Exception:
                        ent = -1.0

                    sec_name = (s.Name or b"").rstrip(b"\x00").decode(errors="ignore")
                    # hint packer (UPX, MPRESS, ecc.)
                    nlow = sec_name.lower()
                    if any(tag in nlow for tag in ("upx", "mpress", "aspack", "petite", "themida", "vmp")):
                        packer_hints.append(sec_name)

                    sections_pe.append({
                        "name": sec_name,
                        "virtual_address": hex(getattr(s, "VirtualAddress", 0)),
                        "virtual_size": getattr(s, "Misc_VirtualSize", 0),
                        "raw_ptr": hex(getattr(s, "PointerToRawData", 0)),
                        "raw_size": getattr(s, "SizeOfRawData", 0),
                        "entropy": ent,
                        "characteristics": hex(getattr(s, "Characteristics", 0)),
                    })
            except Exception:
                pass

        except Exception:
            # pefile non disponibile o PE non parsabile: salta enrichment
            pass

        # Se r2 ci ha dato sezioni, proviamo ad aggiungere entropy se mancasse
        if sections_r2 and not sections_pe:
            # fallback: annota quello che sai da r2
            for s in sections_r2:
                sections_pe.append({
                    "name": s.get("name", ""),
                    "virtual_address": hex(s.get("vaddr", 0)) if isinstance(s.get("vaddr", 0), int) else str(s.get("vaddr", "")),
                    "virtual_size": s.get("vsize", 0),
                    "raw_ptr": hex(s.get("paddr", 0)) if isinstance(s.get("paddr", 0), int) else str(s.get("paddr", "")),
                    "raw_size": s.get("size", 0),
                    "entropy": None,
                    "characteristics": None,
                })

        # Risultato finale
        out = {
            "path": str(path),
            "sha256": sha256,
            "md5": md5,
            "info": {"arch": arch, "bits": bits, "format": fmt, "endian": endian, "entrypoint": entry},
            "imports": imports,
            "exports": exports,
            "sections": sections_pe or sections_r2 or [],
            "strings": strings,
            "functions": functions,
            "mnemonics_hist": mnemonic_hist,
            "entropy_file": entropy,
            "asm_text": asm_text,
            # Enrichment PE
            "pe_meta": pe_meta,
            "imphash": imphash,
            "rich_header_md5": rich_md5,
            "signed": signed,
            "overlay_size": overlay_size,
            "tls_callbacks": tls_callbacks,
            "packer_hints": sorted(set(packer_hints)),
        }
        return out

    except Exception as exc:  # pragma: no cover
        logging.error(f"Radare2 failed on {path.name} → {exc}")
        return None
    finally:
        try:
            if r2 is not None:
                r2.quit()
        except Exception:
            pass


# ───────────────────────────────────────── Salvataggio output

def write_outputs(sample: Path, data: Dict[str, Any]) -> None:
    # usa lo SHA-256 calcolato da r2_scan per nominare i file in modo canonico
    sha = data.get("sha256") or sample.stem
    asm_path  = DISASM_ASM / f"{sha}.asm"
    json_path = DISASM_JSON / f"{sha}.json"

    DISASM_ASM.mkdir(parents=True, exist_ok=True)
    DISASM_JSON.mkdir(parents=True, exist_ok=True)

    with open(asm_path, "w", encoding="utf-8", newline="") as fh:
        fh.write(data.get("asm_text", ""))

    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)

    logging.info(f"✓ Salvato JSON: {json_path.name}")
    logging.info(f"✓ Salvato ASM : {asm_path.name}")

# ───────────────────────────────────────── Main loop

def main() -> None:
    # 1) raccogli (train + test) ricorsivamente
    samples = collect_candidates_recursive()
    if not samples:
        logging.warning("Nessun binario valido da analizzare.")
        return

    # 2) processa con skip idempotente se JSON esiste già
    total = len(samples)
    for idx, path in enumerate(samples, 1):
        # output canonico → json/<sha>.json
        pre_sha = sha256_of(path)
        json_target = DISASM_JSON / f"{pre_sha}.json"
        if json_target.exists():
            logging.info(f"[{idx}/{total}] ↪︎ {path.name} già disassemblato ({json_target.name}) – skip.")
            continue

        logging.info(f"[{idx}/{total}] → {path.name}")
        res = analyze_with_r2(path)
        if not res:
            logging.warning(f"✗ Skipped {path.name} (errore).")
            continue

        write_outputs(path, res)
        arch = res.get("info", {}).get("arch", "n/a")
        bits = res.get("info", {}).get("bits", "n/a")
        sha256 = res.get("sha256", pre_sha)
        md5 = res.get("md5", "")
        filesize = path.stat().st_size
        append_csv([path.name, sha256, md5, arch, bits, filesize, datetime.now(timezone.utc).isoformat()])
        logging.info(f"✔ Disassemblato: {path.name} [arch: {arch} / {bits} bit]")



if __name__ == "__main__":
    main()