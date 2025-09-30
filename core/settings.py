"""
settings.py — Configurazione centralizzata del framework

Linee guida progettuali:
- Evitare path hard-coded e segreti in chiaro: variabili d'ambiente via `.env`.
- Strutturare i percorsi (ROOT/DATA/SAMPLES/OUTPUTS) per poter spostare il repo senza rompere nulla.
- Rendere i path disponibili ai moduli senza import circolari.
"""

# core/settings.py — Configurazione centralizzata del framework
from __future__ import annotations
import os
from pathlib import Path

# Root del repository (core/ -> parent -> ROOT)
ROOT: Path = Path(__file__).resolve().parents[1]

# .env (sviluppo) — opzionale
try:
    from dotenv import load_dotenv  # type: ignore
except Exception:
    load_dotenv = None  # type: ignore

if load_dotenv is not None:
    load_dotenv(ROOT / ".env")

def _getenv_path(var: str, default: Path) -> Path:
    val = os.getenv(var)
    return Path(val) if val else default

# API keys / segreti
MALWAREBAZAAR_API_KEY: str = os.getenv("MALWAREBAZAAR_API_KEY", "")

# Struttura cartelle
DATA_DIR: Path = _getenv_path("DATA_DIR", ROOT / "data")
SAMPLES_DIR: Path = _getenv_path("SAMPLES_DIR", ROOT / "collector" / "malware_samples")
DISASM_DIR: Path = _getenv_path("DISASM_DIR", ROOT / "disassembler" / "disassembled")
DISASM_JSON: Path = _getenv_path("DISASM_JSON", DISASM_DIR / "json")
DISASM_ASM: Path = _getenv_path("DISASM_ASM", DISASM_DIR / "asm")
ARTIFACTS: Path = _getenv_path("ARTIFACTS_DIR", ROOT / "artifacts")
DB_PATH: Path = _getenv_path("DB_PATH", ROOT / "state.sqlite3")

# CSV metadata (unico)
META_CSV: Path = _getenv_path("META_CSV", ROOT / "collector" / "metadata.csv")

# Ensure directories exist
for d in (
    DATA_DIR, SAMPLES_DIR,
    DISASM_DIR, DISASM_JSON, DISASM_ASM, ARTIFACTS
):
    d.mkdir(parents=True, exist_ok=True)
