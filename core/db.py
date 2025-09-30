"""
db.py — Stato della pipeline su SQLite (idempotente e minimale)


Obiettivi:
- Tracciare lo stato per ogni sample (sha256) lungo la pipeline.
- Offrire un'API minimale `mark()` per aggiornare il progresso senza coupling.


Schema:
samples(
  sha256 TEXT PRIMARY KEY,
  filename TEXT,
  collected_at TEXT,
  disassembled_at TEXT,
  iocs_at TEXT,
  predicted_at TEXT,
  reported_at TEXT,
  status TEXT
)


Note:
- I timestamp sono ISO 8601 in UTC per semplicità di audit.
- Il DB è locale (SQLite) e può essere sostituito da Postgres senza cambiare i call-site.
"""

# core/db.py — Stato della pipeline su SQLite (robusto con WAL/timeout/retry)
from __future__ import annotations

import sqlite3, time
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from .settings import DB_PATH

_DDL = """
CREATE TABLE IF NOT EXISTS samples (
  sha256 TEXT PRIMARY KEY,
  filename TEXT,
  collected_at TEXT,
  disassembled_at TEXT,
  iocs_at TEXT,
  predicted_at TEXT,
  reported_at TEXT,
  status TEXT
);

CREATE INDEX IF NOT EXISTS idx_status ON samples(status);
CREATE INDEX IF NOT EXISTS idx_disassembled ON samples(disassembled_at);
"""


def _ensure_columns(con: sqlite3.Connection) -> None:
    try:
        cur = con.execute("PRAGMA table_info(samples);")
        cols = {row[1] for row in cur.fetchall()}
        if "predicted_at" not in cols:
            con.execute("ALTER TABLE samples ADD COLUMN predicted_at TEXT;")
    except Exception:
        pass

def _conn() -> sqlite3.Connection:
    """Connessione robusta con WAL e timeouts."""
    con = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")
    con.execute("PRAGMA busy_timeout=15000;")
    for stmt in _DDL.split(";"):
        s = stmt.strip()
        if s:
            con.execute(s + ";")
    _ensure_columns(con)
    return con

def _with_retry(fn, attempts: int = 6, base_sleep: float = 0.05):
    for i in range(attempts):
        try:
            return fn()
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower():
                time.sleep(base_sleep * (2 ** i))
                continue
            raise
    return fn()

def mark(sha256: str, *, filename: Optional[str] = None,
         field: Optional[str] = None, status: Optional[str] = None) -> None:
    """Aggiorna/inizializza lo stato del sample in modo idempotente."""
    now = datetime.now(timezone.utc).isoformat()

    def _do():
        with _conn() as c:
            c.execute(
                "INSERT OR IGNORE INTO samples (sha256, filename, status, collected_at) VALUES (?,?,?,?)",
                (sha256, filename or sha256, "collected", now),
            )
            if field:
                c.execute(f"UPDATE samples SET {field}=? WHERE sha256= ?", (now, sha256))
            if status:
                c.execute("UPDATE samples SET status=? WHERE sha256=?", (status, sha256))
            if filename:
                c.execute("UPDATE samples SET filename=? WHERE sha256=?", (filename, sha256))
    _with_retry(_do)

def get(sha256: str) -> Optional[Dict[str, Any]]:
    def _do():
        with _conn() as c:
            cur = c.execute("SELECT * FROM samples WHERE sha256=?", (sha256,))
            row = cur.fetchone()
            if not row:
                return None
            cols = [d[0] for d in cur.description]
            return dict(zip(cols, row))
    return _with_retry(_do)

def list_recent(limit: int = 50, status: Optional[str] = None) -> List[Dict[str, Any]]:
    def _do():
        with _conn() as c:
            if status:
                cur = c.execute("SELECT * FROM samples WHERE status=? ORDER BY COALESCE(reported_at, iocs_at, disassembled_at, collected_at) DESC LIMIT ?",
                                (status, limit))
            else:
                cur = c.execute("SELECT * FROM samples ORDER BY COALESCE(reported_at, iocs_at, disassembled_at, collected_at) DESC LIMIT ?",
                                (limit,))
            rows = cur.fetchall()
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in rows]
    return _with_retry(_do)
