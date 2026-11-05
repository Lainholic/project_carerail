"""CareRail Persistent Ledger Storage
Atomic SQLite3 backend for state persistence across process restarts.
Guarantees nonce replay protection, daily spend, and budget reservation durability.
"""

import json
import os
import sqlite3
import threading
from typing import Dict, List, Optional, Tuple


class PersistentLedgerStorage:
    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._lock = threading.Lock()
        # Maintain a persistent connection instance
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        with self._lock:
            cursor = self.conn.cursor()
            # 1. Nonces table for replay attack protection
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS seen_nonces (
                    nonce INTEGER PRIMARY KEY,
                    consumed_at REAL NOT NULL
                )
            """)
            # 2. Daily accounting ledger
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS daily_ledgers (
                    day_key TEXT PRIMARY KEY,
                    settled_spend REAL NOT NULL DEFAULT 0.0,
                    reserved_spend REAL NOT NULL DEFAULT 0.0
                )
            """)
            # 3. Persistent proposals
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS proposals (
                    proposal_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    amount_near REAL NOT NULL,
                    intent_memo TEXT NOT NULL,
                    nonce INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    submitted_day TEXT NOT NULL,
                    rejection_reason TEXT,
                    tx_hash TEXT
                )
            """)
            # 4. Engine settings (pause state)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS engine_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)
            self.conn.commit()

    def is_nonce_consumed(self, nonce: int) -> bool:
        with self._lock:
            row = self.conn.execute("SELECT 1 FROM seen_nonces WHERE nonce = ?", (nonce,)).fetchone()
            return row is not None

    def consume_nonce(self, nonce: int, timestamp: float):
        with self._lock:
            self.conn.execute("INSERT OR IGNORE INTO seen_nonces (nonce, consumed_at) VALUES (?, ?)", (nonce, timestamp))
            self.conn.commit()

    def get_all_nonces(self) -> set:
        with self._lock:
            rows = self.conn.execute("SELECT nonce FROM seen_nonces").fetchall()
            return {r["nonce"] for r in rows}

    def get_daily_ledger(self, day_key: str) -> Tuple[float, float]:
        """Returns (settled_spend, reserved_spend)"""
        with self._lock:
            row = self.conn.execute("SELECT settled_spend, reserved_spend FROM daily_ledgers WHERE day_key = ?", (day_key,)).fetchone()
            if row:
                return (float(row["settled_spend"]), float(row["reserved_spend"]))
            return (0.0, 0.0)

    def set_daily_spend(self, day_key: str, amount: float):
        with self._lock:
            self.conn.execute("""
                INSERT INTO daily_ledgers (day_key, settled_spend, reserved_spend)
                VALUES (?, ?, 0.0)
                ON CONFLICT(day_key) DO UPDATE SET settled_spend = ?
            """, (day_key, amount, amount))
            self.conn.commit()

    def set_daily_reserved(self, day_key: str, amount: float):
        with self._lock:
            self.conn.execute("""
                INSERT INTO daily_ledgers (day_key, settled_spend, reserved_spend)
                VALUES (?, 0.0, ?)
                ON CONFLICT(day_key) DO UPDATE SET reserved_spend = ?
            """, (day_key, amount, amount))
            self.conn.commit()

    def save_proposal(self, p_dict: dict):
        with self._lock:
            self.conn.execute("""
                INSERT INTO proposals (
                    proposal_id, agent_id, recipient, amount_near, intent_memo,
                    nonce, state, created_at, submitted_day, rejection_reason, tx_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(proposal_id) DO UPDATE SET
                    state = excluded.state,
                    rejection_reason = excluded.rejection_reason,
                    tx_hash = excluded.tx_hash
            """, (
                p_dict["proposal_id"], p_dict["agent_id"], p_dict["recipient"],
                p_dict["amount_near"], p_dict["intent_memo"], p_dict["nonce"],
                p_dict["state"], p_dict["created_at"], p_dict["submitted_day"],
                p_dict.get("rejection_reason"), p_dict.get("tx_hash")
            ))
            self.conn.commit()

    def get_proposal(self, proposal_id: str) -> Optional[dict]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,)).fetchone()
            if row:
                return dict(row)
            return None

    def get_all_proposals(self) -> Dict[str, dict]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM proposals").fetchall()
            return {r["proposal_id"]: dict(r) for r in rows}

    def set_pause_state(self, paused: bool):
        with self._lock:
            self.conn.execute("INSERT OR REPLACE INTO engine_state (key, value) VALUES ('is_paused', ?)", (str(int(paused)),))
            self.conn.commit()

    def get_pause_state(self) -> bool:
        with self._lock:
            row = self.conn.execute("SELECT value FROM engine_state WHERE key = 'is_paused'").fetchone()
            if row:
                return bool(int(row["value"]))
            return False

    def close(self):
        with self._lock:
            try:
                self.conn.close()
            except Exception:
                pass
