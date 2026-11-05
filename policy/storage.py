"""CareRail Persistent Ledger Storage
Atomic SQLite3 backend for state persistence across process restarts.
Guarantees nonce replay protection, daily spend, and budget reservation durability.
Supports atomic multi-statement transactions under SQLite BEGIN IMMEDIATE.
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
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False, isolation_level=None)
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

    def is_nonce_consumed(self, nonce: int) -> bool:
        with self._lock:
            row = self.conn.execute("SELECT 1 FROM seen_nonces WHERE nonce = ?", (nonce,)).fetchone()
            return row is not None

    def consume_nonce(self, nonce: int, timestamp: float) -> bool:
        """Consumes a nonce. Returns True if inserted, False if already consumed."""
        with self._lock:
            try:
                self.conn.execute("INSERT INTO seen_nonces (nonce, consumed_at) VALUES (?, ?)", (nonce, timestamp))
                return True
            except sqlite3.IntegrityError:
                return False

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

    def get_all_daily_ledgers(self) -> Dict[str, Tuple[float, float]]:
        with self._lock:
            rows = self.conn.execute("SELECT day_key, settled_spend, reserved_spend FROM daily_ledgers").fetchall()
            return {r["day_key"]: (float(r["settled_spend"]), float(r["reserved_spend"])) for r in rows}

    def set_daily_spend(self, day_key: str, amount: float):
        with self._lock:
            self.conn.execute("""
                INSERT INTO daily_ledgers (day_key, settled_spend, reserved_spend)
                VALUES (?, ?, 0.0)
                ON CONFLICT(day_key) DO UPDATE SET settled_spend = ?
            """, (day_key, amount, amount))

    def set_daily_reserved(self, day_key: str, amount: float):
        with self._lock:
            self.conn.execute("""
                INSERT INTO daily_ledgers (day_key, settled_spend, reserved_spend)
                VALUES (?, 0.0, ?)
                ON CONFLICT(day_key) DO UPDATE SET reserved_spend = ?
            """, (day_key, amount, amount))

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

    def get_pause_state(self) -> bool:
        with self._lock:
            row = self.conn.execute("SELECT value FROM engine_state WHERE key = 'is_paused'").fetchone()
            if row:
                return bool(int(row["value"]))
            return False

    def atomic_commit_spend(self, proposal_id: str, tx_hash: str, today_key: str, max_daily_budget: float) -> Tuple[bool, str]:
        """Atomically transitions an APPROVED proposal to CONFIRMED and updates spend ledger.
        Wraps reservation release, spend accumulation, and proposal state change in a single transaction.
        """
        with self._lock:
            cursor = self.conn.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                row = cursor.execute("SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,)).fetchone()
                if not row:
                    cursor.execute("ROLLBACK")
                    return False, "PROPOSAL_NOT_FOUND"

                p = dict(row)
                if p["state"] != "APPROVED":
                    cursor.execute("ROLLBACK")
                    return False, f"INVALID_STATE: Current state {p['state']} is not APPROVED"

                amount = float(p["amount_near"])
                submitted_day = p["submitted_day"]

                # Fetch today's ledger
                today_row = cursor.execute("SELECT settled_spend, reserved_spend FROM daily_ledgers WHERE day_key = ?", (today_key,)).fetchone()
                today_settled = float(today_row["settled_spend"]) if today_row else 0.0
                today_reserved = float(today_row["reserved_spend"]) if today_row else 0.0

                # Cross-day budget check: if executed on a different day, ensure headroom exists
                if submitted_day != today_key and (today_settled + today_reserved + amount > max_daily_budget):
                    cursor.execute("ROLLBACK")
                    return False, f"CROSS_DAY_BUDGET_EXCEEDED: Headroom insufficient on {today_key}"

                # Release reservation on submitted day
                sub_row = cursor.execute("SELECT reserved_spend FROM daily_ledgers WHERE day_key = ?", (submitted_day,)).fetchone()
                sub_reserved = float(sub_row["reserved_spend"]) if sub_row else 0.0
                new_sub_reserved = max(0.0, sub_reserved - amount)
                cursor.execute("""
                    INSERT INTO daily_ledgers (day_key, settled_spend, reserved_spend)
                    VALUES (?, 0.0, ?)
                    ON CONFLICT(day_key) DO UPDATE SET reserved_spend = ?
                """, (submitted_day, new_sub_reserved, new_sub_reserved))

                # Increment settled spend on today
                new_today_settled = today_settled + amount
                cursor.execute("""
                    INSERT INTO daily_ledgers (day_key, settled_spend, reserved_spend)
                    VALUES (?, ?, 0.0)
                    ON CONFLICT(day_key) DO UPDATE SET settled_spend = ?
                """, (today_key, new_today_settled, new_today_settled))

                # Update proposal state
                cursor.execute("""
                    UPDATE proposals
                    SET state = 'CONFIRMED', tx_hash = ?
                    WHERE proposal_id = ?
                """, (tx_hash, proposal_id))

                cursor.execute("COMMIT")
                return True, "SUCCESS"
            except Exception as e:
                cursor.execute("ROLLBACK")
                return False, f"STORAGE_TRANSACTION_ERROR: {str(e)}"

    def atomic_owner_reject(self, proposal_id: str, reason: str) -> Tuple[bool, str]:
        """Atomically rejects a proposal and releases reservation if held."""
        with self._lock:
            cursor = self.conn.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                row = cursor.execute("SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,)).fetchone()
                if not row:
                    cursor.execute("ROLLBACK")
                    return False, "PROPOSAL_NOT_FOUND"

                p = dict(row)
                if p["state"] not in ("AWAITING_OWNER_APPROVAL", "PROPOSED"):
                    cursor.execute("ROLLBACK")
                    return False, f"CANNOT_REWRITE_STATE: Proposal in state {p['state']} cannot be rejected"

                if p["state"] == "AWAITING_OWNER_APPROVAL":
                    day_key = p["submitted_day"]
                    amount = float(p["amount_near"])
                    cur_row = cursor.execute("SELECT reserved_spend FROM daily_ledgers WHERE day_key = ?", (day_key,)).fetchone()
                    cur_res = float(cur_row["reserved_spend"]) if cur_row else 0.0
                    new_res = max(0.0, cur_res - amount)
                    cursor.execute("""
                        INSERT INTO daily_ledgers (day_key, settled_spend, reserved_spend)
                        VALUES (?, 0.0, ?)
                        ON CONFLICT(day_key) DO UPDATE SET reserved_spend = ?
                    """, (day_key, new_res, new_res))

                cursor.execute("""
                    UPDATE proposals
                    SET state = 'REJECTED', rejection_reason = ?
                    WHERE proposal_id = ?
                """, (reason, proposal_id))

                cursor.execute("COMMIT")
                return True, "SUCCESS"
            except Exception as e:
                cursor.execute("ROLLBACK")
                return False, f"STORAGE_TRANSACTION_ERROR: {str(e)}"

    def close(self):
        with self._lock:
            try:
                self.conn.close()
            except Exception:
                pass
