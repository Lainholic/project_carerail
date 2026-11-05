"""CareRail Persistent Ledger Storage
Atomic SQLite3 backend for state persistence across process restarts.
Guarantees nonce replay protection, daily spend, and budget reservation durability.
Uses exact Decimal arithmetic and string storage to eliminate IEEE-754 floating-point errors (P2-2).
Supports atomic multi-statement transactions under SQLite BEGIN IMMEDIATE.
"""

from decimal import Decimal, getcontext
import json
import os
import sqlite3
import threading
import time
from typing import Dict, List, Optional, Tuple

# 36 decimal places precision for yoctoNEAR level math (1 NEAR = 10^24 yocto)
getcontext().prec = 36


class PersistentLedgerStorage:
    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._lock = threading.Lock()
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
            # 2. Daily accounting ledger (amounts stored as TEXT to prevent IEEE-754 rounding errors)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS daily_ledgers (
                    day_key TEXT PRIMARY KEY,
                    settled_spend TEXT NOT NULL DEFAULT '0',
                    reserved_spend TEXT NOT NULL DEFAULT '0'
                )
            """)
            # 3. Persistent proposals
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS proposals (
                    proposal_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    amount_near TEXT NOT NULL,
                    intent_memo TEXT NOT NULL,
                    nonce INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    submitted_day TEXT NOT NULL,
                    rejection_reason TEXT,
                    tx_hash TEXT
                )
            """)
            # 4. Consumed transaction hashes for replay & reuse protection (Terra Round 9 P0-2)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS consumed_tx_hashes (
                    tx_hash TEXT PRIMARY KEY,
                    proposal_id TEXT NOT NULL,
                    consumed_at REAL NOT NULL
                )
            """)
            # 5. Engine settings (pause state)
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
        """Consumes a nonce atomically. Returns True if inserted, False if already consumed."""
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

    def get_daily_ledger(self, day_key: str) -> Tuple[Decimal, Decimal]:
        """Returns (settled_spend, reserved_spend) as exact Decimals"""
        with self._lock:
            row = self.conn.execute("SELECT settled_spend, reserved_spend FROM daily_ledgers WHERE day_key = ?", (day_key,)).fetchone()
            if row:
                return (Decimal(str(row["settled_spend"])), Decimal(str(row["reserved_spend"])))
            return (Decimal("0"), Decimal("0"))

    def get_all_daily_ledgers(self) -> Dict[str, Tuple[Decimal, Decimal]]:
        with self._lock:
            rows = self.conn.execute("SELECT day_key, settled_spend, reserved_spend FROM daily_ledgers").fetchall()
            return {r["day_key"]: (Decimal(str(r["settled_spend"])), Decimal(str(r["reserved_spend"]))) for r in rows}

    def set_daily_spend(self, day_key: str, amount: Decimal):
        with self._lock:
            amt_str = str(amount)
            self.conn.execute("""
                INSERT INTO daily_ledgers (day_key, settled_spend, reserved_spend)
                VALUES (?, ?, '0')
                ON CONFLICT(day_key) DO UPDATE SET settled_spend = ?
            """, (day_key, amt_str, amt_str))

    def set_daily_reserved(self, day_key: str, amount: Decimal):
        with self._lock:
            amt_str = str(amount)
            self.conn.execute("""
                INSERT INTO daily_ledgers (day_key, settled_spend, reserved_spend)
                VALUES (?, '0', ?)
                ON CONFLICT(day_key) DO UPDATE SET reserved_spend = ?
            """, (day_key, amt_str, amt_str))

    def save_proposal(self, p_dict: dict):
        with self._lock:
            amt_str = str(p_dict["amount_near"])
            st = p_dict["state"]
            st_val = st.value if hasattr(st, "value") else str(st)
            if st_val.startswith("ProposalState."):
                st_val = st_val.split(".", 1)[1]
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
                amt_str, p_dict["intent_memo"], p_dict["nonce"],
                st_val, float(p_dict["created_at"]), p_dict["submitted_day"],
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

    def atomic_evaluate_and_reserve(
        self,
        proposal_id: str,
        agent_id: str,
        recipient: str,
        amount_near: Decimal,
        intent_memo: str,
        nonce: int,
        created_at: float,
        today_key: str,
        max_daily_budget: Decimal,
        owner_threshold: Decimal
    ) -> Tuple[bool, str, Decimal]:
        """Terra Round 10 P0-1: Atomically checks daily headroom, consumes nonce,
        increments reserved spend, and records proposal state in a single SQLite BEGIN IMMEDIATE transaction.
        Returns: (success: bool, state_or_reason: str, new_reserved_spend: Decimal)
        """
        with self._lock:
            cursor = self.conn.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")

                # 1. Check emergency circuit breaker pause
                pause_row = cursor.execute("SELECT value FROM engine_state WHERE key = 'is_paused'").fetchone()
                if pause_row and bool(int(pause_row["value"])):
                    cursor.execute("ROLLBACK")
                    return False, "SECURITY_ALERT: Engine is paused by emergency circuit breaker", Decimal("0")

                # 2. Check nonce replay
                nonce_row = cursor.execute("SELECT 1 FROM seen_nonces WHERE nonce = ?", (nonce,)).fetchone()
                if nonce_row:
                    cursor.execute("ROLLBACK")
                    return False, f"REPLAY_DETECTED: Nonce {nonce} already consumed", Decimal("0")

                # 3. Check duplicate proposal ID
                prop_row = cursor.execute("SELECT 1 FROM proposals WHERE proposal_id = ?", (proposal_id,)).fetchone()
                if prop_row:
                    cursor.execute("ROLLBACK")
                    return False, f"DUPLICATE_PROPOSAL_ID: Proposal {proposal_id} already exists", Decimal("0")

                # 4. Check daily budget headroom atomically from database
                today_row = cursor.execute("SELECT settled_spend, reserved_spend FROM daily_ledgers WHERE day_key = ?", (today_key,)).fetchone()
                today_settled = Decimal(str(today_row["settled_spend"])) if today_row else Decimal("0")
                today_reserved = Decimal(str(today_row["reserved_spend"])) if today_row else Decimal("0")

                if (today_settled + today_reserved + amount_near) > max_daily_budget:
                    cursor.execute("ROLLBACK")
                    return False, f"DAILY_CAP_EXCEEDED: Amount exceeds available daily budget (Settled: {float(today_settled)}, Reserved: {float(today_reserved)})", Decimal("0")

                # 5. Consume nonce
                cursor.execute("INSERT INTO seen_nonces (nonce, consumed_at) VALUES (?, ?)", (nonce, created_at))

                # 6. Increment reservation
                new_reserved = today_reserved + amount_near
                cursor.execute("""
                    INSERT INTO daily_ledgers (day_key, settled_spend, reserved_spend)
                    VALUES (?, '0', ?)
                    ON CONFLICT(day_key) DO UPDATE SET reserved_spend = ?
                """, (today_key, str(new_reserved), str(new_reserved)))

                # 7. Determine initial proposal state
                state_str = "AWAITING_OWNER_APPROVAL" if amount_near > owner_threshold else "APPROVED"

                # 8. Save proposal
                cursor.execute("""
                    INSERT INTO proposals (
                        proposal_id, agent_id, recipient, amount_near, intent_memo,
                        nonce, state, created_at, submitted_day, rejection_reason, tx_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                """, (
                    proposal_id, agent_id, recipient, str(amount_near), intent_memo,
                    nonce, state_str, created_at, today_key
                ))

                cursor.execute("COMMIT")
                return True, state_str, new_reserved
            except Exception as e:
                cursor.execute("ROLLBACK")
                return False, f"STORAGE_TRANSACTION_ERROR: {str(e)}", Decimal("0")

    def is_tx_hash_consumed(self, tx_hash: str) -> bool:
        """Terra Round 9 P0-2: Verify whether a transaction hash was already consumed."""
        if not tx_hash:
            return False
        with self._lock:
            cursor = self.conn.cursor()
            row = cursor.execute("SELECT 1 FROM consumed_tx_hashes WHERE tx_hash = ?", (tx_hash,)).fetchone()
            return row is not None

    def atomic_commit_spend(self, proposal_id: str, tx_hash: str, today_key: str, max_daily_budget: Decimal) -> Tuple[bool, str]:
        """Atomically transitions an APPROVED or UNKNOWN proposal to CONFIRMED and updates spend ledger.
        Wraps reservation release, spend accumulation, consumed tx_hash recording, and proposal state change in a single transaction.
        Invariant P0-3: Strictly requires a valid non-empty on-chain transaction hash.
        """
        if not tx_hash or len(tx_hash.strip()) < 4:
            return False, "INVALID_TX_HASH: A valid on-chain transaction hash is strictly required to commit settlement"

        with self._lock:
            cursor = self.conn.cursor()
            try:
                cursor.execute("BEGIN IMMEDIATE")
                row = cursor.execute("SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,)).fetchone()
                if not row:
                    cursor.execute("ROLLBACK")
                    return False, "PROPOSAL_NOT_FOUND"

                p = dict(row)
                st_val = str(p["state"])
                if st_val.startswith("ProposalState."):
                    st_val = st_val.split(".", 1)[1]
                if st_val not in ("APPROVED", "UNKNOWN"):
                    cursor.execute("ROLLBACK")
                    return False, f"INVALID_STATE: Current state {p['state']} is not APPROVED or UNKNOWN"

                # Check tx_hash uniqueness to prevent replay attacks (Terra Round 9 P0-2)
                if tx_hash:
                    dup = cursor.execute("SELECT proposal_id FROM consumed_tx_hashes WHERE tx_hash = ?", (tx_hash,)).fetchone()
                    if dup and dup["proposal_id"] != proposal_id:
                        cursor.execute("ROLLBACK")
                        return False, f"TX_HASH_REPLAY_DETECTED: Transaction {tx_hash} already consumed by proposal {dup['proposal_id']}"

                amount = Decimal(str(p["amount_near"]))
                submitted_day = p["submitted_day"]

                # Fetch today's ledger
                today_row = cursor.execute("SELECT settled_spend, reserved_spend FROM daily_ledgers WHERE day_key = ?", (today_key,)).fetchone()
                today_settled = Decimal(str(today_row["settled_spend"])) if today_row else Decimal("0")
                today_reserved = Decimal(str(today_row["reserved_spend"])) if today_row else Decimal("0")

                # Cross-day budget check: if executed on a different day, ensure headroom exists
                if submitted_day != today_key and (today_settled + today_reserved + amount > max_daily_budget):
                    cursor.execute("ROLLBACK")
                    return False, f"CROSS_DAY_BUDGET_EXCEEDED: Headroom insufficient on {today_key}"

                # Release reservation on submitted day
                sub_row = cursor.execute("SELECT reserved_spend FROM daily_ledgers WHERE day_key = ?", (submitted_day,)).fetchone()
                sub_reserved = Decimal(str(sub_row["reserved_spend"])) if sub_row else Decimal("0")
                new_sub_reserved = max(Decimal("0"), sub_reserved - amount)
                cursor.execute("""
                    INSERT INTO daily_ledgers (day_key, settled_spend, reserved_spend)
                    VALUES (?, '0', ?)
                    ON CONFLICT(day_key) DO UPDATE SET reserved_spend = ?
                """, (submitted_day, str(new_sub_reserved), str(new_sub_reserved)))

                # Increment settled spend on today
                new_today_settled = today_settled + amount
                cursor.execute("""
                    INSERT INTO daily_ledgers (day_key, settled_spend, reserved_spend)
                    VALUES (?, ?, '0')
                    ON CONFLICT(day_key) DO UPDATE SET settled_spend = ?
                """, (today_key, str(new_today_settled), str(new_today_settled)))

                # Record consumed transaction hash
                if tx_hash:
                    cursor.execute("""
                        INSERT INTO consumed_tx_hashes (tx_hash, proposal_id, consumed_at)
                        VALUES (?, ?, ?)
                        ON CONFLICT(tx_hash) DO NOTHING
                    """, (tx_hash, proposal_id, time.time()))

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
                st_val = str(p["state"])
                if st_val.startswith("ProposalState."):
                    st_val = st_val.split(".", 1)[1]
                if st_val not in ("AWAITING_OWNER_APPROVAL", "PROPOSED"):
                    cursor.execute("ROLLBACK")
                    return False, f"CANNOT_REWRITE_STATE: Proposal in state {p['state']} cannot be rejected"

                if st_val == "AWAITING_OWNER_APPROVAL":
                    day_key = p["submitted_day"]
                    amount = Decimal(str(p["amount_near"]))
                    cur_row = cursor.execute("SELECT reserved_spend FROM daily_ledgers WHERE day_key = ?", (day_key,)).fetchone()
                    cur_res = Decimal(str(cur_row["reserved_spend"])) if cur_row else Decimal("0")
                    new_res = max(Decimal("0"), cur_res - amount)
                    cursor.execute("""
                        INSERT INTO daily_ledgers (day_key, settled_spend, reserved_spend)
                        VALUES (?, '0', ?)
                        ON CONFLICT(day_key) DO UPDATE SET reserved_spend = ?
                    """, (day_key, str(new_res), str(new_res)))

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

# Backward compatibility alias
PolicyStorage = PersistentLedgerStorage

