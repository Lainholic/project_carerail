"""CareRail Deterministic FSM Policy Engine
Enforces fail-closed execution barriers between AI agents and NEAR blockchain.
Now updated with strict cryptographic-only approvals, atomic budget reservations,
immutable nonce replay protection, anti-dust floors, emergency pause, day-boundary isolation,
SQLite persistent ledger storage with full proposal restoration, and atomic multi-statement transitions.
"""

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import math
import os
import re
import time
from typing import Dict, List, Optional, Tuple

from policy.storage import PersistentLedgerStorage


class ProposalState(str, Enum):
    PROPOSED = "PROPOSED"
    VALIDATING = "VALIDATING"
    AWAITING_OWNER_APPROVAL = "AWAITING_OWNER_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    RESERVED = "RESERVED"
    SUBMITTED = "SUBMITTED"
    CONFIRMED = "CONFIRMED"
    UNKNOWN = "UNKNOWN"


@dataclass
class PolicyRules:
    version: str
    policy_id: str
    allowed_recipients: List[str]
    max_per_transfer_near: float
    max_daily_total_near: float
    owner_approval_threshold_near: float
    request_expiry_seconds: int
    reject_unknown_actions: bool
    blocked_memo_keywords: List[str]
    owner_public_key: Optional[str] = None
    min_transfer_floor_near: float = 0.001
    max_pending_proposals: int = 50

    @classmethod
    def load_from_json(cls, path: str) -> "PolicyRules":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls(
            version=data["version"],
            policy_id=data["policy_id"],
            allowed_recipients=data["allowed_recipients"],
            max_per_transfer_near=float(data["max_per_transfer_near"]),
            max_daily_total_near=float(data["max_daily_total_near"]),
            owner_approval_threshold_near=float(data["owner_approval_threshold_near"]),
            request_expiry_seconds=int(data["request_expiry_seconds"]),
            reject_unknown_actions=bool(data["reject_unknown_actions"]),
            blocked_memo_keywords=[k.lower() for k in data.get("blocked_memo_keywords", [])],
            owner_public_key=data.get("owner_public_key"),
            min_transfer_floor_near=float(data.get("min_transfer_floor_near", 0.001)),
            max_pending_proposals=int(data.get("max_pending_proposals", 50)),
        )


@dataclass
class PaymentProposal:
    proposal_id: str
    agent_id: str
    recipient: str
    amount_near: float
    intent_memo: str
    nonce: int
    created_at: float = field(default_factory=time.time)
    state: ProposalState = ProposalState.PROPOSED
    rejection_reason: Optional[str] = None
    tx_hash: Optional[str] = None
    submitted_day: str = field(default_factory=lambda: time.strftime("%Y-%m-%d", time.gmtime()))

    def compute_hash(self) -> str:
        payload = f"{self.proposal_id}:{self.agent_id}:{self.recipient}:{self.amount_near}:{self.nonce}:{self.intent_memo}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class CareRailEngine:
    def __init__(self, rules: PolicyRules, db_path: str = ":memory:"):
        self.rules = rules
        self.storage = PersistentLedgerStorage(db_path)
        self.proposals: Dict[str, PaymentProposal] = {}
        self.seen_nonces: set = self.storage.get_all_nonces()
        self.daily_spend_ledger: Dict[str, float] = {}      # Date string -> settled total NEAR
        self.daily_reserved_ledger: Dict[str, float] = {}   # Date string -> pending reserved NEAR
        self.is_paused: bool = self.storage.get_pause_state()

        # 1. Restore all daily ledgers from storage
        all_ledgers = self.storage.get_all_daily_ledgers()
        for day_k, (settled, reserved) in all_ledgers.items():
            self.daily_spend_ledger[day_k] = settled
            self.daily_reserved_ledger[day_k] = reserved

        today_key = self._get_today_key()
        if today_key not in self.daily_spend_ledger:
            self.daily_spend_ledger[today_key] = 0.0
            self.daily_reserved_ledger[today_key] = 0.0

        # 2. Restore all persistent proposals across restarts (Fix for P1-B restoration gap)
        stored_proposals = self.storage.get_all_proposals()
        for pid, p in stored_proposals.items():
            try:
                state_enum = ProposalState(p["state"])
            except ValueError:
                state_enum = ProposalState.REJECTED

            restored_proposal = PaymentProposal(
                proposal_id=p["proposal_id"],
                agent_id=p["agent_id"],
                recipient=p["recipient"],
                amount_near=float(p["amount_near"]),
                intent_memo=p["intent_memo"],
                nonce=int(p["nonce"]),
                created_at=float(p["created_at"]),
                state=state_enum,
                rejection_reason=p.get("rejection_reason"),
                tx_hash=p.get("tx_hash"),
                submitted_day=p.get("submitted_day") or today_key,
            )
            self.proposals[pid] = restored_proposal
            self.seen_nonces.add(int(p["nonce"]))

    def _get_today_key(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime())

    def get_today_spent(self) -> float:
        today_key = self._get_today_key()
        return self.daily_spend_ledger.get(today_key, 0.0)

    def get_remaining_daily_budget(self) -> float:
        today_key = self._get_today_key()
        spent = self.daily_spend_ledger.get(today_key, 0.0)
        reserved = self.daily_reserved_ledger.get(today_key, 0.0)
        return max(0.0, self.rules.max_daily_total_near - (spent + reserved))

    def set_emergency_pause(self, paused: bool) -> bool:
        self.is_paused = paused
        self.storage.set_pause_state(paused)
        return self.is_paused

    def evaluate_proposal(self, proposal: PaymentProposal) -> Tuple[ProposalState, Optional[str]]:
        """Strict deterministic FSM transition evaluation.
        Fail-closed: Any violation immediately halts into REJECTED state.
        """
        # Invariant P0-B: Check duplicate BEFORE mutating any state on the passed proposal object
        if proposal.proposal_id in self.proposals:
            existing = self.proposals[proposal.proposal_id]
            return existing.state, f"DUPLICATE_PROPOSAL_ID: Proposal ID {proposal.proposal_id} already exists in state {existing.state}"

        # Invariant: Persistent storage duplicate check
        if self.storage.get_proposal(proposal.proposal_id):
            return ProposalState.REJECTED, f"DUPLICATE_PROPOSAL_ID: Proposal ID {proposal.proposal_id} already stored in persistent DB"

        if proposal.nonce in self.seen_nonces or self.storage.is_nonce_consumed(proposal.nonce):
            self.seen_nonces.add(proposal.nonce)
            return ProposalState.REJECTED, f"REPLAY_DETECTED: Nonce {proposal.nonce} already consumed"

        proposal.state = ProposalState.VALIDATING

        # Circuit Breaker Check
        if self.is_paused:
            proposal.state = ProposalState.REJECTED
            proposal.rejection_reason = "SECURITY_ALERT: Engine is paused by emergency circuit breaker"
            return proposal.state, proposal.rejection_reason

        # 0. Float, NaN, Infinity, and Floor sanitization
        if not isinstance(proposal.amount_near, (int, float)) or not math.isfinite(proposal.amount_near) or proposal.amount_near <= 0.0:
            proposal.state = ProposalState.REJECTED
            proposal.rejection_reason = "NUMERIC_VIOLATION: Payment amount must be a positive finite number"
            return proposal.state, proposal.rejection_reason

        if proposal.amount_near < self.rules.min_transfer_floor_near:
            proposal.state = ProposalState.REJECTED
            proposal.rejection_reason = f"ANTI_DUST_FLOOR_VIOLATION: Amount {proposal.amount_near} NEAR is below minimum floor {self.rules.min_transfer_floor_near} NEAR"
            return proposal.state, proposal.rejection_reason

        # 1. Pending proposal pool limit (DoS defense)
        pending_count = sum(1 for p in self.proposals.values() if p.state in (ProposalState.PROPOSED, ProposalState.AWAITING_OWNER_APPROVAL))
        if pending_count >= self.rules.max_pending_proposals:
            proposal.state = ProposalState.REJECTED
            proposal.rejection_reason = f"DOS_PROTECTION: Pending proposals pool exhausted ({pending_count}/{self.rules.max_pending_proposals})"
            return proposal.state, proposal.rejection_reason

        # 2. Recipient Whitelist
        if proposal.recipient not in self.rules.allowed_recipients:
            proposal.state = ProposalState.REJECTED
            proposal.rejection_reason = f"SECURITY_ALERT: Recipient '{proposal.recipient}' is not whitelisted in policy allowlist"
            return proposal.state, proposal.rejection_reason

        # 3. Expiry / Stale Check
        now = time.time()
        if now - proposal.created_at > self.rules.request_expiry_seconds:
            proposal.state = ProposalState.REJECTED
            proposal.rejection_reason = "REQUEST_EXPIRED: Proposal exceeded max validity window"
            return proposal.state, proposal.rejection_reason

        # 4. Per-Transfer Ceiling
        if proposal.amount_near > self.rules.max_per_transfer_near:
            proposal.state = ProposalState.REJECTED
            proposal.rejection_reason = f"LIMIT_EXCEEDED: Amount {proposal.amount_near} NEAR exceeds max per transfer limit {self.rules.max_per_transfer_near} NEAR"
            return proposal.state, proposal.rejection_reason

        # 5. Daily Total Ceiling with Headroom Reservation
        today_key = self._get_today_key()
        current_spent = self.daily_spend_ledger.get(today_key, 0.0)
        current_reserved = self.daily_reserved_ledger.get(today_key, 0.0)

        if (current_spent + current_reserved + proposal.amount_near) > self.rules.max_daily_total_near:
            proposal.state = ProposalState.REJECTED
            proposal.rejection_reason = f"DAILY_CAP_EXCEEDED: Amount exceeds available daily budget (Spent: {current_spent}, Reserved: {current_reserved}, Max: {self.rules.max_daily_total_near})"
            return proposal.state, proposal.rejection_reason

        # 6. Prompt Injection Defense (Semantic anomaly keyword filtering)
        memo_lower = proposal.intent_memo.lower()
        for kw in self.rules.blocked_memo_keywords:
            if kw in memo_lower:
                proposal.state = ProposalState.REJECTED
                proposal.rejection_reason = f"PROMPT_INJECTION_FLAG: Blocked keyword '{kw}' detected in memo"
                return proposal.state, proposal.rejection_reason

        # Consume nonce atomically in DB first
        proposal.submitted_day = today_key
        consumed_ok = self.storage.consume_nonce(proposal.nonce, proposal.created_at)
        if not consumed_ok:
            proposal.state = ProposalState.REJECTED
            proposal.rejection_reason = f"REPLAY_DETECTED: Nonce {proposal.nonce} already consumed"
            return proposal.state, proposal.rejection_reason

        self.seen_nonces.add(proposal.nonce)
        self.proposals[proposal.proposal_id] = proposal

        # 7. Human-in-the-Loop threshold check
        if proposal.amount_near > self.rules.owner_approval_threshold_near:
            proposal.state = ProposalState.AWAITING_OWNER_APPROVAL
            self.daily_reserved_ledger[today_key] = current_reserved + proposal.amount_near
            self.storage.set_daily_reserved(today_key, self.daily_reserved_ledger[today_key])
            self.storage.save_proposal(proposal.__dict__)
            return proposal.state, None

        # 8. All standard criteria passed -> APPROVED with reservation
        proposal.state = ProposalState.APPROVED
        self.daily_reserved_ledger[today_key] = current_reserved + proposal.amount_near
        self.storage.set_daily_reserved(today_key, self.daily_reserved_ledger[today_key])
        self.storage.save_proposal(proposal.__dict__)
        return proposal.state, None

    def owner_approve(self, proposal_id: str, owner_public_key: str, signature_b58: str) -> Tuple[bool, str]:
        """Owner manually approves a held transaction.
        CRITICAL P0: Strictly requires registered owner_public_key. No arbitrary key bypasses.
        """
        if self.is_paused:
            return False, "SECURITY_ALERT: Engine is paused by emergency circuit breaker"

        proposal = self.proposals.get(proposal_id)
        if not proposal:
            return False, "Proposal not found"

        if proposal.state != ProposalState.AWAITING_OWNER_APPROVAL:
            return False, f"Invalid state transition from {proposal.state}"

        if not self.rules.owner_public_key:
            return False, "CONFIGURATION_ERROR: owner_public_key must be configured in PolicyRules"

        if not owner_public_key or not signature_b58:
            return False, "CRYPTOGRAPHIC_SIGNATURE_REQUIRED: Valid owner_public_key and signature_b58 are strictly required"

        # Enforce identity match with pre-registered authorized owner
        if owner_public_key != self.rules.owner_public_key:
            return False, f"KEY_MISMATCH: Provided key {owner_public_key} does not match authorized owner {self.rules.owner_public_key}"

        from policy.owner_auth import Nep413Authorizer
        is_valid = Nep413Authorizer.verify_approval(
            owner_public_key=owner_public_key,
            proposal_id=proposal.proposal_id,
            amount_near=proposal.amount_near,
            recipient=proposal.recipient,
            nonce=proposal.nonce,
            signature_b58=signature_b58,
        )
        if not is_valid:
            return False, "CRYPTOGRAPHIC_VERIFICATION_FAILED: Invalid NEP-413 owner signature"

        proposal.state = ProposalState.APPROVED
        self.storage.save_proposal(proposal.__dict__)
        return True, "Owner cryptographic approval accepted"

    def owner_reject(self, proposal_id: str, reason: str = "Rejected by owner") -> Tuple[bool, str]:
        proposal = self.proposals.get(proposal_id)
        if not proposal:
            return False, "Proposal not found"

        if proposal.state not in (ProposalState.AWAITING_OWNER_APPROVAL, ProposalState.PROPOSED):
            return False, f"CANNOT_REWRITE_STATE: Proposal in state {proposal.state} cannot be rejected"

        success, msg = self.storage.atomic_owner_reject(proposal_id, reason)
        if not success:
            return False, msg

        if proposal.state == ProposalState.AWAITING_OWNER_APPROVAL:
            day_key = proposal.submitted_day
            self.daily_reserved_ledger[day_key] = max(0.0, self.daily_reserved_ledger.get(day_key, 0.0) - proposal.amount_near)

        proposal.state = ProposalState.REJECTED
        proposal.rejection_reason = reason
        return True, "Proposal rejected by owner"

    def commit_spend(self, proposal_id: str, tx_hash: str) -> bool:
        """Records executed transaction, shifts reservation to settled daily spend.
        Invariant P0-A: Atomically executes under SQLite transaction and re-verifies headroom.
        """
        proposal = self.proposals.get(proposal_id)
        if not proposal or proposal.state != ProposalState.APPROVED:
            return False

        today_key = self._get_today_key()
        success, msg = self.storage.atomic_commit_spend(proposal_id, tx_hash, today_key, self.rules.max_daily_total_near)
        if not success:
            return False

        # Synchronize local memory cache from updated ledger
        day_key = proposal.submitted_day
        settled_sub, reserved_sub = self.storage.get_daily_ledger(day_key)
        self.daily_reserved_ledger[day_key] = reserved_sub

        settled_today, reserved_today = self.storage.get_daily_ledger(today_key)
        self.daily_spend_ledger[today_key] = settled_today
        self.daily_reserved_ledger[today_key] = reserved_today

        proposal.state = ProposalState.CONFIRMED
        proposal.tx_hash = tx_hash
        return True
