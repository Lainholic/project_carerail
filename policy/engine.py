"""CareRail Deterministic FSM Policy Engine
Enforces fail-closed execution barriers between AI agents and NEAR blockchain.
"""

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
import os
import time
from typing import Dict, List, Optional, Tuple


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

    def compute_hash(self) -> str:
        payload = f"{self.proposal_id}:{self.agent_id}:{self.recipient}:{self.amount_near:.6f}:{self.nonce}:{self.intent_memo}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class CareRailEngine:
    def __init__(self, rules: PolicyRules):
        self.rules = rules
        self.proposals: Dict[str, PaymentProposal] = {}
        self.seen_nonces: set = set()
        self.daily_spend_ledger: Dict[str, float] = {}  # Date string -> total NEAR

    def _get_today_key(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime())

    def get_today_spent(self) -> float:
        return self.daily_spend_ledger.get(self._get_today_key(), 0.0)

    def evaluate_proposal(self, proposal: PaymentProposal) -> Tuple[ProposalState, Optional[str]]:
        """Evaluates a proposed payment against deterministic policy rules.
        Fail-Closed: Any violation results in immediate REJECTED state.
        """
        # Save record
        self.proposals[proposal.proposal_id] = proposal
        proposal.state = ProposalState.VALIDATING

        # 1. Nonce check (replay protection)
        if proposal.nonce in self.seen_nonces:
            proposal.state = ProposalState.REJECTED
            proposal.rejection_reason = "REPLAY_DETECTED: Nonce already used"
            return proposal.state, proposal.rejection_reason

        # 2. Expiry check
        if time.time() - proposal.created_at > self.rules.request_expiry_seconds:
            proposal.state = ProposalState.REJECTED
            proposal.rejection_reason = "EXPIRED: Request lifetime exceeded"
            return proposal.state, proposal.rejection_reason

        # 3. Recipient allowlist check
        if proposal.recipient not in self.rules.allowed_recipients:
            proposal.state = ProposalState.REJECTED
            proposal.rejection_reason = f"SECURITY_ALERT: Recipient '{proposal.recipient}' is not whitelisted"
            return proposal.state, proposal.rejection_reason

        # 4. Amount positivity and ceiling check
        if proposal.amount_near <= 0.0:
            proposal.state = ProposalState.REJECTED
            proposal.rejection_reason = "INVALID_AMOUNT: Amount must be strictly greater than zero"
            return proposal.state, proposal.rejection_reason

        if proposal.amount_near > self.rules.max_per_transfer_near:
            proposal.state = ProposalState.REJECTED
            proposal.rejection_reason = (
                f"LIMIT_EXCEEDED: Requested {proposal.amount_near} NEAR exceeds per-transfer limit "
                f"of {self.rules.max_per_transfer_near} NEAR"
            )
            return proposal.state, proposal.rejection_reason

        # 5. Daily cumulative spend check
        today_key = self._get_today_key()
        current_spent = self.daily_spend_ledger.get(today_key, 0.0)
        if current_spent + proposal.amount_near > self.rules.max_daily_total_near:
            proposal.state = ProposalState.REJECTED
            proposal.rejection_reason = (
                f"DAILY_CAP_EXCEEDED: New total {current_spent + proposal.amount_near:.2f} NEAR "
                f"exceeds daily cap of {self.rules.max_daily_total_near:.2f} NEAR"
            )
            return proposal.state, proposal.rejection_reason

        # 6. Prompt injection signature scan in intent memo
        memo_lower = proposal.intent_memo.lower()
        for kw in self.rules.blocked_memo_keywords:
            if kw in memo_lower:
                proposal.state = ProposalState.REJECTED
                proposal.rejection_reason = f"PROMPT_INJECTION_FLAG: Blocked keyword '{kw}' detected in memo"
                return proposal.state, proposal.rejection_reason

        # 7. Human-in-the-Loop threshold check
        if proposal.amount_near > self.rules.owner_approval_threshold_near:
            proposal.state = ProposalState.AWAITING_OWNER_APPROVAL
            return proposal.state, None

        # 8. All standard criteria passed
        self.seen_nonces.add(proposal.nonce)
        proposal.state = ProposalState.APPROVED
        return proposal.state, None

    def owner_approve(self, proposal_id: str, owner_auth_token: str = "", owner_public_key: str = "", signature_b58: str = "") -> Tuple[bool, str]:
        """Owner manually approves a held transaction.
        Supports both token authentication and cryptographic NEP-413 Ed25519 signature verification.
        """
        proposal = self.proposals.get(proposal_id)
        if not proposal:
            return False, "Proposal not found"

        if proposal.state != ProposalState.AWAITING_OWNER_APPROVAL:
            return False, f"Invalid state transition from {proposal.state}"

        # If cryptographic signature is provided, verify via NEP-413
        if owner_public_key and signature_b58:
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
        elif not owner_auth_token or len(owner_auth_token) < 8:
            return False, "Invalid owner authorization token"

        self.seen_nonces.add(proposal.nonce)
        proposal.state = ProposalState.APPROVED
        return True, "Owner approval accepted"

    def owner_reject(self, proposal_id: str, reason: str = "Rejected by owner") -> Tuple[bool, str]:
        proposal = self.proposals.get(proposal_id)
        if not proposal:
            return False, "Proposal not found"

        proposal.state = ProposalState.REJECTED
        proposal.rejection_reason = reason
        return True, "Proposal rejected by owner"

    def commit_spend(self, proposal_id: str, tx_hash: str) -> bool:
        """Records executed transaction and updates the daily spend ledger."""
        proposal = self.proposals.get(proposal_id)
        if not proposal or proposal.state != ProposalState.APPROVED:
            return False

        proposal.state = ProposalState.CONFIRMED
        proposal.tx_hash = tx_hash
        today_key = self._get_today_key()
        self.daily_spend_ledger[today_key] = self.daily_spend_ledger.get(today_key, 0.0) + proposal.amount_near
        return True
