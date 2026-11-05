"""CareRail AI Agent Payment Tool (SDK)
Standardized Agent Tool for LangChain, AutoGPT, and OpenAI Function Calling.
Enforces multi-layered autonomous firewall protection between LLM agents and the NEAR blockchain.
Now updated to eliminate phantom settlements (Terra P0 Fixed):
Only settles upon verified on-chain dispatch; simulation mode is strictly isolated.
"""

from decimal import Decimal
import json
import time
from typing import Any, Callable, Dict, Optional, Tuple, Union
import uuid

from policy.engine import CareRailEngine, PaymentProposal, PolicyRules, ProposalState, _to_decimal
from policy.reconciliation import NearReconciliationVerifier


class CareRailPaymentTool:
    """Production-grade autonomous payment firewall tool for AI agents.
    Inspects, sanitizes, and enforces cryptographic policies on agent payment attempts.
    """
    name: str = "carerail_pay"
    description: str = (
        "Safely transfers NEAR tokens to an authorized recipient. "
        "Every request is evaluated through the CareRail security firewall for semantic injection, "
        "dust floors, per-transfer ceilings, daily aggregate budgets, and owner authorization gates."
    )

    def __init__(
        self,
        engine: CareRailEngine,
        agent_id: str = "autonomous-agent-01",
        onchain_dispatcher: Optional[Callable[[str, Union[Decimal, float], str], Tuple[bool, str]]] = None,
        verifier: Optional[NearReconciliationVerifier] = None,
        contract_id: str = "carerail-274071e4.testnet",
        simulation_mode: bool = False
    ):
        self.engine = engine
        self.agent_id = agent_id
        self.onchain_dispatcher = onchain_dispatcher
        self.contract_id = contract_id
        self.simulation_mode = simulation_mode
        self._nonce_counter = int(time.time() * 1000)

        # Terra Round 9 & 10: True Isolated Simulation Engine with complete live state snapshot
        if self.simulation_mode:
            from policy.engine import CareRailEngine
            self.sim_engine = CareRailEngine(
                rules=self.engine.rules,
                db_path=":memory:"
            )
            # Synchronize today's spent & reserved headroom and pause state without mutating live DB (Terra Round 10 P1-9)
            today_key = self.engine._get_today_key()
            live_spent, live_res = self.engine.storage.get_daily_ledger(today_key)
            self.sim_engine.storage.set_daily_spend(today_key, live_spent)
            self.sim_engine.storage.set_daily_reserved(today_key, live_res)
            self.sim_engine.daily_spend_ledger[today_key] = live_spent
            self.sim_engine.daily_reserved_ledger[today_key] = live_res
            if self.engine.storage.get_pause_state():
                self.sim_engine.storage.set_pause_state(True)
                self.sim_engine.is_paused = True
        else:
            self.sim_engine = None

        if verifier is not None:
            self.verifier = verifier
        elif not simulation_mode:
            self.verifier = NearReconciliationVerifier(storage=self.engine.storage)
        else:
            self.verifier = None

    def _get_next_nonce(self) -> int:
        self._nonce_counter += 1
        return self._nonce_counter

    def to_openai_tool(self) -> Dict[str, Any]:
        """Exports standard OpenAI Function Calling Tool definition."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "recipient": {
                            "type": "string",
                            "description": "Authorized NEAR account ID of the service provider (e.g. care-clinic.testnet)"
                        },
                        "amount_near": {
                            "type": "number",
                            "description": "Amount of NEAR tokens to transfer (must be positive and within budget)"
                        },
                        "intent_memo": {
                            "type": "string",
                            "description": "Auditable business rationale and intent description for this transfer"
                        }
                    },
                    "required": ["recipient", "amount_near", "intent_memo"]
                }
            }
        }

    def execute(self, recipient: str, amount_near: Union[Decimal, float, str, int], intent_memo: str, client_idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        """Evaluates and executes an agent payment request through the CareRail Firewall.
        Strict invariant: Never claims SETTLED or PAYMENT_CONFIRMED without a verified on-chain execution receipt.
        Supports client_idempotency_key for durable payment-intent deduplication (Terra Round 10 P0-2).
        """
        nonce = self._get_next_nonce()
        if client_idempotency_key:
            proposal_id = f"tool-prop-{client_idempotency_key}"
        else:
            unique_suffix = uuid.uuid4().hex[:8]
            proposal_id = f"tool-prop-{nonce}-{unique_suffix}"

        amount_dec = _to_decimal(amount_near) if isinstance(amount_near, (int, float, str, Decimal)) else Decimal("0")
        proposal = PaymentProposal(
            proposal_id=proposal_id,
            agent_id=self.agent_id,
            recipient=recipient,
            amount_near=amount_dec,
            intent_memo=intent_memo,
            nonce=nonce,
        )

        # 1. Gate evaluation through deterministic FSM policy engine
        # In simulation mode, evaluate strictly on ephemeral memory engine to guarantee zero live mutation (Terra Round 9 P1-5)
        target_engine = self.sim_engine if self.simulation_mode else self.engine
        state, reason = target_engine.evaluate_proposal(proposal)

        # 2. Case: REJECTED (Fail-Closed)
        if state == ProposalState.REJECTED:
            return {
                "success": False,
                "state": "REJECTED",
                "proposal_id": proposal_id,
                "reason": reason,
                "feedback_for_llm": f"FIREWALL_BLOCKED: {reason}. You must reconsider the request or seek human owner intervention."
            }

        # 3. Case: AWAITING_OWNER_APPROVAL (Human-in-the-Loop)
        if state == ProposalState.AWAITING_OWNER_APPROVAL:
            return {
                "success": False,
                "state": "AWAITING_OWNER_APPROVAL",
                "proposal_id": proposal_id,
                "reserved_amount": float(proposal.amount_near),
                "feedback_for_llm": (
                    f"TRANSACTION_HELD: Amount ({proposal.amount_near} NEAR) exceeds autonomous limit. "
                    f"Awaiting owner cryptographic signature (NEP-413) on proposal '{proposal_id}'."
                )
            }

        # 4. Case: APPROVED -> Dispatch to Blockchain
        if state == ProposalState.APPROVED:
            real_tx_hash = None

            if self.simulation_mode:
                # Isolated simulation mode - NEVER touches live blockchain or production DB (Terra Round 9 P1-5)
                real_tx_hash = f"sim-tx-{proposal_id}-{int(time.time())}"
                return {
                    "success": True,
                    "state": "SIMULATED_SETTLED",
                    "proposal_id": proposal_id,
                    "tx_hash": real_tx_hash,
                    "recipient": recipient,
                    "amount_near": float(proposal.amount_near),
                    "remaining_daily_budget": target_engine.get_remaining_daily_budget(),
                    "feedback_for_llm": f"SIMULATION_CONFIRMED: Policy approved {proposal.amount_near} NEAR transfer to {recipient}. (Simulation mode: zero live state mutated)."
                }
            elif self.onchain_dispatcher:
                # Production mode: Must have verifier to prevent phantom settlement (Terra Round 7 P0-1 Fixed)
                if not self.verifier:
                    self.engine.release_reservation(proposal_id, reason="VERIFIER_MISSING")
                    return {
                        "success": False,
                        "state": "VERIFIER_MISSING",
                        "proposal_id": proposal_id,
                        "reason": "PRODUCTION_INVARIANT: Cannot settle without a live on-chain reconciliation verifier.",
                        "feedback_for_llm": "PAYMENT_ABORTED: No reconciliation verifier configured in production mode."
                    }

                # Execute real on-chain transaction
                try:
                    dispatch_ok, dispatch_result = self.onchain_dispatcher(recipient, float(proposal.amount_near), intent_memo)
                except Exception as ex:
                    dispatch_ok = False
                    dispatch_result = f"DISPATCHER_EXCEPTION: {str(ex)}"

                if not dispatch_ok:
                    # Strict prefix check: only unambiguous local pre-broadcast failures may release reservation (Terra Round 10 P0-4)
                    is_preflight = dispatch_result.startswith("PRE_FLIGHT:") or dispatch_result.startswith("NOT_BROADCAST:")
                    if is_preflight:
                        # Definitive pre-broadcast failure: safe to release reservation
                        self.engine.release_reservation(proposal_id, reason=f"DISPATCH_PREFLIGHT_FAILED: {dispatch_result}")
                        return {
                            "success": False,
                            "state": "DISPATCH_FAILED",
                            "proposal_id": proposal_id,
                            "reason": f"ONCHAIN_BROADCAST_PREFLIGHT_ERROR: {dispatch_result}",
                            "feedback_for_llm": f"PAYMENT_ABORTED: Pre-broadcast validation failed: {dispatch_result}. Reservation released."
                        }
                    else:
                        # Terra Round 9 P0-1: Ambiguous failure (e.g. network timeout). Transaction may be in flight!
                        # Retain reservation in UNKNOWN state to prevent double-spending.
                        proposal.state = ProposalState.UNKNOWN
                        self.engine.storage.save_proposal(proposal.__dict__)
                        return {
                            "success": False,
                            "state": "PENDING_RECONCILIATION",
                            "proposal_id": proposal_id,
                            "reason": f"AMBIGUOUS_BROADCAST_STATUS: {dispatch_result}",
                            "feedback_for_llm": (
                                f"PAYMENT_AMBIGUOUS: Transaction submission status is unconfirmed ({dispatch_result}). "
                                f"Budget reservation remains locked in UNKNOWN state to prevent double-spending. DO NOT retry."
                            )
                        }

                real_tx_hash = dispatch_result

                # Cross-verify with NearReconciliationVerifier before claiming SETTLED (Terra Round 6, 7, 8, 9 Fixed)
                rec_ok, rec_msg = self.verifier.verify_and_reconcile(
                    tx_hash=real_tx_hash,
                    sender_id=self.agent_id,
                    contract_id=self.contract_id,
                    expected_recipient=recipient,
                    expected_amount_near=proposal.amount_near,
                    expected_proposal_id=proposal_id,
                    allow_mock=False
                )
                if not rec_ok:
                    # Invariant P0-1: DO NOT release reservation on unverified broadcast.
                    # Retain reservation and save tx_hash for future recovery.
                    proposal.state = ProposalState.UNKNOWN
                    proposal.tx_hash = real_tx_hash
                    self.engine.storage.save_proposal(proposal.__dict__)
                    return {
                        "success": False,
                        "state": "PENDING_RECONCILIATION",
                        "proposal_id": proposal_id,
                        "tx_hash": real_tx_hash,
                        "reason": f"ONCHAIN_SETTLEMENT_PENDING: {rec_msg}",
                        "feedback_for_llm": (
                            f"PAYMENT_PENDING: Transaction broadcast to NEAR network (Tx: {real_tx_hash}), "
                            f"but final reconciliation is unconfirmed ({rec_msg}). "
                            f"Budget reservation remains locked to prevent double-spending. DO NOT retry."
                        )
                    }
            else:
                # Production mode without dispatcher -> Strictly refuse to settle phantom payments (Terra P0 Fix)
                self.engine.release_reservation(proposal_id, reason="DISPATCHER_MISSING")
                return {
                    "success": False,
                    "state": "DISPATCHER_MISSING",
                    "proposal_id": proposal_id,
                    "reason": "PRODUCTION_INVARIANT: Cannot settle without a live on-chain transaction dispatcher.",
                    "feedback_for_llm": "PAYMENT_ABORTED: No on-chain dispatcher configured in production mode."
                }

            # Commit settled spend in persistent ledger
            commit_ok = self.engine.commit_spend(proposal_id, real_tx_hash)
            if not commit_ok:
                proposal.state = ProposalState.UNKNOWN
                self.engine.storage.save_proposal(proposal.__dict__)
                return {
                    "success": False,
                    "state": "COMMIT_UNRESOLVED",
                    "proposal_id": proposal_id,
                    "tx_hash": real_tx_hash,
                    "reason": "Failed to shift reservation to confirmed spend in ledger (manual intervention required)"
                }

            final_state = "SIMULATED_SETTLED" if self.simulation_mode else "SETTLED"
            return {
                "success": True,
                "state": final_state,
                "proposal_id": proposal_id,
                "tx_hash": real_tx_hash,
                "recipient": recipient,
                "amount_near": float(proposal.amount_near),
                "remaining_daily_budget": self.engine.get_remaining_daily_budget(),
                "feedback_for_llm": (
                    f"PAYMENT_CONFIRMED: Successfully transferred {proposal.amount_near} NEAR to {recipient} (Tx: {real_tx_hash})."
                    if not self.simulation_mode else
                    f"SIMULATION_CONFIRMED: Policy approved {proposal.amount_near} NEAR transfer to {recipient}."
                )
            }

        return {
            "success": False,
            "state": str(state),
            "reason": f"Unhandled proposal state {state}"
        }
