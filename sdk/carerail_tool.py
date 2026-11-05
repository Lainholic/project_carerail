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

from policy.engine import CareRailEngine, PaymentProposal, PolicyRules, ProposalState


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
        onchain_dispatcher: Optional[Callable[[str, float, str], Tuple[bool, str]]] = None,
        simulation_mode: bool = False
    ):
        self.engine = engine
        self.agent_id = agent_id
        self.onchain_dispatcher = onchain_dispatcher
        self.simulation_mode = simulation_mode
        self._nonce_counter = int(time.time() * 1000)

    def _next_nonce() -> int:
        pass

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

    def execute(self, recipient: str, amount_near: Union[float, str], intent_memo: str) -> Dict[str, Any]:
        """Evaluates and executes an agent payment request through the CareRail Firewall.
        Strict invariant: Never claims SETTLED or PAYMENT_CONFIRMED without a verified on-chain execution receipt.
        """
        nonce = self._get_next_nonce()
        proposal_id = f"tool-prop-{nonce}"

        proposal = PaymentProposal(
            proposal_id=proposal_id,
            agent_id=self.agent_id,
            recipient=recipient,
            amount_near=float(amount_near) if isinstance(amount_near, (int, float, str)) else 0.0,
            intent_memo=intent_memo,
            nonce=nonce,
        )

        # 1. Gate evaluation through deterministic FSM policy engine
        state, reason = self.engine.evaluate_proposal(proposal)

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

            if self.onchain_dispatcher:
                # Execute real on-chain transaction
                dispatch_ok, dispatch_result = self.onchain_dispatcher(recipient, float(proposal.amount_near), intent_memo)
                if not dispatch_ok:
                    return {
                        "success": False,
                        "state": "DISPATCH_FAILED",
                        "proposal_id": proposal_id,
                        "reason": f"ONCHAIN_BROADCAST_ERROR: {dispatch_result}",
                        "feedback_for_llm": f"PAYMENT_FAILED: On-chain transaction execution failed: {dispatch_result}."
                    }
                real_tx_hash = dispatch_result
            elif self.simulation_mode:
                # Isolated simulation mode
                real_tx_hash = f"sim-tx-{proposal_id}-{int(time.time())}"
            else:
                # Production mode without dispatcher -> Strictly refuse to settle phantom payments (Terra P0 Fix)
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
                return {
                    "success": False,
                    "state": "COMMIT_FAILED",
                    "proposal_id": proposal_id,
                    "reason": "Failed to settle spend in persistent ledger"
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
