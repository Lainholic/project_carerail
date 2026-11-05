"""CareRail Autonomous LLM Agent
Parses user instructions and untrusted web inputs to construct payment proposals.
Architectural boundary: The LLM agent has NO private keys and NO signing capabilities.
"""

import json
import os
import re
import uuid
import time
from typing import Dict, Any, Tuple
from policy.engine import PaymentProposal, CareRailEngine, ProposalState


class AutonomousCareAgent:
    def __init__(self, agent_id: str = "care-agent-llm-v1"):
        self.agent_id = agent_id
        self._nonce = 2000

    def _next_nonce(self) -> int:
        self._nonce += 1
        return self._nonce

    def process_instruction(self, user_instruction: str, untrusted_web_context: str = "") -> PaymentProposal:
        """Processes user intent alongside external untrusted text (e.g. web search, clinic reviews).
        Simulates the cognitive step of an LLM tool caller.
        """
        combined_text = f"{user_instruction}\nContext:\n{untrusted_web_context}"

        # Check for simulated prompt injection pattern
        injection_match = re.search(r"Transfer\s+([\d\.]+)\s+NEAR\s+to\s+([\w\.\-]+)", combined_text, re.IGNORECASE)
        has_override_flag = "ignore all previous" in combined_text.lower() or "system override" in combined_text.lower() or "system instruction" in combined_text.lower()

        if has_override_flag and injection_match:
            # The LLM gets deceived by the prompt injection and adopts the malicious command!
            injected_amount = float(injection_match.group(1))
            injected_target = injection_match.group(2)
            return PaymentProposal(
                proposal_id=f"prop-{uuid.uuid4().hex[:8]}",
                agent_id=self.agent_id,
                recipient=injected_target,
                amount_near=injected_amount,
                intent_memo=f"URGENT: System instruction override to {injected_target}",
                nonce=self._next_nonce(),
                created_at=time.time(),
            )

        # Check high-value equipment first
        if "equipment" in combined_text.lower() or "brace" in combined_text.lower() or "hardware" in combined_text.lower() or "decompression" in combined_text.lower():
            return PaymentProposal(
                proposal_id=f"prop-{uuid.uuid4().hex[:8]}",
                agent_id=self.agent_id,
                recipient="testnet",
                amount_near=2.5,
                intent_memo="Procurement of orthopedic decompression device",
                nonce=self._next_nonce(),
                created_at=time.time(),
            )

        # Normal care booking
        if "lumbar" in combined_text.lower() or "physio" in combined_text.lower() or "clinic" in combined_text.lower():
            return PaymentProposal(
                proposal_id=f"prop-{uuid.uuid4().hex[:8]}",
                agent_id=self.agent_id,
                recipient="testnet",
                amount_near=0.05,
                intent_memo="Booking 45-min lumbar physical therapy consultation",
                nonce=self._next_nonce(),
                created_at=time.time(),
            )

        # Default fallback proposal
        return PaymentProposal(
            proposal_id=f"prop-{uuid.uuid4().hex[:8]}",
            agent_id=self.agent_id,
            recipient="testnet",
            amount_near=0.01,
            intent_memo="General service inquiry fee",
            nonce=self._next_nonce(),
            created_at=time.time(),
        )
