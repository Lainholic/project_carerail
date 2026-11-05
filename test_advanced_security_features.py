"""CareRail Advanced Security Features Verification Suite
Tests next-generation institutional AI security capabilities:
1. Sliding Window Velocity Throttling & Auto-Freeze Circuit Breaker
2. Multi-Tenant Sub-Budget Sandboxing & Per-Agent Quota Isolation
3. Cryptographic Merkle Audit Trail & Tamper-Evident Inclusion Proofs
"""

from decimal import Decimal
import time
import unittest

from policy.engine import (
    CareRailEngine,
    PaymentProposal,
    PolicyRules,
    ProposalState,
    _to_decimal
)
from policy.audit_merkle import MerkleAuditTrail


class TestAdvancedSecurityFeatures(unittest.TestCase):
    def setUp(self):
        self.rules = PolicyRules(
            version="1.0.0",
            policy_id="adv_security_test",
            allowed_recipients=["testnet", "care-provider.testnet", "pharmacy.testnet"],
            max_per_transfer_near=5.0,
            max_daily_total_near=20.0,
            owner_approval_threshold_near=2.0,
            request_expiry_seconds=300,
            reject_unknown_actions=True,
            blocked_memo_keywords=["drain", "urgent", "bypass"],
            owner_public_key="ed25519:6E8sCci9badyRkXb3JoRtubqwUMoVMMNaY2LTCSt6Z11",
            min_transfer_floor_near=0.001,
            max_pending_proposals=50,
            max_requests_per_minute=5,  # Tight limit for rapid testing
            agent_quotas={
                "care-booking-agent": {"per_tx_limit": 1.0, "daily_limit": 3.0},
                "pharmacy-agent": {"per_tx_limit": 2.5, "daily_limit": 10.0}
            }
        )
        self.engine = CareRailEngine(self.rules, db_path=":memory:")

    def test_case_1_velocity_rate_limiting_and_auto_freeze(self):
        """Case 1: Rapid-fire requests are throttled, and repeat bursts trigger auto-freeze."""
        agent_id = "spammy-agent-01"

        # 1. Fire 5 requests rapidly (within limit of 5 req/min)
        for i in range(5):
            prop = PaymentProposal(
                proposal_id=f"prop-vel-{i}",
                agent_id=agent_id,
                recipient="testnet",
                amount_near=Decimal("0.01"),
                intent_memo=f"Rapid call {i}",
                nonce=8000 + i
            )
            st, reason = self.engine.evaluate_proposal(prop)
            self.assertEqual(st, ProposalState.APPROVED, f"Req {i} should be approved")

        # 2. 6th request MUST be rejected due to VELOCITY_LIMIT_EXCEEDED
        prop_overflow = PaymentProposal(
            proposal_id="prop-vel-overflow",
            agent_id=agent_id,
            recipient="testnet",
            amount_near=Decimal("0.01"),
            intent_memo="Overflow call",
            nonce=8010
        )
        st, reason = self.engine.evaluate_proposal(prop_overflow)
        self.assertEqual(st, ProposalState.REJECTED)
        self.assertIn("VELOCITY_LIMIT_EXCEEDED", reason)

        # 3. Repeated burst attacks trigger Auto-Circuit-Breaker Emergency Pause
        for j in range(4):
            prop_burst = PaymentProposal(
                proposal_id=f"prop-burst-{j}",
                agent_id=agent_id,
                recipient="testnet",
                amount_near=Decimal("0.01"),
                intent_memo=f"Burst attack {j}",
                nonce=8020 + j
            )
            self.engine.evaluate_proposal(prop_burst)

        # 5th violation triggers auto-pause
        self.assertTrue(self.engine.is_paused, "Engine should be auto-paused after 5 consecutive velocity violations!")

    def test_case_2_multi_tenant_sub_budget_sandboxing(self):
        """Case 2: Different agents are confined strictly within their independent sub-budget quotas."""
        # A. Care Booking Agent (per-tx ceiling = 1.0 NEAR, global is 5.0)
        # Attempting 1.5 NEAR: Within global limit, but exceeds agent-specific ceiling!
        prop_care = PaymentProposal(
            proposal_id="prop-care-over",
            agent_id="care-booking-agent",
            recipient="care-provider.testnet",
            amount_near=Decimal("1.5"),
            intent_memo="Large booking",
            nonce=8101
        )
        st, reason = self.engine.evaluate_proposal(prop_care)
        self.assertEqual(st, ProposalState.REJECTED)
        self.assertIn("AGENT_QUOTA_EXCEEDED", reason)

        # Attempting 0.8 NEAR: Within agent ceiling -> Must SUCCEED
        prop_care_ok = PaymentProposal(
            proposal_id="prop-care-ok",
            agent_id="care-booking-agent",
            recipient="care-provider.testnet",
            amount_near=Decimal("0.8"),
            intent_memo="Valid booking",
            nonce=8102
        )
        st, _ = self.engine.evaluate_proposal(prop_care_ok)
        self.assertEqual(st, ProposalState.APPROVED)

        # B. Pharmacy Agent (per-tx ceiling = 2.5 NEAR)
        # Attempting 2.0 NEAR: Valid for pharmacy-agent
        prop_pharm_ok = PaymentProposal(
            proposal_id="prop-pharm-ok",
            agent_id="pharmacy-agent",
            recipient="pharmacy.testnet",
            amount_near=Decimal("2.0"),
            intent_memo="Valid meds",
            nonce=8103
        )
        st, _ = self.engine.evaluate_proposal(prop_pharm_ok)
        self.assertEqual(st, ProposalState.APPROVED)

    def test_case_3_cryptographic_merkle_audit_trail(self):
        """Case 3: All processed proposals build a cryptographic Merkle Tree with verifiable inclusion proofs."""
        trail = MerkleAuditTrail()

        # Record 4 distinct proposal events
        records = [
            {"proposal_id": "p-1", "agent_id": "a-1", "recipient": "r-1", "amount_near": "0.1", "state": "APPROVED", "nonce": 1, "created_at": 100.0},
            {"proposal_id": "p-2", "agent_id": "a-2", "recipient": "r-2", "amount_near": "0.2", "state": "REJECTED", "nonce": 2, "created_at": 101.0},
            {"proposal_id": "p-3", "agent_id": "a-1", "recipient": "r-3", "amount_near": "0.5", "state": "APPROVED", "nonce": 3, "created_at": 102.0},
            {"proposal_id": "p-4", "agent_id": "a-3", "recipient": "r-4", "amount_near": "1.0", "state": "SETTLED",  "nonce": 4, "created_at": 103.0},
        ]

        for r in records:
            trail.add_record(r)

        root = trail.get_merkle_root()
        self.assertEqual(len(root), 64, "Merkle Root must be a 32-byte hex hash (64 chars)")

        # Verify Inclusion Proof for record 2 (p-3)
        leaf_hash, proof = trail.generate_proof(2)
        is_valid = MerkleAuditTrail.verify_proof(leaf_hash, proof, root)
        self.assertTrue(is_valid, "Merkle inclusion proof must be cryptographically valid")

        # Tamper Detection: If an attacker alters amount in record 2 from '0.5' to '500.0'
        tampered_record = dict(records[2])
        tampered_record["amount_near"] = "500.0"
        tampered_leaf = MerkleAuditTrail.hash_leaf(tampered_record)

        # Verification with tampered leaf MUST FAIL
        is_tampered_valid = MerkleAuditTrail.verify_proof(tampered_leaf, proof, root)
        self.assertFalse(is_tampered_valid, "Merkle verification MUST detect altered record data!")


if __name__ == "__main__":
    unittest.main()
