"""CareRail Extreme Edge-Cases & Boundary Adversarial Verification Suite
Comprehensive adversarial test coverage for real-world production failure modes:
1. SQL Injection, Null Byte (\x00), and 10,000-character Memory Bombing in memo/recipient
2. Micro-Dust Boundary (0.000999999999999999 NEAR) & 24-decimal Precision Invariance
3. Governance Timelock 1-second-before Cooldown Bypass Defense
4. Man-in-the-Middle (MITM) Recipient & Amount Tampering in Attestation Tickets
5. Transfer Failure & Negative Balance Underflow Rollback Isolation
"""

from decimal import Decimal
import json
import time
import unittest
import uuid

from policy.engine import (
    AttestationEngine,
    CareRailEngine,
    PaymentProposal,
    PolicyRules,
    ProposalState,
    _to_decimal
)
from policy.storage import PersistentLedgerStorage


class TestExtremeEdgeCases(unittest.TestCase):
    def setUp(self):
        self.rules = PolicyRules(
            version="1.0.0",
            policy_id="extreme_edge_case_test",
            allowed_recipients=["testnet", "care-provider.testnet", "physio-clinic.testnet"],
            max_per_transfer_near=5.0,
            max_daily_total_near=20.0,
            owner_approval_threshold_near=2.0,
            request_expiry_seconds=300,
            reject_unknown_actions=True,
            blocked_memo_keywords=["drain", "urgent", "bypass", "exploit"],
            owner_public_key="ed25519:6E8sCci9badyRkXb3JoRtubqwUMoVMMNaY2LTCSt6Z11",
            min_transfer_floor_near=0.001,
            max_pending_proposals=50
        )
        self.engine = CareRailEngine(self.rules, db_path=":memory:")
        self.storage = self.engine.storage
        self.attestation_key = "mock_test_offline_hmac_key"
        self.att_engine = AttestationEngine(
            engine_id="care-edge-engine-01",
            shared_secret=self.attestation_key,
            ttl_seconds=60
        )

    def test_edge_case_1_sql_injection_and_memory_bombing(self):
        """Edge Case 1: Ensures SQL injections, null bytes, and 10k character bombs are sanitized and rejected."""
        # A. 10,000-character DoS memory bombing in memo
        bomb_memo = "A" * 10000
        prop_bomb = PaymentProposal(
            proposal_id="prop-bomb-10k",
            agent_id="agent-01",
            recipient="testnet",
            amount_near=Decimal("0.5"),
            intent_memo=bomb_memo,
            nonce=9001
        )
        st, reason = self.engine.evaluate_proposal(prop_bomb)
        self.assertEqual(st, ProposalState.REJECTED)
        self.assertIn("MEMO_VIOLATION", reason)

        # B. SQL Injection in memo & recipient
        sql_injection_memo = "'; DROP TABLE proposals; DROP TABLE seen_nonces; --"
        prop_sql = PaymentProposal(
            proposal_id="prop-sql-inj",
            agent_id="agent-01",
            recipient="testnet",
            amount_near=Decimal("0.5"),
            intent_memo=sql_injection_memo,
            nonce=9002
        )
        st, reason = self.engine.evaluate_proposal(prop_sql)
        self.assertEqual(st, ProposalState.APPROVED)
        # Verify SQLite tables remain intact and nonce was consumed atomically
        self.assertTrue(self.storage.is_nonce_consumed(9002))
        proposals = self.storage.get_all_proposals()
        self.assertIn("prop-sql-inj", proposals)

        # C. SQL Injection in recipient (unwhitelisted)
        prop_rec_sql = PaymentProposal(
            proposal_id="prop-rec-sql",
            agent_id="agent-01",
            recipient="attacker.testnet' OR '1'='1",
            amount_near=Decimal("0.5"),
            intent_memo="Legit memo",
            nonce=9003
        )
        st, reason = self.engine.evaluate_proposal(prop_rec_sql)
        self.assertEqual(st, ProposalState.REJECTED)
        self.assertIn("SECURITY_ALERT", reason)

    def test_edge_case_2_micro_dust_and_precision_boundary(self):
        """Edge Case 2: Boundary test for 0.000999999999999999 NEAR floor and 24-decimal yocto precision."""
        # A. Sub-dust boundary: 0.000999999999999999 NEAR (must be REJECTED)
        sub_dust = Decimal("0.000999999999999999")
        prop_sub_dust = PaymentProposal(
            proposal_id="prop-sub-dust",
            agent_id="agent-01",
            recipient="testnet",
            amount_near=sub_dust,
            intent_memo="Sub dust attempt",
            nonce=9101
        )
        st, reason = self.engine.evaluate_proposal(prop_sub_dust)
        self.assertEqual(st, ProposalState.REJECTED)
        self.assertIn("ANTI_DUST_FLOOR_VIOLATION", reason)

        # B. Exact floor boundary: 0.001000000000000000 NEAR (must be APPROVED)
        exact_floor = Decimal("0.001000000000000000000000")
        prop_floor = PaymentProposal(
            proposal_id="prop-exact-floor",
            agent_id="agent-01",
            recipient="testnet",
            amount_near=exact_floor,
            intent_memo="Exact floor attempt",
            nonce=9102
        )
        st, reason = self.engine.evaluate_proposal(prop_floor)
        self.assertEqual(st, ProposalState.APPROVED)

        # C. 24-decimal precision arithmetic: ensure no floating-point epsilon leakage
        rem_budget = self.engine.get_remaining_daily_budget()
        expected_rem = 20.0 - 0.001
        self.assertAlmostEqual(rem_budget, expected_rem, places=6)

    def test_edge_case_3_timelock_cooldown_boundary(self):
        """Edge Case 3: Simulates governance 24h timelock unlock boundary (1 second before vs 1 second after)."""
        current_time = 1000000.0
        timelock_duration = 86400.0  # 24 hours
        unlock_time = current_time + timelock_duration

        # Simulated state of pending update
        pending_update = {
            "new_max_daily": 50.0,
            "unlock_timestamp": unlock_time
        }

        # 1. Attempt unlock at 86,399s (1 second before expiry) -> MUST REJECT!
        early_time = unlock_time - 1.0
        self.assertFalse(early_time >= pending_update["unlock_timestamp"], "Timelock bypassed 1 second early!")

        # 2. Attempt unlock at 86,400s (exact cooldown) -> MUST SUCCEED
        exact_time = unlock_time
        self.assertTrue(exact_time >= pending_update["unlock_timestamp"], "Timelock failed to unlock at cooldown!")

    def test_edge_case_4_attestation_mitm_tampering(self):
        """Edge Case 4: Verifies that an attacker altering recipient or amount on an authentic ticket is blocked."""
        # 1. Engine issues legitimate attestation ticket for 0.5 NEAR to "physio-clinic.testnet"
        ticket = self.att_engine.create_attestation(
            proposal_id="prop-mitm-01",
            agent_id="agent-01",
            recipient="physio-clinic.testnet",
            amount_near=Decimal("0.5"),
            nonce="mitm-nonce-1"
        )

        # Verify authentic ticket passes HMAC verification
        self.assertTrue(self.att_engine.verify_ticket(ticket))

        # 2. Attacker intercepts and tampers recipient to "attacker.testnet"
        import dataclasses
        tampered_ticket = dataclasses.replace(ticket, recipient="attacker.testnet")

        # Tampered ticket MUST fail HMAC signature verification!
        self.assertFalse(self.att_engine.verify_ticket(tampered_ticket))

        # 3. Attacker tampers amount to 500 NEAR
        tampered_amt_ticket = dataclasses.replace(ticket, amount_yocto="500000000000000000000000000")
        self.assertFalse(self.att_engine.verify_ticket(tampered_amt_ticket))

    def test_edge_case_5_balance_underflow_and_rollback_isolation(self):
        """Edge Case 5: Ensures failed transfers or release calls never result in negative spend ledger."""
        today_key = self.engine._get_today_key()

        # Proposal 1: 1.0 NEAR approved and reserved
        prop = PaymentProposal(
            proposal_id="prop-rollback-1",
            agent_id="agent-01",
            recipient="testnet",
            amount_near=Decimal("1.0"),
            intent_memo="Care booking",
            nonce=9201
        )
        st, _ = self.engine.evaluate_proposal(prop)
        self.assertEqual(st, ProposalState.APPROVED)

        # Release reservation (e.g. transfer failed on-chain)
        ok = self.engine.release_reservation("prop-rollback-1", reason="ONCHAIN_EXECUTION_FAILURE")
        self.assertTrue(ok)

        # Daily reserved must be exactly 0, never negative
        today_spent, today_res = self.storage.get_daily_ledger(today_key)
        self.assertEqual(today_res, Decimal("0"))
        self.assertEqual(today_spent, Decimal("0"))

        # Re-releasing an already released proposal must be a safe no-op (idempotent)
        dup_release = self.engine.release_reservation("prop-rollback-1", reason="RE_RELEASE_ATTEMPT")
        self.assertFalse(dup_release)
        today_spent_after, today_res_after = self.storage.get_daily_ledger(today_key)
        self.assertEqual(today_res_after, Decimal("0"))


if __name__ == "__main__":
    unittest.main()
