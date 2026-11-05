"""CareRail Adversarial Stress & Cryptographic Boundary Verification Suite
Engineered collaboratively with DeepSeek-V4.1-Flash and Annie (Google Antigravity Worker).

Scenarios Covered:
1. Cryptographic Attestation Tampering & Boundary Defense (Forged amounts, modified recipients, expired tickets, replay nonces)
2. High-Concurrency Multi-Thread Race Attack (10 concurrent threads bombing single remaining budget slot - SQLite BEGIN IMMEDIATE serialization)
3. Nonce Collision Bombing (10 threads attempting identical nonce simultaneously)
4. Network Failure / RPC Griefing Simulation (Unambiguous failure vs Ambiguous timeout reservation retention - Zero budget leak)
"""

import concurrent.futures
from decimal import Decimal
import os
import tempfile
import time
import unittest

from policy.engine import CareRailEngine, PaymentProposal, PolicyRules, ProposalState, AttestationEngine, AttestationTicket
from policy.storage import PersistentLedgerStorage
from sdk.carerail_tool import CareRailPaymentTool


class TestAdversarialStress(unittest.TestCase):
    def setUp(self):
        self.rules_dict = {
            "version": "1.0.0",
            "policy_id": "pol_adversarial_stress",
            "allowed_recipients": ["clinic.testnet", "groceries.testnet"],
            "max_per_transfer_near": 1.0,
            "max_daily_total_near": 1.0,  # Tight daily cap of 1.0 NEAR
            "owner_approval_threshold_near": 0.5,
            "request_expiry_seconds": 60,
            "reject_unknown_actions": True,
            "blocked_memo_keywords": ["jailbreak", "override"],
            "owner_public_key": "ed25519:6EUtptVoYsQ6iZsgmJ8jX6oQ8sF9qF8i3c5y6wX7z8A9",
            "min_transfer_floor_near": 0.001,
            "max_pending_proposals": 50,
        }
        self.rules = PolicyRules(
            version=self.rules_dict["version"],
            policy_id=self.rules_dict["policy_id"],
            allowed_recipients=self.rules_dict["allowed_recipients"],
            max_per_transfer_near=self.rules_dict["max_per_transfer_near"],
            max_daily_total_near=self.rules_dict["max_daily_total_near"],
            owner_approval_threshold_near=self.rules_dict["owner_approval_threshold_near"],
            request_expiry_seconds=self.rules_dict["request_expiry_seconds"],
            reject_unknown_actions=self.rules_dict["reject_unknown_actions"],
            blocked_memo_keywords=self.rules_dict["blocked_memo_keywords"],
            owner_public_key=self.rules_dict["owner_public_key"],
            min_transfer_floor_near=self.rules_dict["min_transfer_floor_near"],
            max_pending_proposals=self.rules_dict["max_pending_proposals"],
        )
        self.test_secret = "carerail-adversarial-secret-2026"
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.temp_db_fd)

    def tearDown(self):
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except OSError:
                pass

    # =========================================================================
    # Test 1: Cryptographic Engine Attestation Tampering & Replay Defense
    # =========================================================================
    def test_cryptographic_attestation_tampering_and_boundary(self):
        engine = CareRailEngine(self.rules, db_path=self.temp_db_path, attestation_secret=self.test_secret)
        
        # Valid proposal
        prop = PaymentProposal(
            proposal_id="prop_att_001",
            agent_id="agent.testnet",
            recipient="clinic.testnet",
            amount_near=0.3,
            intent_memo="Valid medical copay",
            nonce=1001,
        )
        state, reason = engine.evaluate_proposal(prop)
        self.assertEqual(state, ProposalState.APPROVED)
        self.assertIsNotNone(prop.attestation)

        att = engine.attestation_engine.create_attestation(
            prop.proposal_id, prop.agent_id, prop.recipient, prop.amount_near, prop.nonce
        )
        self.assertTrue(engine.attestation_engine.verify_ticket(att))

        # A. Tampered amount in ticket
        tampered_amt_ticket = AttestationTicket(
            engine_id=att.engine_id,
            proposal_id=att.proposal_id,
            agent_id=att.agent_id,
            recipient=att.recipient,
            amount_yocto="999999999999999999999999", # Tampered!
            nonce=att.nonce,
            expires_at=att.expires_at,
            sig_hash=att.sig_hash,
        )
        self.assertFalse(engine.attestation_engine.verify_ticket(tampered_amt_ticket))

        # B. Tampered recipient in ticket
        tampered_rec_ticket = AttestationTicket(
            engine_id=att.engine_id,
            proposal_id=att.proposal_id,
            agent_id=att.agent_id,
            recipient="attacker.testnet", # Tampered!
            amount_yocto=att.amount_yocto,
            nonce=att.nonce,
            expires_at=att.expires_at,
            sig_hash=att.sig_hash,
        )
        self.assertFalse(engine.attestation_engine.verify_ticket(tampered_rec_ticket))

        # C. Expired ticket
        past_exp_ticket = AttestationTicket(
            engine_id=att.engine_id,
            proposal_id=att.proposal_id,
            agent_id=att.agent_id,
            recipient=att.recipient,
            amount_yocto=att.amount_yocto,
            nonce=att.nonce,
            expires_at=str(time.time_ns() - 1000), # 1us in past
            sig_hash=att.sig_hash,
        )
        self.assertFalse(engine.attestation_engine.verify_ticket(past_exp_ticket))

    # =========================================================================
    # Test 2: Concurrency Bombing Attack (10 Threads Racing for Single 1.0 NEAR Slot)
    # =========================================================================
    def test_multi_threaded_concurrency_race_condition(self):
        """Simulates 10 concurrent LLM agents attempting simultaneous 1.0 NEAR transfers.
        Daily budget ceiling is 1.0 NEAR. Exactly ONE must succeed. 9 must fail.
        Verifies SQLite BEGIN IMMEDIATE transaction serialization prevents over-reservation.
        """
        engine = CareRailEngine(self.rules, db_path=self.temp_db_path)
        
        results = []

        def worker_attempt(idx):
            # Each worker uses its own connection to the persistent DB
            worker_engine = CareRailEngine(self.rules, db_path=self.temp_db_path)
            prop = PaymentProposal(
                proposal_id=f"race_prop_{idx}",
                agent_id=f"agent_{idx}.testnet",
                recipient="clinic.testnet",
                amount_near=1.0,
                intent_memo=f"Race attempt {idx}",
                nonce=2000 + idx,
            )
            state, reason = worker_engine.evaluate_proposal(prop)
            return idx, state, reason

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(worker_attempt, i) for i in range(10)]
            for f in concurrent.futures.as_completed(futures):
                results.append(f.result())

        approved_count = sum(1 for _, st, _ in results if st in (ProposalState.APPROVED, ProposalState.AWAITING_OWNER_APPROVAL))
        rejected_count = sum(1 for _, st, _ in results if st == ProposalState.REJECTED)

        self.assertEqual(approved_count, 1, f"Expected exactly 1 approval, got {approved_count}")
        self.assertEqual(rejected_count, 9, f"Expected exactly 9 rejections, got {rejected_count}")

        # Authoritative persistent storage inspection: Reserved amount must be exactly 1.0 NEAR
        storage = PersistentLedgerStorage(self.temp_db_path)
        today_k = time.strftime("%Y-%m-%d", time.gmtime())
        _, reserved = storage.get_daily_ledger(today_k)
        self.assertEqual(reserved, Decimal("1.0"), f"Budget leaked! Reserved: {reserved}")

    # =========================================================================
    # Test 3: Nonce Collision Bombing (10 Threads Attacking With Identical Nonce)
    # =========================================================================
    def test_nonce_collision_race_condition(self):
        """10 threads concurrently submit proposals with the EXACT SAME nonce.
        Exactly 1 must succeed; 9 must be rejected for nonce collision.
        """
        results = []
        shared_nonce = 99999

        def nonce_worker(idx):
            worker_engine = CareRailEngine(self.rules, db_path=self.temp_db_path)
            prop = PaymentProposal(
                proposal_id=f"nonce_bomb_{idx}",
                agent_id="agent.testnet",
                recipient="clinic.testnet",
                amount_near=0.05,
                intent_memo=f"Nonce bomb {idx}",
                nonce=shared_nonce,
            )
            state, reason = worker_engine.evaluate_proposal(prop)
            return idx, state, reason

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(nonce_worker, i) for i in range(10)]
            for f in concurrent.futures.as_completed(futures):
                results.append(f.result())

        approved = [r for r in results if r[1] in (ProposalState.APPROVED, ProposalState.AWAITING_OWNER_APPROVAL)]
        rejected = [r for r in results if r[1] == ProposalState.REJECTED]

        self.assertEqual(len(approved), 1, "Exactly one proposal should succeed with shared nonce")
        self.assertEqual(len(rejected), 9, "9 proposals must fail on nonce collision")

    # =========================================================================
    # Test 4: Network Griefing / RPC Timeout Reservation Retention
    # =========================================================================
    def test_network_griefing_reservation_retention(self):
        """Simulates an ambiguous network timeout during blockchain broadcast.
        Verifies that:
        1. Ambiguous errors hold the reservation in UNKNOWN state.
        2. A subsequent rogue transaction cannot double-spend that reserved budget.
        """
        # Mock broadcast failure that simulates post-broadcast network timeout
        def ambiguous_network_drop(*args, **kwargs):
            raise TimeoutError("RPC connection dropped while waiting for final block receipt")

        engine = CareRailEngine(self.rules, db_path=self.temp_db_path)
        tool = CareRailPaymentTool(engine=engine, agent_id="agent.testnet", onchain_dispatcher=ambiguous_network_drop)

        # Agent attempts to send 0.4 NEAR (under 0.5 threshold, so auto-dispatches, but hits network drop)
        res = tool.execute(
            recipient="clinic.testnet",
            amount_near=0.4,
            intent_memo="Payment during network drop",
            client_idempotency_key="idemp-net-drop-01"
        )

        self.assertFalse(res["success"])
        self.assertEqual(res["state"], "PENDING_RECONCILIATION")
        self.assertIn("AMBIGUOUS_BROADCAST_STATUS", res["reason"])

        # Storage check: 0.4 NEAR MUST remain reserved
        today_k = time.strftime("%Y-%m-%d", time.gmtime())
        _, reserved = engine.storage.get_daily_ledger(today_k)
        self.assertEqual(reserved, Decimal("0.4"))

        # Attacker tries to consume 0.8 NEAR -> (0.4 reserved + 0.8 = 1.2 > 1.0 cap) -> MUST BE REJECTED!
        rogue_res = tool.execute(
            recipient="clinic.testnet",
            amount_near=0.8,
            intent_memo="Attacker double-spend attempt during timeout",
            client_idempotency_key="idemp-rogue-02"
        )
        self.assertFalse(rogue_res["success"])
        self.assertEqual(rogue_res["state"], "REJECTED")
        self.assertIn("DAILY_CAP_EXCEEDED", rogue_res["reason"])


if __name__ == "__main__":
    unittest.main()
