import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from near_rail.crypto import NearKeyManager
from policy.engine import CareRailEngine, PaymentProposal, PolicyRules, ProposalState
from policy.owner_auth import Nep413Authorizer


class TestNep413OwnerAuth(unittest.TestCase):
    def setUp(self):
        rules_path = os.path.join(os.path.dirname(__file__), "rules.json")
        self.rules = PolicyRules.load_from_json(rules_path)
        self.owner_kp = NearKeyManager.generate_keypair()
        self.attacker_kp = NearKeyManager.generate_keypair()
        self.rules.owner_public_key = self.owner_kp["public_key"]
        self.engine = CareRailEngine(self.rules)

    def test_cryptographic_owner_approval_success(self):
        # 1. Propose high value item
        p = PaymentProposal(
            proposal_id="prop-nep413-001",
            agent_id="agent-01",
            recipient="testnet",
            amount_near=3.0,
            intent_memo="High value medical equipment",
            nonce=5001,
        )
        state, _ = self.engine.evaluate_proposal(p)
        self.assertEqual(state, ProposalState.AWAITING_OWNER_APPROVAL)

        # 2. Owner cryptographically signs the challenge with their real ed25519 private key
        sig = Nep413Authorizer.sign_approval(
            owner_private_key_hex=self.owner_kp["private_key_raw_hex"],
            proposal_id=p.proposal_id,
            amount_near=p.amount_near,
            recipient=p.recipient,
            nonce=p.nonce,
        )

        # 3. Policy engine verifies against owner's public key
        ok, msg = self.engine.owner_approve(
            proposal_id=p.proposal_id,
            owner_public_key=self.owner_kp["public_key"],
            signature_b58=sig,
        )
        self.assertTrue(ok)
        self.assertEqual(p.state, ProposalState.APPROVED)

    def test_forged_attacker_signature_rejected(self):
        p = PaymentProposal(
            proposal_id="prop-nep413-002",
            agent_id="agent-01",
            recipient="testnet",
            amount_near=4.0,
            intent_memo="Expensive surgery prepayment",
            nonce=5002,
        )
        self.engine.evaluate_proposal(p)

        # Attacker tries to forge the approval with attacker's private key
        forged_sig = Nep413Authorizer.sign_approval(
            owner_private_key_hex=self.attacker_kp["private_key_raw_hex"],
            proposal_id=p.proposal_id,
            amount_near=p.amount_near,
            recipient=p.recipient,
            nonce=p.nonce,
        )

        # Engine checks against the real owner's public key -> MUST FAIL
        ok, msg = self.engine.owner_approve(
            proposal_id=p.proposal_id,
            owner_public_key=self.owner_kp["public_key"],
            signature_b58=forged_sig,
        )
        self.assertFalse(ok)
        self.assertIn("CRYPTOGRAPHIC_VERIFICATION_FAILED", msg)
        self.assertEqual(p.state, ProposalState.AWAITING_OWNER_APPROVAL)


if __name__ == "__main__":
    unittest.main()
