"""Unit Tests for NearIntentsFirewallAdapter
Verifies pre-flight inspection and deterministic policy enforcement over NEAR Intents.
"""

from decimal import Decimal
import json
import unittest

from policy.engine import CareRailEngine, PolicyRules, ProposalState
from near_rail.intents_adapter import NearIntentsFirewallAdapter


class TestNearIntentsFirewallAdapter(unittest.TestCase):
    def setUp(self):
        self.rules = PolicyRules(
            version="1.0.0",
            policy_id="pol_intents_test",
            allowed_recipients=["intents.near", "merchant.testnet", "uber.testnet"],
            max_per_transfer_near=1.0,
            max_daily_total_near=2.0,
            owner_approval_threshold_near=0.5,
            request_expiry_seconds=60,
            reject_unknown_actions=True,
            blocked_memo_keywords=["drain", "jailbreak"],
            owner_public_key="ed25519:6EUtptVoYsQ6iZsgmJ8jX6oQ8sF9qF8i3c5y6wX7z8A9",
            min_transfer_floor_near=0.001,
            max_pending_proposals=50,
        )
        self.engine = CareRailEngine(self.rules, db_path=":memory:")
        self.adapter = NearIntentsFirewallAdapter(
            engine=self.engine,
            allowed_tokens=["nep141:wrap.testnet", "nep141:usdc.testnet", "near"]
        )

    def test_legitimate_swap_intent_approved(self):
        """0.2 NEAR swap to USDC (under 0.5 threshold) -> MUST BE APPROVED"""
        intent = {
            "standard": "nep413",
            "message": {
                "signer_id": "agent-01.testnet",
                "intents": [
                    {
                        "intent": "token_diff",
                        "diff": {
                            "nep141:wrap.testnet": "-200000000000000000000000", # 0.2 wNEAR debit
                            "nep141:usdc.testnet": "1000000"                   # 1.0 USDC credit
                        }
                    }
                ]
            }
        }
        ok, reason, prop = self.adapter.inspect_and_filter_intent(intent, "agent-01.testnet", nonce=101)
        self.assertTrue(ok)
        self.assertEqual(reason, "INTENT_POLICY_APPROVED")
        self.assertIsNotNone(prop)
        self.assertEqual(prop.state, ProposalState.APPROVED)

    def test_unauthorized_token_drain_blocked(self):
        """Attacker prompts agent to swap into an unwhitelisted shady meme token -> BLOCKED"""
        malicious_intent = {
            "standard": "nep413",
            "message": {
                "signer_id": "agent-01.testnet",
                "intents": [
                    {
                        "intent": "token_diff",
                        "diff": {
                            "nep141:wrap.testnet": "-100000000000000000000000",
                            "nep141:shady-rugpull-token.testnet": "1000000000000"
                        }
                    }
                ]
            }
        }
        ok, reason, prop = self.adapter.inspect_and_filter_intent(malicious_intent, "agent-01.testnet", nonce=102)
        self.assertFalse(ok)
        self.assertIn("UNAUTHORIZED_TOKEN", reason)
        self.assertIn("shady-rugpull-token.testnet", reason)

    def test_high_value_intent_held_for_owner_approval(self):
        """0.8 NEAR swap exceeds 0.5 NEAR owner threshold -> HELD FOR OWNER APPROVAL"""
        high_value_intent = {
            "standard": "nep413",
            "message": {
                "signer_id": "agent-01.testnet",
                "intents": [
                    {
                        "intent": "token_diff",
                        "diff": {
                            "nep141:wrap.testnet": "-800000000000000000000000", # 0.8 wNEAR debit
                            "nep141:usdc.testnet": "4000000"
                        }
                    }
                ]
            }
        }
        ok, reason, prop = self.adapter.inspect_and_filter_intent(high_value_intent, "agent-01.testnet", nonce=103)
        self.assertFalse(ok)
        self.assertIn("INTENT_HELD_FOR_HUMAN_APPROVAL", reason)
        self.assertEqual(prop.state, ProposalState.AWAITING_OWNER_APPROVAL)

    def test_budget_exceeded_intent_rejected(self):
        """2.5 NEAR swap exceeds 1.0 per-tx ceiling and 2.0 daily budget -> REJECTED"""
        excessive_intent = {
            "standard": "nep413",
            "message": {
                "signer_id": "agent-01.testnet",
                "intents": [
                    {
                        "intent": "token_diff",
                        "diff": {
                            "nep141:wrap.testnet": "-2500000000000000000000000", # 2.5 wNEAR debit
                            "nep141:usdc.testnet": "12500000"
                        }
                    }
                ]
            }
        }
        ok, reason, prop = self.adapter.inspect_and_filter_intent(excessive_intent, "agent-01.testnet", nonce=104)
        self.assertFalse(ok)
        self.assertIn("LIMIT_EXCEEDED", reason)

    def test_malformed_intent_fails_closed(self):
        """Corrupted JSON payload -> FAILS CLOSED"""
        ok, reason, prop = self.adapter.inspect_and_filter_intent("NOT_A_VALID_JSON{", "agent-01.testnet", nonce=105)
        self.assertFalse(ok)
        self.assertIn("MALFORMED_INTENT_JSON", reason)


if __name__ == "__main__":
    unittest.main()
