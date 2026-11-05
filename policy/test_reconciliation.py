"""Unit tests for NearReconciliationVerifier
Verifies on-chain finality parsing, recipient matching, and exact amount reconciliation.
"""

import base64
from decimal import Decimal
import json
import unittest
from unittest.mock import MagicMock, patch

from policy.reconciliation import NearReconciliationVerifier, YOCTO_PER_NEAR


class TestNearReconciliationVerifier(unittest.TestCase):
    def setUp(self):
        self.verifier = NearReconciliationVerifier()

    def test_mock_bypass_mode(self):
        ok, msg = self.verifier.verify_and_reconcile(
            tx_hash="mock-tx-12345",
            sender_id="agent.testnet",
            contract_id="carerail-274071e4.testnet",
            expected_recipient="doctor.testnet",
            expected_amount_near=Decimal("0.5"),
            allow_mock=True
        )
        self.assertTrue(ok)
        self.assertEqual(msg, "MOCK_VERIFIED_SUCCESS")

    @patch("urllib.request.urlopen")
    def test_success_value_with_matching_args(self, mock_urlopen):
        args_payload = json.dumps({
            "recipient": "clinic.testnet",
            "amount": str(int(Decimal("0.1") * YOCTO_PER_NEAR))
        }).encode("utf-8")
        args_b64 = base64.b64encode(args_payload).decode("utf-8")

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "jsonrpc": "2.0",
            "result": {
                "status": {"SuccessValue": "AAAA"},
                "transaction": {
                    "receiver_id": "carerail-274071e4.testnet",
                    "actions": [{
                        "FunctionCall": {
                            "method_name": "propose_payment",
                            "args": args_b64
                        }
                    }]
                }
            },
            "id": "rec-1"
        }).encode("utf-8")
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        ok, msg = self.verifier.verify_and_reconcile(
            tx_hash="3X8K2a...",
            sender_id="agent.testnet",
            contract_id="carerail-274071e4.testnet",
            expected_recipient="clinic.testnet",
            expected_amount_near=Decimal("0.1"),
            allow_mock=False
        )
        self.assertTrue(ok)
        self.assertEqual(msg, "ONCHAIN_RECONCILIATION_VERIFIED")

    @patch("urllib.request.urlopen")
    def test_amount_mismatch_fails_reconciliation(self, mock_urlopen):
        """Terra P1: Different amount on-chain must be caught and rejected."""
        args_payload = json.dumps({
            "recipient": "clinic.testnet",
            "amount": str(int(Decimal("0.05") * YOCTO_PER_NEAR)) # 0.05 NEAR on-chain vs 0.1 expected
        }).encode("utf-8")
        args_b64 = base64.b64encode(args_payload).decode("utf-8")

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "jsonrpc": "2.0",
            "result": {
                "status": {"SuccessValue": "AAAA"},
                "transaction": {
                    "receiver_id": "carerail-274071e4.testnet",
                    "actions": [{
                        "FunctionCall": {
                            "method_name": "propose_payment",
                            "args": args_b64
                        }
                    }]
                }
            },
            "id": "rec-2"
        }).encode("utf-8")
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        ok, msg = self.verifier.verify_and_reconcile(
            tx_hash="3X8K2a...",
            sender_id="agent.testnet",
            contract_id="carerail-274071e4.testnet",
            expected_recipient="clinic.testnet",
            expected_amount_near=Decimal("0.1"), # expected 0.1
            allow_mock=False
        )
        self.assertFalse(ok)
        self.assertIn("PAYMENT_AMOUNT_MISMATCH", msg)


if __name__ == "__main__":
    unittest.main()
