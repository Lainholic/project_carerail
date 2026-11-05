"""Unit tests for NearReconciliationVerifier
Verifies on-chain finality parsing and fraud-proof state reconciliation.
"""

from decimal import Decimal
import unittest
from unittest.mock import MagicMock, patch

from policy.reconciliation import NearReconciliationVerifier


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
    def test_success_value_reconciliation(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = b"""{
            "jsonrpc": "2.0",
            "result": {
                "status": {"SuccessValue": "AAAA"},
                "transaction": {"receiver_id": "carerail-274071e4.testnet"}
            },
            "id": "rec-1"
        }"""
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
    def test_receiver_mismatch_fails_reconciliation(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = b"""{
            "jsonrpc": "2.0",
            "result": {
                "status": {"SuccessValue": "AAAA"},
                "transaction": {"receiver_id": "evil-contract.testnet"}
            },
            "id": "rec-2"
        }"""
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
        self.assertFalse(ok)
        self.assertIn("TARGET_CONTRACT_MISMATCH", msg)

    @patch("urllib.request.urlopen")
    def test_onchain_failure_status_rejected(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = b"""{
            "jsonrpc": "2.0",
            "result": {
                "status": {"Failure": {"ActionError": {"kind": "FunctionCallError"}}},
                "transaction": {"receiver_id": "carerail-274071e4.testnet"}
            },
            "id": "rec-3"
        }"""
        mock_response.__enter__.return_value = mock_response
        mock_urlopen.return_value = mock_response

        ok, msg = self.verifier.verify_and_reconcile(
            tx_hash="failed-tx",
            sender_id="agent.testnet",
            contract_id="carerail-274071e4.testnet",
            expected_recipient="clinic.testnet",
            expected_amount_near=Decimal("0.1"),
            allow_mock=False
        )
        self.assertFalse(ok)
        self.assertIn("RECONCILIATION_FAILED", msg)


if __name__ == "__main__":
    unittest.main()
