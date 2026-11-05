"""CareRail On-Chain Reconciliation & Settlement Verifier
Verifies on-chain finality and state matching before or during commit_spend.
Prevents unconfirmed or rolled-back transactions from permanently altering off-chain budget state (P1-7).
"""

from decimal import Decimal
import json
import os
import time
from typing import Dict, Optional, Tuple
import urllib.request
import urllib.error


class NearReconciliationVerifier:
    def __init__(self, rpc_url: str = "https://rpc.testnet.fastnear.com", timeout_seconds: int = 5):
        self.rpc_url = rpc_url
        self.timeout = timeout_seconds

    def query_tx_status(self, tx_hash: str, sender_id: str) -> Tuple[bool, Optional[dict], str]:
        """Queries NEAR RPC EXPERIMENTAL_tx_status or tx for transaction outcome.
        Returns: (is_success, raw_result_dict, error_or_status_message)
        """
        payload = {
            "jsonrpc": "2.0",
            "id": f"rec-{int(time.time()*1000)}",
            "method": "tx",
            "params": {
                "tx_hash": tx_hash,
                "sender_account_id": sender_id
            }
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.rpc_url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "CareRail-Reconciliation/1.0"}
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                res = json.loads(resp.read().decode("utf-8"))

            if "error" in res:
                return False, None, f"RPC_ERROR: {res['error'].get('message', str(res['error']))}"

            result = res.get("result", {})
            status = result.get("status", {})

            # Check if transaction succeeded on-chain
            if "SuccessValue" in status:
                return True, result, "SUCCESS_VALUE"
            elif "SuccessReceiptId" in status:
                return True, result, "SUCCESS_RECEIPT"
            elif "Failure" in status:
                return False, result, f"ONCHAIN_EXECUTION_FAILURE: {status['Failure']}"
            else:
                return False, result, f"UNKNOWN_STATUS: {status}"

        except urllib.error.URLError as e:
            return False, None, f"NETWORK_UNAVAILABLE: {str(e.reason)}"
        except Exception as e:
            return False, None, f"QUERY_EXCEPTION: {str(e)}"

    def verify_and_reconcile(
        self,
        tx_hash: str,
        sender_id: str,
        contract_id: str,
        expected_recipient: str,
        expected_amount_near: Decimal,
        allow_mock: bool = False
    ) -> Tuple[bool, str]:
        """High-level verification gate.
        Validates:
        1. On-chain finality status is Success
        2. Receiver of transaction was CareRail PolicyVault contract
        """
        # In mock or test mode, synthetic hashes can bypass RPC call
        if allow_mock and (tx_hash.startswith("mock-") or tx_hash.startswith("tx-")):
            return True, "MOCK_VERIFIED_SUCCESS"

        success, res, msg = self.query_tx_status(tx_hash, sender_id)
        if not success:
            return False, f"RECONCILIATION_FAILED: {msg}"

        # Verify transaction receiver was indeed the CareRail contract
        tx_info = res.get("transaction", {})
        actual_receiver = tx_info.get("receiver_id")
        if actual_receiver and actual_receiver != contract_id:
            return False, f"TARGET_CONTRACT_MISMATCH: Expected {contract_id}, but on-chain receiver was {actual_receiver}"

        return True, "ONCHAIN_RECONCILIATION_VERIFIED"
