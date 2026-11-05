"""CareRail On-Chain Reconciliation & Settlement Verifier
Verifies on-chain finality, recipient binding, and exact amount matching before or during commit_spend.
Prevents unconfirmed, rolled-back, or spoofed transactions from altering off-chain budget state (Terra Round 5 Fixed).
"""

import base64
from decimal import Decimal
import json
import os
import time
from typing import Dict, Optional, Tuple
import urllib.request
import urllib.error

YOCTO_PER_NEAR = Decimal("1000000000000000000000000")


class NearReconciliationVerifier:
    def __init__(self, rpc_url: str = "https://rpc.testnet.fastnear.com", timeout_seconds: int = 5):
        self.rpc_url = rpc_url
        self.timeout = timeout_seconds

    def query_tx_status(self, tx_hash: str, sender_id: str) -> Tuple[bool, Optional[dict], str]:
        """Queries NEAR RPC for transaction outcome."""
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
        expected_proposal_id: Optional[str] = None,
        allow_mock: bool = False
    ) -> Tuple[bool, str]:
        """High-level verification gate.
        Validates:
        1. On-chain finality status is Success
        2. Receiver of transaction was CareRail PolicyVault contract
        3. Transaction args exactly match expected recipient and expected amount (Terra P1 Fixed)
        4. Execution return value confirms SUBMITTED state (funds dispatched), not AWAITING_OWNER_APPROVAL (Terra Round 6 P1-1 Fixed)
        """
        if allow_mock and (tx_hash.startswith("mock-") or tx_hash.startswith("sim-")):
            return True, "MOCK_VERIFIED_SUCCESS"

        success, res, msg = self.query_tx_status(tx_hash, sender_id)
        if not success:
            return False, f"RECONCILIATION_FAILED: {msg}"

        # 1. Verify transaction receiver was the PolicyVault contract (Terra Round 7 P1-2 Fixed)
        tx_info = res.get("transaction", {})
        actual_receiver = tx_info.get("receiver_id")
        if not actual_receiver or actual_receiver != contract_id:
            return False, f"TARGET_CONTRACT_MISMATCH: Expected {contract_id}, but on-chain receiver was {actual_receiver}"

        # 2. Check receipts outcome for cross-contract execution failures
        receipts_outcome = res.get("receipts_outcome", [])
        for ro in receipts_outcome:
            status = ro.get("outcome", {}).get("status", {})
            if "Failure" in status:
                return False, f"RECEIPT_EXECUTION_FAILURE: {status['Failure']}"

        # 3. Verify payload arguments (strict Fail-Closed matching of propose_payment)
        actions_list = tx_info.get("actions", [])
        verified_call = False
        for act in actions_list:
            if isinstance(act, dict) and "FunctionCall" in act:
                fc = act["FunctionCall"]
                if fc.get("method_name") != "propose_payment":
                    continue
                args_b64 = fc.get("args")
                if not args_b64:
                    return False, "MISSING_FUNCTION_ARGS"
                try:
                    args_json = json.loads(base64.b64decode(args_b64).decode("utf-8"))
                    if "recipient" not in args_json or "amount" not in args_json:
                        return False, "INCOMPLETE_PAYMENT_ARGS: recipient and amount are mandatory"
                    if args_json["recipient"] != expected_recipient:
                        return False, f"PAYMENT_RECIPIENT_MISMATCH: Expected {expected_recipient}, but tx has {args_json['recipient']}"
                    act_yocto = Decimal(str(args_json["amount"]))
                    exp_yocto = (Decimal(str(expected_amount_near)) * YOCTO_PER_NEAR).quantize(Decimal("1"))
                    if act_yocto != exp_yocto:
                        return False, f"PAYMENT_AMOUNT_MISMATCH: Expected {exp_yocto} yoctoNEAR, but tx has {act_yocto} yoctoNEAR"
                    verified_call = True
                except Exception as parse_err:
                    return False, f"ARGS_DECODING_ERROR: {str(parse_err)}"

        if not verified_call:
            return False, "NO_MATCHING_PROPOSE_PAYMENT_ACTION_FOUND"

        # 4. Verify execution return value (Accepts both callback boolean true and SUBMITTED/SETTLED dict) (Terra Round 8 P1-1 Fixed)
        final_status = res.get("status", {})
        success_val_b64 = final_status.get("SuccessValue")
        if not success_val_b64:
            tx_outcome = res.get("transaction_outcome", {}).get("outcome", {})
            success_val_b64 = tx_outcome.get("status", {}).get("SuccessValue")

        if not success_val_b64:
            return False, "MISSING_SUCCESS_VALUE: Transaction outcome did not produce a valid SuccessValue"

        try:
            decoded = base64.b64decode(success_val_b64).decode("utf-8")
            ret_json = json.loads(decoded)
            if isinstance(ret_json, bool):
                if not ret_json:
                    return False, "CALLBACK_RETURNED_FALSE: Transfer callback signaled failure"
                # Boolean True confirms on_transfer_callback settled successfully
            elif isinstance(ret_json, dict):
                prop_state = ret_json.get("state")
                if prop_state == "AWAITING_OWNER_APPROVAL":
                    return False, "PAYMENT_NOT_SETTLED_YET: Proposal held in AWAITING_OWNER_APPROVAL state"
                if prop_state and prop_state not in ("SUBMITTED", "SETTLED"):
                    return False, f"UNEXPECTED_PROPOSAL_STATE: Proposal is in '{prop_state}', not SUBMITTED/SETTLED"
                if expected_proposal_id and ret_json.get("proposal_id") and ret_json.get("proposal_id") != expected_proposal_id:
                    return False, f"PROPOSAL_ID_MISMATCH: Expected {expected_proposal_id}, got {ret_json.get('proposal_id')}"
            else:
                return False, f"UNEXPECTED_RETURN_TYPE: Expected boolean or JSON object, got {type(ret_json).__name__}"
        except Exception as ret_err:
            return False, f"RETURN_VALUE_DECODING_ERROR: {str(ret_err)}"

        return True, "ONCHAIN_RECONCILIATION_VERIFIED"
