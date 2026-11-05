"""NEAR Testnet RPC Client for CareRail
Interacts with the NEAR Testnet via standard JSON-RPC 2.0.
"""

import json
import logging
import os
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

logger = logging.getLogger("NearRailClient")

DEFAULT_TESTNET_RPCS = [
    "https://test.rpc.fastnear.com",
    "https://rpc.testnet.near.org",
    "https://testnet.neardata.xyz/v1/node",
]


class NearRailClient:
    def __init__(self, rpc_urls: Optional[list] = None, timeout_seconds: int = 10):
        if rpc_urls is None:
            self.rpc_urls = list(DEFAULT_TESTNET_RPCS)
        elif isinstance(rpc_urls, str):
            self.rpc_urls = [rpc_urls]
        else:
            self.rpc_urls = list(rpc_urls)
        self.timeout = timeout_seconds

    def _rpc_call(self, method: str, params: Any) -> Dict[str, Any]:
        payload = {
            "jsonrpc": "2.0",
            "id": "carerail-rpc",
            "method": method,
            "params": params,
        }
        data = json.dumps(payload).encode("utf-8")
        last_error = None

        for endpoint in self.rpc_urls:
            req = urllib.request.Request(
                endpoint,
                data=data,
                headers={"Content-Type": "application/json", "User-Agent": "CareRail/1.0"},
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    res_body = json.loads(resp.read().decode("utf-8"))
                    if "error" in res_body:
                        return {"success": False, "error": res_body["error"]}
                    return {"success": True, "result": res_body.get("result"), "endpoint": endpoint}
            except Exception as e:
                last_error = f"{endpoint}: {str(e)}"
                logger.warning(f"RPC call to {endpoint} failed ({e}), attempting failover...")
                continue

        return {"success": False, "error": f"All RPC endpoints failed. Last error: {last_error}"}

    def get_network_status(self) -> Dict[str, Any]:
        """Queries NEAR testnet status to verify RPC connectivity."""
        return self._rpc_call("status", [])

    def query_account(self, account_id: str) -> Dict[str, Any]:
        """Queries an account state on NEAR testnet."""
        params = {
            "request_type": "view_account",
            "finality": "final",
            "account_id": account_id,
        }
        return self._rpc_call("query", params)

    def submit_settlement(
        self,
        sender_account: str,
        recipient_account: str,
        amount_near: float,
        proposal_hash: str,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """Executes the settlement on NEAR.
        When dry_run=False (default), signs and broadcasts real on-chain transaction via send_tx.js.
        When dry_run=True, returns simulated hash.
        """
        if dry_run:
            simulated_hash = f"NEAR-TX-{proposal_hash[:16].upper()}-TESTNET"
            return {
                "success": True,
                "status": "CONFIRMED",
                "transaction_hash": simulated_hash,
                "explorer_url": f"https://testnet.nearblocks.io/txns/{simulated_hash}",
                "amount_near": amount_near,
                "recipient": recipient_account,
                "sender": sender_account,
                "mode": "deterministic_simulation",
            }

        # Real Live On-Chain Broadcast via isolated Node signer
        import subprocess
        script_path = os.path.join(os.path.dirname(__file__), "send_tx.js")
        project_root = os.path.dirname(os.path.dirname(__file__))
        try:
            res = subprocess.run(
                ["node", script_path, recipient_account, str(amount_near)],
                cwd=project_root,
                capture_output=True,
                text=True,
                timeout=25,
            )
            if res.returncode == 0:
                data = json.loads(res.stdout.strip())
                data["mode"] = "live_onchain"
                return data
            else:
                try:
                    err_json = json.loads(res.stderr.strip() or res.stdout.strip())
                    return {"success": False, "error": err_json.get("error", "Transaction failed")}
                except Exception:
                    return {"success": False, "error": res.stderr.strip() or res.stdout.strip()}
        except Exception as e:
            return {"success": False, "error": f"Execution error: {str(e)}"}
