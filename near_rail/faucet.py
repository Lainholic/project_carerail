"""NEAR Testnet Account & Faucet Provisioner for CareRail
Safely provisions real on-chain testnet accounts and stores isolated keys in .env
"""

import json
import os
import sys
import urllib.request
from pathlib import Path

# Add project root
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from near_rail.crypto import NearKeyManager
from near_rail.client import NearRailClient

ENV_FILE = ROOT_DIR / ".env"


def provision_testnet_account() -> dict:
    # 1. Generate keypair
    kp = NearKeyManager.generate_keypair()
    acc_name = f"carerail-{kp['implicit_account_id'][:8]}.testnet"

    print(f"[*] Requesting real on-chain testnet account from NEAR Helper: {acc_name}")
    payload = {
        "newAccountId": acc_name,
        "newAccountPublicKey": kp["public_key"]
    }

    req = urllib.request.Request(
        "https://helper.testnet.near.org/account",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "CareRail/1.0"}
    )

    with urllib.request.urlopen(req, timeout=20) as resp:
        res_data = json.loads(resp.read().decode("utf-8"))
        tx_hash = res_data.get("transaction", {}).get("hash", "")
        print(f"[+] Account created on-chain! Transaction Hash: {tx_hash}")

    # 2. Save credentials safely to .env (git-ignored)
    env_content = f"""# CareRail Isolated Testnet Execution Keys
# NEVER commit this file to git
CARERAIL_TESTNET_ACCOUNT_ID={acc_name}
CARERAIL_TESTNET_PUBLIC_KEY={kp['public_key']}
CARERAIL_TESTNET_PRIVATE_KEY={kp['private_key']}
CARERAIL_TESTNET_PRIVATE_KEY_HEX={kp['private_key_raw_hex']}
CARERAIL_PROVISION_TX_HASH={tx_hash}
"""
    with open(ENV_FILE, "w", encoding="utf-8") as f:
        f.write(env_content)

    print(f"[+] Saved credentials to {ENV_FILE}")

    # 3. Verify balance
    client = NearRailClient()
    acc_res = client.query_account(acc_name)
    yocto = int(acc_res.get("result", {}).get("amount", 0))
    near_balance = yocto / (10**24)
    print(f"[+] Verified On-Chain Balance: {near_balance:.2f} NEAR")

    return {
        "account_id": acc_name,
        "public_key": kp["public_key"],
        "tx_hash": tx_hash,
        "balance_near": near_balance,
        "explorer_url": f"https://testnet.nearblocks.io/txns/{tx_hash}"
    }


if __name__ == "__main__":
    res = provision_testnet_account()
    print(f"\nProvisioning Complete! Explorer: {res['explorer_url']}")
