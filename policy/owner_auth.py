"""CareRail NEP-413 Cryptographic Owner Authentication Module
Verifies that high-value transaction approvals are authenticated by real Ed25519 owner signatures.
"""

import json
import hashlib
from typing import Dict, Any, Tuple
from near_rail.crypto import NearKeyManager


class Nep413Authorizer:
    @staticmethod
    def construct_approval_message(proposal_id: str, amount_near: float, recipient: str, nonce: int) -> bytes:
        """Constructs the canonical NEP-413 authorization payload."""
        canonical_str = f"NEP413:APPROVE:{proposal_id}:{recipient}:{amount_near:.4f}:{nonce}"
        return canonical_str.encode("utf-8")

    @staticmethod
    def sign_approval(owner_private_key_hex: str, proposal_id: str, amount_near: float, recipient: str, nonce: int) -> str:
        """Simulates the human owner's hardware key or WebAuthn wallet signing the NEP-413 challenge."""
        msg = Nep413Authorizer.construct_approval_message(proposal_id, amount_near, recipient, nonce)
        return NearKeyManager.sign_message(owner_private_key_hex, msg)

    @staticmethod
    def verify_approval(owner_public_key: str, proposal_id: str, amount_near: float, recipient: str, nonce: int, signature_b58: str) -> bool:
        """Verifies the cryptographically signed approval payload."""
        msg = Nep413Authorizer.construct_approval_message(proposal_id, amount_near, recipient, nonce)
        return NearKeyManager.verify_signature(owner_public_key, msg, signature_b58)
