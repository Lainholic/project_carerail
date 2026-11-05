"""CareRail NEAR Cryptographic Key Manager
Generates and manages Ed25519 keypairs and NEAR implicit accounts using python cryptography.
Key isolation invariant: Private keys are strictly confined to the execution boundary.
"""

import os
from typing import Tuple, Dict
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Standard Bitcoin/NEAR Base58 Alphabet
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    origlen = len(data)
    data = data.lstrip(b"\x00")
    newlen = len(data)

    acc = int.from_bytes(data, byteorder="big")
    result = []
    while acc > 0:
        acc, mod = divmod(acc, 58)
        result.append(B58_ALPHABET[mod])

    pad = origlen - newlen
    return (B58_ALPHABET[0] * pad) + "".join(reversed(result))


def b58decode(s: str) -> bytes:
    origlen = len(s)
    s = s.lstrip(B58_ALPHABET[0])
    newlen = len(s)

    acc = 0
    for char in s:
        acc = acc * 58 + B58_ALPHABET.index(char)

    # Convert int back to bytes
    length = (acc.bit_length() + 7) // 8
    res = acc.to_bytes(length, byteorder="big") if acc > 0 else b""
    pad = origlen - newlen
    return (b"\x00" * pad) + res


class NearKeyManager:
    @staticmethod
    def generate_keypair() -> Dict[str, str]:
        """Generates a fresh ed25519 keypair and NEAR account representations."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        priv_raw = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        near_public_key = f"ed25519:{b58encode(pub_raw)}"
        full_priv = priv_raw + pub_raw
        near_private_key = f"ed25519:{b58encode(full_priv)}"
        implicit_account_id = pub_raw.hex().lower()

        return {
            "public_key": near_public_key,
            "private_key": near_private_key,
            "private_key_raw_hex": priv_raw.hex(),
            "implicit_account_id": implicit_account_id,
        }

    @staticmethod
    def sign_message(private_key_raw_hex: str, message: bytes) -> str:
        """Signs an arbitrary message or serialized transaction hash."""
        priv_bytes = bytes.fromhex(private_key_raw_hex)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        signature = private_key.sign(message)
        return b58encode(signature)

    @staticmethod
    def verify_signature(near_public_key: str, message: bytes, signature_b58: str) -> bool:
        try:
            pub_b58 = near_public_key.replace("ed25519:", "")
            pub_bytes = b58decode(pub_b58)
            sig_bytes = b58decode(signature_b58)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            public_key.verify(sig_bytes, message)
            return True
        except Exception:
            return False
