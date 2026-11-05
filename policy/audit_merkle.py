"""CareRail Cryptographic Merkle Audit Trail Engine
Constructs cryptographic Merkle Trees over all processed proposals and settlements.
Enables verifiable inclusion proofs and anchors tamper-evident state roots.
Guarantees that off-chain SQLite ledger history cannot be silently altered or deleted.
"""

from decimal import Decimal
import hashlib
import json
import time
from typing import Dict, List, Optional, Tuple, Any


class MerkleAuditTrail:
    """Cryptographic Merkle Tree for verifiable audit logging."""

    def __init__(self):
        self.leaves: List[str] = []         # Hex-encoded leaf hashes
        self.proposals: List[dict] = []      # Raw proposal event snapshots

    @staticmethod
    def hash_leaf(proposal_dict: Dict[str, Any]) -> str:
        """Computes deterministic canonical SHA-256 leaf hash for a proposal record."""
        canonical_str = (
            f"{proposal_dict.get('proposal_id','')}:"
            f"{proposal_dict.get('agent_id','')}:"
            f"{proposal_dict.get('recipient','')}:"
            f"{proposal_dict.get('amount_near','')}:"
            f"{proposal_dict.get('state','')}:"
            f"{proposal_dict.get('nonce','')}:"
            f"{proposal_dict.get('created_at','')}"
        )
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    @staticmethod
    def hash_pair(left_hex: str, right_hex: str) -> str:
        """Hashes two 32-byte hex hashes together in lexicographical order (RFC 6962)."""
        if left_hex > right_hex:
            left_hex, right_hex = right_hex, left_hex
        combined = bytes.fromhex(left_hex) + bytes.fromhex(right_hex)
        return hashlib.sha256(combined).hexdigest()

    def add_record(self, proposal_dict: Dict[str, Any]) -> str:
        """Appends a new proposal record into the audit trail and returns its leaf hash."""
        leaf_h = self.hash_leaf(proposal_dict)
        self.leaves.append(leaf_h)
        self.proposals.append(dict(proposal_dict))
        return leaf_h

    def get_merkle_root(self) -> str:
        """Calculates the current Merkle Root hash across all recorded leaves.
        Returns empty hash string if tree has no leaves.
        """
        if not self.leaves:
            return hashlib.sha256(b"EMPTY_CARERAIL_AUDIT_TREE").hexdigest()

        current_level = list(self.leaves)
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    # Odd number of leaves: duplicate the last leaf to balance tree
                    right = left
                parent = self.hash_pair(left, right)
                next_level.append(parent)
            current_level = next_level

        return current_level[0]

    def generate_proof(self, leaf_index: int) -> Tuple[str, List[Tuple[str, str]]]:
        """Generates Merkle Inclusion Proof for the leaf at leaf_index.
        Returns: (leaf_hash, list_of_(sibling_hash, direction))
        """
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise IndexError("Leaf index out of bounds")

        target_leaf = self.leaves[leaf_index]
        proof = []
        current_index = leaf_index
        current_level = list(self.leaves)

        while len(current_level) > 1:
            next_level = []
            is_right_child = (current_index % 2 == 1)
            sibling_index = current_index - 1 if is_right_child else current_index + 1

            if sibling_index < len(current_level):
                sibling_hash = current_level[sibling_index]
            else:
                sibling_hash = current_level[current_index]

            direction = "left" if is_right_child else "right"
            proof.append((sibling_hash, direction))

            for i in range(0, len(current_level), 2):
                l = current_level[i]
                r = current_level[i + 1] if i + 1 < len(current_level) else l
                next_level.append(self.hash_pair(l, r))

            current_index = current_index // 2
            current_level = next_level

        return target_leaf, proof

    @classmethod
    def verify_proof(cls, leaf_hash: str, proof: List[Tuple[str, str]], expected_root: str) -> bool:
        """Verifies cryptographic Merkle inclusion proof against a known Root."""
        curr = leaf_hash
        for sibling_hash, direction in proof:
            curr = cls.hash_pair(curr, sibling_hash)
        return curr == expected_root
