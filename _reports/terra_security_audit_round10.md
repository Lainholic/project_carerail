# Terra Round 10 Adversarial Security Audit Report
Date: 2026-11-05
Model: gpt-6.1-terra (reasoning_effort: high)

## Executive Summary
Terra Round 10 uncovered high-precision bugs and architectural edge cases across the stack:
1. [P1-2 Bug] In `policy/reconciliation.py`: Variable name typo: expected amount was calculated into `exp_yocto`, but return check referenced `expected_yocto` (undefined variable)!
2. [P1-1 Gap] Local SDK proposal ID (`tool-prop-...`) vs on-chain proposal ID (`prop-N`): When contract returns structured callback `{ proposal_id: "prop-65", ... }`, passing `expected_proposal_id=proposal_id` caused mismatch. Need client payment/intent idempotency key support or onchain prop mapping.
3. [P0-1 Multi-Worker Concurrency] Budget reservation in `engine.py` checked in-memory ledger before writing. Needs a single atomic SQLite transaction for proposal insertion, nonce check, and reservation increment.
4. [P0-2 Idempotency Key] Re-submitting an identical payment intent on network drop generated a new UUID proposal ID. Needs caller-specified or deterministic intent idempotency key.
5. [P0-3 Direct Engine Bypass] `commit_spend(proposal_id, tx_hash)` in storage checked `if tx_hash:` so an empty string `""` could technically be passed if caller bypassed SDK. Must enforce `assert tx_hash and len(tx_hash) > 10`.
6. [P0-4 Error Substring Matching] `is_preflight` checked broad substrings. Should be strict and fail closed.
7. [P1-9 Simulation Snapshot] Simulation engine should snapshot live reservations and pause state.
8. [P1-7 Owner Approve Reconciliation] Reconciliation verifier only looked for `propose_payment` method name; should also recognize `owner_approve` method execution.

Status: Security-Validation Alpha / PoC (Strict No-Premature-Completion Rule).
