# Terra Round 9 Adversarial Security Audit Report
Date: 2026-11-05
Model: gpt-6.1-terra (reasoning_effort: high)

## Executive Summary
Round 8 patches addressed baseline surface issues, but Terra Round 9 identifies critical underlying gaps:
1. [P0-1] Ambiguous Dispatch Failures (`False, "timeout"`) currently release reservation, causing double-spending if transaction was actually submitted to NEAR mempool/validators.
2. [P0-2] Reconciliation does not cryptographically bind local proposal with onchain payment or detect transaction hash reuse / idempotency key collisions.
3. [P1-1] On-chain transfer callback failure modes: `try/catch` wraps both `promiseResult(0)` and storage mutation, conflating storage errors with transfer failures.
4. [P1-2] Permanent proposal storage unbounded accumulation (Storage Staking depletion / Denial of Service risk).
5. [P1-4] Non-atomic reservation creation in engine: memory checks followed by separate write calls leave race windows.
6. [P1-5] Simulation mode uses real engine/storage, polluting pending proposals and nonces instead of evaluating purely on isolated snapshots.

---

## Detailed Findings

### P0-1. Ambiguous Dispatcher Failure Double-Spend Vulnerability
- Current Code: `sdk/carerail_tool.py`:
  When dispatcher returns `False, err_msg`, it immediately calls `release_reservation()`.
  If the failure was a network timeout or connection reset AFTER the RPC node received/relayed the transaction, the transaction can be mined on NEAR while the SDK releases the reservation.
  The agent then creates a new proposal and re-broadcasts, resulting in a double-spend!
- Required Fix:
  - Distinguish `NOT_BROADCAST` (definitive local pre-validation failure) vs `BROADCAST_OR_TIMEOUT` / `UNKNOWN`.
  - For any timeout or network error, budget reservation MUST NOT be released. Must lock into `UNKNOWN / PENDING_RECONCILIATION`.
  - Implement idempotent payment key tracking in SDK/Engine.

### P0-2. Reconciliation Hash Reuse & Idempotency Key Binding
- Current Code: `policy/reconciliation.py`:
  - If callback returned boolean `true`, proposal ID check was bypassed.
  - If a malicious or buggy dispatcher returned a previously used `tx_hash`, reconciliation did not verify if the `tx_hash` was already consumed.
- Required Fix:
  - Track consumed transaction hashes (`consumed_tx_hashes`) in persistent storage to strictly reject replay of previously confirmed transactions.
  - Ensure return value strictly matches expected proposal attributes.

### P1-5. True Isolated Simulation Mode
- Current Code: `sdk/carerail_tool.py`:
  Simulation mode invoked `self.engine.evaluate_proposal()`, which writes nonces and pending proposals to live storage.
- Required Fix:
  Simulation mode should use an ephemeral memory engine snapshot, guaranteeing zero persistent ledger/storage writes.

### P1-1. On-Chain Contract Callback Robustness
- Current Code: `contract/src/index.js`:
  In `on_transfer_callback`, wrap only `near.promiseResult(0)` in the try/catch, not the entire state mutation.

### P1-2. On-Chain Storage Staking Bounded Storage
- Current Code: Bounded pending proposals exists (`MAX_PENDING_PROPOSALS = 50`), but completed proposals stay forever. Add explicit size limit or tombstone eviction if needed.
