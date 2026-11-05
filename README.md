# CareRail: Autonomous Payment Firewall for AI Agents on NEAR

> **Built for NEAR HACKATHON 2026**  
> **Primary Track**: `[ 06 / SEC ] AI Security & Defense` (Agent Security, Function Call Keys, Attestation)  
> **Secondary Tracks**: `[ 07 / AGT ] Agent Economy`, `[ 04 / BUS ] Autonomous Business`  
> **Engineering Maturity**: **Security-Hardened Alpha / PoC** (Audited by DeepSeek-V4.1-Flash, Terra, and Annie)  
> **License**: MIT  
> **On-Chain Vault Contract**: [`carerail-274071e4.testnet`](https://testnet.nearblocks.io/address/carerail-274071e4.testnet)  
> **Latest Contract Upgrade Tx**: [`4JGC5y35GmdVfD8edKdX8frrAv2SBjyMWAW57M6CXVuG`](https://testnet.nearblocks.io/txns/4JGC5y35GmdVfD8edKdX8frrAv2SBjyMWAW57M6CXVuG)  
> **Active Policy Invariants**: 22 On-Chain Invariants | 10 Automated Harness Suites (100% Invariants Verified)

---

## 1. Executive Summary & Problem Definition

Autonomous AI agents are increasingly entrusted with cryptocurrency wallets to purchase compute, pay API quotas, and transact with other agents. However, granting an LLM direct signing keys creates an unacceptable security hazard: **a single prompt injection, context escape, or hallucination can instantly drain the entire treasury to an adversary.**

**CareRail** is a physical security air-gap and deterministic execution barrier that decouples untrusted LLM decision-making from cryptographic signing authorities:
* **Zero Private Keys in Agent Context**: The LLM runtime can only formulate structured payment proposals. It possesses zero private keys.
* **Deterministic FSM Policy Engine**: Enforces fail-closed rules using exact Decimal arithmetic (IEEE-754 floating-point errors eliminated), atomic SQLite `BEGIN IMMEDIATE` budget reservations, and replay nonce deduplication.
* **Engine Attestation**: Evaluated proposals receive an HMAC-SHA256 attestation ticket that binds proposal ID, recipient, yoctoNEAR amount, and nanosecond timestamp for on-chain verification.
* **Cryptographic Human-in-the-Loop Gateway**: High-value transactions automatically transition to `AWAITING_OWNER_APPROVAL`, strictly requiring valid **NEP-413 Ed25519 cryptographic owner signatures**.
* **Protocol-Level Access Key Isolation**: Agent keys on NEAR are restricted `FunctionCallAccessKey` allowances strictly locked to `propose_payment`. Direct transfers and administrative calls are blocked at the NEAR protocol validator level.
* **NEAR Intents Cross-Chain Pre-Flight Firewall**: Intercepts NEP-413 token swap intents (Defuse protocol) before solver broadcast, preventing MEV sandwiching and unauthorized token drainage.

---

## 2. Multi-Layer Security Architecture

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                     HUMAN OWNER / SECURITY GOVERNOR                    │
 │  - Configures on-chain Policy Vault & Emergency Pause                  │
 │  - Signs High-Value Escalations (> 0.1 NEAR) via NEP-413 Ed25519       │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │
 ┌───────────────────────┐           │
 │  UNTRUSTED AI AGENT   │           ▼
 │  (Zero Private Keys)  │ ──> [ CareRail Tool Interceptor (SDK) ]
 └───────────────────────┘           │
                                     ▼
                     [ Deterministic FSM Engine ]
                     - Exact 36-decimal yoctoNEAR math
                     - Atomic SQLite BEGIN IMMEDIATE reservation
                     - Nonce replay & transaction hash deduplication
                     - Prompt injection keyword filter
                                     │
                        ┌────────────┴────────────┐
                        ▼                         ▼
                  [ REJECTED ]              [ APPROVED ]
                  (Fail-Closed)       (Issues Attestation Ticket)
                                                  │
                                                  ▼
                                      [ Multi-RPC Client ]
                                (FastNEAR + Official RPC Failover)
                                                  │
                                                  ▼
                                    [ On-Chain PolicyVault ]
                                  (carerail-274071e4.testnet)
                                  - 22 On-Chain Invariants
                                  - Attestation Hash Verification
                                  - 24h Governance Timelock
                                  - Asynchronous Callback Isolation
```

---

## 3. Finite State Machine (FSM) Lifecycle

Every proposal deterministically traverses strict states:

```text
PROPOSED ──> VALIDATING ──┬──> REJECTED (Fail-Closed)
                          ├──> AWAITING_OWNER_APPROVAL ──> APPROVED / REJECTED
                          └──> RESERVED ──> SUBMITTED ──> CONFIRMED / PENDING_RECONCILIATION
```

* **`PROPOSED`**: Agent requests payment with recipient, amount, intent memo, and unique nonce.
* **`VALIDATING`**: FSM runs whitelist, velocity, anti-dust floor, and boundary constraints.
* **`AWAITING_OWNER_APPROVAL`**: Exceeds autonomous threshold; holds on-chain until owner signs.
* **`RESERVED`**: Budget atomically reserved in persistent storage; prevents race conditions.
* **`SUBMITTED`**: Broadcasted to NEAR via multi-RPC provider with Function Call Key.
* **`PENDING_RECONCILIATION`**: Ambiguous network drop retains reservation in `UNKNOWN` state to prevent double-spending until verified on-chain.
* **`CONFIRMED`**: Cryptographically reconciled against on-chain execution receipt.

---

## 4. Quickstart: 10/10 Verification Harness (Judge Instructions)

Run the full automated verification harness in under 15 seconds:

```bash
# 1. Clone repository
git clone https://github.com/Lainholic/project_carerail.git
cd project_carerail

# 2. Run complete automated 10-suite verification harness
python verify_all.py
```

### Automated Verification Suite Results (10/10 PASS - 100% Invariants Verified):
1. **PolicyVault Smart Contract Invariants (Node.js)**: 23 invariant tests covering callback isolation, day-boundary rollback, emergency killswitch, anti-dust floor, bounded memo, governance 24h timelock, cryptographic engine attestation, and malformed float/string injection defense.
2. **Deterministic FSM Policy Engine & Decimal Arithmetic (Python)**: 17 invariant tests covering exact Decimal arithmetic (eliminating IEEE-754 errors), atomic reservation, cross-day budget isolation, and persistent SQLite recovery.
3. **On-Chain Reconciliation & Settlement Verifier (Python)**: Fail-closed transaction receipt and action hash reconciliation.
4. **CareRail AI Agent SDK & Tool Interceptor (Python)**: In-memory simulation isolation, proposal formulation, and idempotent retry keys.
5. **E2E LLM Agent & Prompt Injection Defense (Python)**: End-to-end prompt injection attack simulations.
6. **NEAR Official Testnet RPC & Account State**: Multi-endpoint status query verifying network liveliness.
7. **Live On-Chain Red-Team Security & Protocol Isolation**: Real on-chain broadcast testing:
   - Direct agent transfer attempt to attacker: Blocked by NEAR protocol layer.
   - Privileged administrative call: Blocked by Function Call Access Key.
   - Malicious unwhitelisted proposal: Blocked by smart contract guardrail.
   - Legitimate proposal: Confirmed on testnet.
8. **Live On-Chain Human-in-the-Loop Threshold Verification**: Real on-chain high-value escalation hold and owner cryptographic approval.
9. **Adversarial Stress & Cryptographic Boundary (DeepSeek & Annie)**:
   - Attestation tampering, signature forgery, and ticket expiry defense.
   - 10-thread simultaneous concurrency attack: `BEGIN IMMEDIATE` guarantees exactly 1 success and 9 rejections with zero budget leakage.
   - Nonce collision bombing defense.
   - Network griefing / RPC timeout reservation retention.
10. **NEAR Intents Cross-Chain Pre-Flight Firewall Adapter**: Pre-flight inspection of NEP-413 intent messages, token diffs, and cross-chain routing.

---

## 5. Security-Hardened Alpha Declaration & Institutional Production Roadmap

Following rigorous adversarial audits by **DeepSeek-V4.1-Flash** and **Terra (`gpt-6.1-terra`)**, CareRail is classified as **`Security-Hardened Alpha`**. We transparently disclose remaining institutional gaps and the engineering roadmap to mainnet production readiness:

| Category | CareRail Current State (Alpha) | Institutional Production Roadmap |
| :--- | :--- | :--- |
| **Off-Chain Engine** | Single Python FSM process with SQLite `BEGIN IMMEDIATE` | 3-Node BFT Byzantine Fault Tolerant consensus (Rust + Go + Python) |
| **Trust Boundary** | HMAC-SHA256 Engine Attestation verified in QuickJS WASM | Intel SGX / Phala TEE Remote Attestation or zk-SNARK proof on-chain |
| **Formal Verification** | 23 comprehensive property and invariant tests | TLA+ mathematical model of timelock and async callback reentrancy |
| **Key Management** | Local Ed25519 signing keys in environment | Hardware Security Module (HSM) and MPC multi-signature integration |
| **Economic Security** | Technical policy enforcement | Slashing collateral and insurance pool for breach indemnification |

---

## 6. Real On-Chain Artifacts & Evidence

* **Vault Contract Account**: [`carerail-274071e4.testnet`](https://testnet.nearblocks.io/address/carerail-274071e4.testnet)
* **Latest WASM Deployment Tx**: [`4JGC5y35GmdVfD8edKdX8frrAv2SBjyMWAW57M6CXVuG`](https://testnet.nearblocks.io/txns/4JGC5y35GmdVfD8edKdX8frrAv2SBjyMWAW57M6CXVuG)
* **WASM Binary Size**: 556,905 bytes (compiled via `near-sdk-js 2.0.0` in QuickJS WebAssembly)
* **Agent Restricted Access Key Tx**: [`F3A9EBmBh9iukummvVjwkB7F2wbuxDoLNMN42BZQdeHM`](https://testnet.nearblocks.io/txns/F3A9EBmBh9iukummvVjwkB7F2wbuxDoLNMN42BZQdeHM)
* **Live Red-Team Valid Proposal Tx**: [`H3TF7fztyb8wdnHLAJZVv1834HRb8v28foWQS95vtTi1`](https://testnet.nearblocks.io/txns/H3TF7fztyb8wdnHLAJZVv1834HRb8v28foWQS95vtTi1)
* **Live Human-in-the-Loop Hold Tx**: [`D3LkzRC1bVskYaKyYfTwBe1EvoWYgjoBD1GJ1A2mymBq`](https://testnet.nearblocks.io/txns/D3LkzRC1bVskYaKyYfTwBe1EvoWYgjoBD1GJ1A2mymBq)
* **Live Owner Approval Settlement Tx**: [`99yYJP78W3BetjDULkvwks8TZE4qqu1umra3eAKzpnh`](https://testnet.nearblocks.io/txns/99yYJP78W3BetjDULkvwks8TZE4qqu1umra3eAKzpnh)
* **Visual Evidence**: `docs/carerail_dashboard_live_onchain.png`

---

## 7. Cybersecurity Command Center Dashboard

Launch the monitoring dashboard and scenario evaluator:
```bash
# Windows Quick Launcher
open_dashboard.bat
# Or run web server directly
python web/server.py
```
* **Traffic & Quota Gauges**: Real-time visualization of daily budget usage and pending threshold approvals.
* **Interactive Red-Team Attack Simulator**: One-click execution of prompt injections, unwhitelisted transfers, and dust spam attacks.
* **Human-in-the-Loop Approval Modal**: Real-time inspection of held proposals and cryptographic signing.
