/**
 * Unit Test for PolicyVault Smart Contract Logic
 * Updated with Annie's Verified Governance & Cryptographic Attestation Architecture:
 * 1. Strict callback privacy
 * 2. Day-boundary accounting isolation
 * 3. Emergency circuit breaker
 * 4. Anti-dust floor
 * 5. Strict FSM state immutability
 * 6. Cryptographic NEP-413 Attestation Recording (Test 14)
 * 7. Absolute Protocol Hard-Caps Protection (Test 15)
 * 8. Governance Time-Lock 24h Cooldown (Test 16)
 * 9. Defensive Instant Limit Reduction & Timelock Cancellation (Test 17)
 */

import assert from 'assert';
import crypto from 'crypto';

// Crypto helpers for test environment
function utf8Encode(str) {
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    let code = str.charCodeAt(i);
    if (code < 0x80) {
      bytes.push(code);
    } else if (code < 0x800) {
      bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code < 0xd800 || code >= 0xe000) {
      bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      i++;
      const next = str.charCodeAt(i);
      const cp = 0x10000 + (((code & 0x3ff) << 10) | (next & 0x3ff));
      bytes.push(
        0xf0 | (cp >> 18),
        0x80 | ((cp >> 12) & 0x3f),
        0x80 | ((cp >> 6) & 0x3f),
        0x80 | (cp & 0x3f)
      );
    }
  }
  return new Uint8Array(bytes);
}

function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function hmacSha256(keyBytes, messageBytes) {
  const BLOCK = 64;
  let key = keyBytes;
  if (key.length > BLOCK) {
    key = global.near.sha256(key);
  }
  const paddedKey = new Uint8Array(BLOCK);
  paddedKey.set(key);

  const ipad = new Uint8Array(BLOCK);
  const opad = new Uint8Array(BLOCK);
  for (let i = 0; i < BLOCK; i++) {
    ipad[i] = paddedKey[i] ^ 0x36;
    opad[i] = paddedKey[i] ^ 0x5c;
  }

  const inner = new Uint8Array(BLOCK + messageBytes.length);
  inner.set(ipad, 0);
  inner.set(messageBytes, BLOCK);
  const innerHash = global.near.sha256(inner);

  const outer = new Uint8Array(BLOCK + innerHash.length);
  outer.set(opad, 0);
  outer.set(innerHash, BLOCK);
  return global.near.sha256(outer);
}

function hmacSha256Hex(keyStr, messageStr) {
  const keyBytes = utf8Encode(keyStr);
  const msgBytes = utf8Encode(messageStr);
  return bytesToHex(hmacSha256(keyBytes, msgBytes));
}

function constantTimeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

const DAY_IN_NANOSECONDS = BigInt(86400) * BigInt(1000000000);
const MIN_TRANSFER_FLOOR = BigInt("1000000000000000000000"); // 0.001 NEAR
const MAX_PENDING_PROPOSALS = 50;

const ABSOLUTE_MAX_DAILY_LIMIT = BigInt("50000000000000000000000000"); // 50 NEAR
const ABSOLUTE_MAX_PER_TRANSFER = BigInt("10000000000000000000000000"); // 10 NEAR
const TIMELOCK_DURATION_NS = BigInt(86400) * BigInt(1000000000); // 24 hours

class MockUnorderedMap {
  constructor(prefix) {
    this.prefix = prefix;
    this.store = new Map();
  }
  get(key) {
    return this.store.get(key) || null;
  }
  set(key, val) {
    this.store.set(key, val);
  }
}

class MockLookupMap {
  constructor(prefix) {
    this.prefix = prefix;
    this.store = new Map();
  }
  containsKey(key) {
    return this.store.has(key);
  }
  get(key) {
    return this.store.get(key) || null;
  }
  set(key, val) {
    this.store.set(key, val);
  }
}

const attestationNonces = new MockLookupMap("uan");

global.near = {
  _timestamp: BigInt(1700000000) * BigInt(1000000000),
  _caller: "agent-01.testnet",
  _currentAccount: "vault.testnet",
  _logs: [],
  blockTimestamp() {
    return this._timestamp;
  },
  predecessorAccountId() {
    return this._caller;
  },
  currentAccountId() {
    return this._currentAccount;
  },
  promiseBatchCreate(recipient) {
    return 1;
  },
  promiseBatchActionTransfer(promiseId, amount) {},
  promiseThen() {
    return 2;
  },
  promiseReturn() {},
  log(msg) {
    this._logs.push(msg);
  },
  sha256(bytes) {
    return new Uint8Array(crypto.createHash('sha256').update(Buffer.from(bytes)).digest());
  }
};

class Proposal {
  constructor({ id, recipient, amount, memo, state, createdAt, submittedDay, attestation }) {
    this.id = id;
    this.recipient = recipient;
    this.amount = amount;
    this.memo = memo;
    this.state = state;
    this.createdAt = createdAt;
    this.submittedDay = submittedDay;
    this.attestation = attestation || null;
  }
}

class PolicyVaultTestable {
  constructor() {
    this.owner_id = "";
    this.agent_id = "";
    this.allowed_recipients = [];
    this.max_per_transfer = BigInt(0);
    this.max_daily_total = BigInt(0);
    this.owner_approval_threshold = BigInt(0);
    this.spent_today = BigInt(0);
    this.last_reset_day = BigInt(0);
    this.is_paused = false;
    this.pending_count = 0;
    this.pending_timelock_update = null;
    this.proposals = new MockUnorderedMap("p");
    this.proposal_nonce = 0;
    this.engine_attestation_key = "";
  }

  init({ owner_id, agent_id, allowed_recipients, max_per_transfer, max_daily_total, owner_approval_threshold, engine_attestation_key }) {
    const perTransfer = BigInt(max_per_transfer);
    const dailyTotal = BigInt(max_daily_total);
    if (perTransfer > ABSOLUTE_MAX_PER_TRANSFER) throw new Error("max_per_transfer exceeds absolute protocol hard cap");
    if (dailyTotal > ABSOLUTE_MAX_DAILY_LIMIT) throw new Error("max_daily_total exceeds absolute protocol hard cap");

    this.owner_id = owner_id;
    this.agent_id = agent_id;
    this.allowed_recipients = allowed_recipients || [];
    this.max_per_transfer = perTransfer;
    this.max_daily_total = dailyTotal;
    this.owner_approval_threshold = BigInt(owner_approval_threshold);
    this.spent_today = BigInt(0);
    this.last_reset_day = global.near.blockTimestamp() / DAY_IN_NANOSECONDS;
    this.is_paused = false;
    this.pending_count = 0;
    this.pending_timelock_update = null;
    this.proposal_nonce = 0;
    this.engine_attestation_key = engine_attestation_key || "";
  }

  _checkAndResetDailyAllowance() {
    const currentDay = global.near.blockTimestamp() / DAY_IN_NANOSECONDS;
    if (currentDay > this.last_reset_day) {
      this.spent_today = BigInt(0);
      this.last_reset_day = currentDay;
    }
  }

  _verifyAttestation(attestationStr, caller, recipient, amt) {
    if (!attestationStr || typeof attestationStr !== 'string') throw new Error("SECURITY_ALERT: Attestation required by policy vault");
    let att = null;
    try {
      att = JSON.parse(attestationStr);
    } catch (e) {
      att = null;
    }
    if (!att || typeof att !== 'object') throw new Error("INVALID_ENGINE_ATTESTATION: Malformed JSON");
    if (!att.engine_id) throw new Error("INVALID_ENGINE_ATTESTATION: Missing engine_id");
    if (att.agent_id !== caller) throw new Error("INVALID_ENGINE_ATTESTATION: Caller agent mismatch");
    if (att.recipient !== recipient) throw new Error("INVALID_ENGINE_ATTESTATION: Recipient mismatch");
    if (att.amount_yocto !== amt.toString()) throw new Error("INVALID_ENGINE_ATTESTATION: Amount mismatch");
    if (!att.nonce) throw new Error("INVALID_ENGINE_ATTESTATION: Missing nonce");
    if (!att.expires_at) throw new Error("INVALID_ENGINE_ATTESTATION: Missing expires_at");
    if (!att.sig_hash || att.sig_hash.length !== 64) throw new Error("INVALID_ENGINE_ATTESTATION: Invalid sig_hash format");

    const currentTs = global.near.blockTimestamp();
    const expiresAt = BigInt(att.expires_at);
    if (expiresAt <= currentTs) throw new Error("INVALID_ENGINE_ATTESTATION: Attestation ticket expired");

    const nonceKey = `nonce:${att.nonce}`;
    if (attestationNonces.containsKey(nonceKey)) throw new Error("INVALID_ENGINE_ATTESTATION: Attestation nonce already consumed");

    const canonical = `${att.engine_id}|${att.agent_id}|${att.recipient}|${att.amount_yocto}|${att.nonce}|${att.expires_at}`;
    const expectedSig = hmacSha256Hex(this.engine_attestation_key, canonical);
    if (!constantTimeEqualHex(expectedSig, att.sig_hash)) throw new Error("INVALID_ENGINE_ATTESTATION: Cryptographic signature mismatch");

    attestationNonces.set(nonceKey, "1");
  }

  set_engine_attestation_key({ engine_attestation_key }) {
    if (this.is_paused) throw new Error("SECURITY_ALERT: Vault is paused by emergency circuit breaker");
    const caller = global.near.predecessorAccountId();
    if (caller !== this.owner_id) throw new Error("Only owner can set engine attestation key");
    this.engine_attestation_key = engine_attestation_key || "";
    return { engine_attestation_key: this.engine_attestation_key };
  }

  set_emergency_pause({ paused }) {
    const caller = global.near.predecessorAccountId();
    if (caller !== this.owner_id) throw new Error("Only owner can toggle emergency pause");
    this.is_paused = !!paused;
    return { is_paused: this.is_paused };
  }

  propose_payment({ recipient, amount, memo, attestation }) {
    if (this.is_paused) throw new Error("SECURITY_ALERT: Vault is paused by emergency circuit breaker");

    const caller = global.near.predecessorAccountId();
    if (caller !== this.agent_id && caller !== this.owner_id) {
      throw new Error("Caller is not authorized agent or owner");
    }

    this._checkAndResetDailyAllowance();
    if (!recipient || typeof recipient !== 'string' || recipient.length === 0 || recipient.length > 64) {
      throw new Error("Invalid recipient: must be between 1 and 64 characters");
    }
    if (memo && memo.length > 256) {
      throw new Error("SECURITY_ALERT: Memo exceeds 256 character limit");
    }
    if (amount === undefined || amount === null) {
      throw new Error("Invalid amount: required");
    }
    const amountStr = typeof amount === 'string' ? amount : amount.toString();
    if (!/^\d+$/.test(amountStr)) {
      throw new Error("Invalid amount: must be positive integer yoctoNEAR string");
    }
    const amt = BigInt(amountStr);
    if (amt <= BigInt(0)) throw new Error("Amount must be strictly positive");

    if (this.engine_attestation_key && this.engine_attestation_key.length > 0) {
      this._verifyAttestation(attestation, caller, recipient, amt);
    }

    if (amt < MIN_TRANSFER_FLOOR) {
      throw new Error("SECURITY_ALERT: Amount below minimum floor (0.001 NEAR)");
    }
    if (this.pending_count >= MAX_PENDING_PROPOSALS) {
      throw new Error("SECURITY_ALERT: Maximum pending proposals reached");
    }

    if (!this.allowed_recipients.includes(recipient)) {
      throw new Error(`SECURITY_VIOLATION: Recipient ${recipient} is not whitelisted`);
    }

    if (amt > this.max_per_transfer) {
      throw new Error(`LIMIT_VIOLATION: Amount exceeds per-transfer ceiling of ${this.max_per_transfer}`);
    }

    if (this.spent_today + amt > this.max_daily_total) {
      throw new Error("LIMIT_VIOLATION: Amount exceeds remaining daily budget");
    }

    this.proposal_nonce += 1;
    const proposalId = `prop-${this.proposal_nonce}`;

    let initialState = "SUBMITTED";
    if (amt > this.owner_approval_threshold) {
      initialState = "AWAITING_OWNER_APPROVAL";
      this.pending_count += 1;
    }

    const proposal = new Proposal({
      id: proposalId,
      recipient,
      amount: amt.toString(),
      memo: memo || "",
      state: initialState,
      createdAt: global.near.blockTimestamp().toString(),
      submittedDay: this.last_reset_day.toString()
    });

    this.proposals.set(proposalId, proposal);

    if (initialState === "SUBMITTED") {
      this.spent_today += amt;
    }

    return { proposal_id: proposalId, state: proposal.state };
  }

  owner_approve({ proposal_id, owner_public_key, signature_b58 }) {
    if (this.is_paused) throw new Error("SECURITY_ALERT: Vault is paused by emergency circuit breaker");

    const caller = global.near.predecessorAccountId();
    if (caller !== this.owner_id) throw new Error("Only owner can manually approve held proposals");

    const proposal = this.proposals.get(proposal_id);
    if (!proposal) throw new Error("Proposal does not exist");
    if (proposal.state !== "AWAITING_OWNER_APPROVAL") throw new Error("Proposal is not awaiting approval");

    this._checkAndResetDailyAllowance();
    const amt = BigInt(proposal.amount);

    if (!this.allowed_recipients.includes(proposal.recipient)) {
      throw new Error(`RECIPIENT_REVOKED: Recipient ${proposal.recipient} is no longer whitelisted`);
    }
    if (amt > this.max_per_transfer) {
      throw new Error(`LIMIT_EXCEEDED: Proposal amount (${amt}) exceeds current max_per_transfer (${this.max_per_transfer})`);
    }
    if (this.spent_today + amt > this.max_daily_total) throw new Error("Daily budget would be exceeded");

    if (owner_public_key && signature_b58) {
      proposal.attestation = {
        owner_public_key,
        signature: signature_b58,
        approved_at: global.near.blockTimestamp().toString()
      };
      global.near.log(`EVENT_JSON:{"standard":"carerail","version":"1.0.0","event":"owner_approval_attestation","data":[{"proposal_id":"${proposal_id}","public_key":"${owner_public_key}","signature":"${signature_b58}"}]}`);
    }

    this.spent_today += amt;
    proposal.state = "SUBMITTED";
    proposal.submittedDay = this.last_reset_day.toString();
    if (this.pending_count > 0) this.pending_count -= 1;
    this.proposals.set(proposal_id, proposal);

    return { proposal_id, state: "SUBMITTED", settled_amount: proposal.amount, attestation: proposal.attestation };
  }

  request_limit_update({ new_max_per_transfer, new_max_daily_total, new_owner_threshold }) {
    const caller = global.near.predecessorAccountId();
    if (caller !== this.owner_id) throw new Error("Only owner can request limit updates");

    const reqPerTransfer = BigInt(new_max_per_transfer);
    const reqDailyTotal = BigInt(new_max_daily_total);
    const curPerTransfer = BigInt(this.max_per_transfer);
    const curDailyTotal = BigInt(this.max_daily_total);

    if (reqDailyTotal > ABSOLUTE_MAX_DAILY_LIMIT) throw new Error(`LIMIT_VIOLATION: Exceeds protocol absolute daily cap (${ABSOLUTE_MAX_DAILY_LIMIT})`);
    if (reqPerTransfer > ABSOLUTE_MAX_PER_TRANSFER) throw new Error(`LIMIT_VIOLATION: Exceeds protocol absolute per-transfer cap (${ABSOLUTE_MAX_PER_TRANSFER})`);
    if (reqPerTransfer > reqDailyTotal) throw new Error("INVALID_LIMITS: Per-transfer limit cannot exceed daily total");

    const reqThreshold = new_owner_threshold !== undefined ? BigInt(new_owner_threshold) : this.owner_approval_threshold;
    const isIncrease = reqPerTransfer > curPerTransfer || reqDailyTotal > curDailyTotal || reqThreshold > this.owner_approval_threshold;

    if (isIncrease) {
      const unlock_timestamp = (global.near.blockTimestamp() + TIMELOCK_DURATION_NS).toString();
      this.pending_timelock_update = {
        new_max_per_transfer: reqPerTransfer.toString(),
        new_max_daily_total: reqDailyTotal.toString(),
        new_owner_threshold: reqThreshold.toString(),
        unlock_timestamp: unlock_timestamp
      };
      return { status: "QueuedInTimelock", unlock_timestamp };
    } else {
      this.max_per_transfer = reqPerTransfer;
      this.max_daily_total = reqDailyTotal;
      if (new_owner_threshold !== undefined) {
        this.owner_approval_threshold = BigInt(new_owner_threshold);
      }
      this.pending_timelock_update = null;
      return { status: "AppliedImmediately" };
    }
  }

  apply_limit_update() {
    const caller = global.near.predecessorAccountId();
    if (caller !== this.owner_id) throw new Error("Only owner can apply timelock updates");
    if (!this.pending_timelock_update) throw new Error("No pending timelock update found");

    const current_timestamp = global.near.blockTimestamp();
    const unlock_timestamp = BigInt(this.pending_timelock_update.unlock_timestamp);
    if (current_timestamp < unlock_timestamp) throw new Error("Timelock cooldown has not expired yet");

    this.max_per_transfer = BigInt(this.pending_timelock_update.new_max_per_transfer);
    this.max_daily_total = BigInt(this.pending_timelock_update.new_max_daily_total);
    this.owner_approval_threshold = BigInt(this.pending_timelock_update.new_owner_threshold);
    this.pending_timelock_update = null;

    return {
      status: "Success",
      max_per_transfer: this.max_per_transfer.toString(),
      max_daily_total: this.max_daily_total.toString(),
      owner_approval_threshold: this.owner_approval_threshold.toString()
    };
  }

  cancel_limit_update() {
    const caller = global.near.predecessorAccountId();
    if (caller !== this.owner_id) throw new Error("Only owner can cancel timelock updates");
    this.pending_timelock_update = null;
    return { status: "Cancelled" };
  }

  on_transfer_callback({ proposal_id, amount, transfer_succeeded = true }) {
    const caller = global.near.predecessorAccountId();
    if (caller !== global.near.currentAccountId()) {
      throw new Error("SECURITY_ALERT: Callback is strictly private to contract");
    }

    const proposal = this.proposals.get(proposal_id);
    if (!proposal) return false;
    if (proposal.state !== "SUBMITTED") {
      throw new Error("Invalid callback state transition");
    }

    if (transfer_succeeded) {
      proposal.state = "SETTLED";
      this.proposals.set(proposal_id, proposal);
      return true;
    } else {
      const amt = BigInt(proposal.amount || amount);
      const submittedDay = BigInt(proposal.submittedDay || this.last_reset_day.toString());
      if (submittedDay === this.last_reset_day) {
        if (this.spent_today >= amt) {
          this.spent_today -= amt;
        } else {
          this.spent_today = BigInt(0);
        }
      }
      proposal.state = "FAILED";
      this.proposals.set(proposal_id, proposal);
      return false;
    }
  }

  owner_reject({ proposal_id, reason }) {
    const caller = global.near.predecessorAccountId();
    if (caller !== this.owner_id) throw new Error("Only owner can reject proposals");

    const proposal = this.proposals.get(proposal_id);
    if (!proposal) throw new Error("Proposal does not exist");

    if (proposal.state !== "AWAITING_OWNER_APPROVAL" && proposal.state !== "PROPOSED") {
      throw new Error("Cannot reject settled or active transfer proposal");
    }

    if (proposal.state === "AWAITING_OWNER_APPROVAL" && this.pending_count > 0) {
      this.pending_count -= 1;
    }

    proposal.state = "REJECTED";
    proposal.memo = `${proposal.memo} [REJECTED: ${reason || "By owner"}]`;
    this.proposals.set(proposal_id, proposal);

    return { proposal_id, state: "REJECTED" };
  }
}

async function runTests() {
  console.log("=== Running PolicyVault Smart Contract Verification Suite ===");

  const vault = new PolicyVaultTestable();
  vault.init({
    owner_id: "human-owner.testnet",
    agent_id: "agent-01.testnet",
    allowed_recipients: ["care-clinic.testnet", "pharmacy.testnet"],
    max_per_transfer: "5000000000000000000000000",        // 5 NEAR
    max_daily_total: "10000000000000000000000000",       // 10 NEAR
    owner_approval_threshold: "2000000000000000000000000" // 2 NEAR
  });
  console.log("[PASS] Test 1: Contract Initialized Successfully");

  // 2. Normal low-value proposal auto-approved & verified via callback
  global.near._caller = "agent-01.testnet";
  const res1 = vault.propose_payment({
    recipient: "care-clinic.testnet",
    amount: "1500000000000000000000000", // 1.5 NEAR
    memo: "Physical therapy co-pay"
  });
  assert.strictEqual(res1.state, "SUBMITTED");
  assert.strictEqual(vault.spent_today, BigInt("1500000000000000000000000"));

  global.near._caller = "vault.testnet";
  const cbRes = vault.on_transfer_callback({
    proposal_id: res1.proposal_id,
    amount: "1500000000000000000000000",
    transfer_succeeded: true
  });
  assert.strictEqual(cbRes, true);
  const p1 = vault.proposals.get(res1.proposal_id);
  assert.strictEqual(p1.state, "SETTLED");
  console.log("[PASS] Test 2: Auto-Approved Proposal Verified & Settled via Callback");

  // 3. Unwhitelisted recipient blocked
  global.near._caller = "agent-01.testnet";
  assert.throws(() => {
    vault.propose_payment({
      recipient: "hacker-wallet.testnet",
      amount: "1000000000000000000000000",
      memo: "Exploit attempt"
    });
  }, /SECURITY_VIOLATION/);
  console.log("[PASS] Test 3: Unwhitelisted Recipient Blocked (Fail-Closed)");

  // 4. Per-transfer ceiling
  assert.throws(() => {
    vault.propose_payment({
      recipient: "care-clinic.testnet",
      amount: "6000000000000000000000000", // 6 NEAR > 5 NEAR max
      memo: "Over limit"
    });
  }, /LIMIT_VIOLATION/);
  console.log("[PASS] Test 4: Single Transfer Limit Exceeded Blocked");

  // 5. High-value held for owner approval
  const resHeld = vault.propose_payment({
    recipient: "care-clinic.testnet",
    amount: "3000000000000000000000000", // 3 NEAR > 2 NEAR threshold
    memo: "MRI Diagnostics"
  });
  assert.strictEqual(resHeld.state, "AWAITING_OWNER_APPROVAL");
  console.log("[PASS] Test 5: High Value Held for Owner Approval");

  // 6. Owner approval
  global.near._caller = "human-owner.testnet";
  const approveRes = vault.owner_approve({ proposal_id: resHeld.proposal_id });
  assert.strictEqual(approveRes.state, "SUBMITTED");
  global.near._caller = "vault.testnet";
  vault.on_transfer_callback({ proposal_id: resHeld.proposal_id, amount: "3000000000000000000000000", transfer_succeeded: true });
  assert.strictEqual(vault.proposals.get(resHeld.proposal_id).state, "SETTLED");
  console.log("[PASS] Test 6: Owner Approved Held Proposal Settled Successfully");

  // 7. Failed transfer rolls back daily spend
  global.near._caller = "agent-01.testnet";
  const resFail = vault.propose_payment({
    recipient: "care-clinic.testnet",
    amount: "1000000000000000000000000",
    memo: "Will fail"
  });
  const spendBeforeRollback = vault.spent_today;
  global.near._caller = "vault.testnet";
  vault.on_transfer_callback({ proposal_id: resFail.proposal_id, amount: "1000000000000000000000000", transfer_succeeded: false });
  assert.strictEqual(vault.proposals.get(resFail.proposal_id).state, "FAILED");
  assert.strictEqual(vault.spent_today, spendBeforeRollback - BigInt("1000000000000000000000000"));
  console.log("[PASS] Test 7: Failed Transfer Rolls Back Daily Budget (Terra F-02 Fixed)");

  // 8. Cannot reject settled proposals
  global.near._caller = "human-owner.testnet";
  assert.throws(() => {
    vault.owner_reject({ proposal_id: res1.proposal_id, reason: "Too late" });
  }, /Cannot reject settled or active transfer proposal/);
  console.log("[PASS] Test 8: Cannot Retroactively Tamper With Settled Proposals (Audit Invariant Passed)");

  // 9. External callback hijacking blocked
  global.near._caller = "attacker.testnet";
  assert.throws(() => {
    vault.on_transfer_callback({ proposal_id: "dummy", amount: "100" });
  }, /Callback is strictly private to contract/);
  console.log("[PASS] Test 9: External Callback Hijacking Blocked (P0 Fixed)");

  // 10. Dust spam proposal blocked
  global.near._caller = "agent-01.testnet";
  assert.throws(() => {
    vault.propose_payment({
      recipient: "care-clinic.testnet",
      amount: "500000000000000000000", // 0.0005 NEAR
      memo: "Dust attack"
    });
  }, /SECURITY_ALERT: Amount below minimum floor/);
  console.log("[PASS] Test 10: Sub-0.001 NEAR Dust Spam Proposal Blocked (P1 Fixed)");

  // 11. Emergency Circuit Breaker Freeze & Resume
  global.near._caller = "human-owner.testnet";
  vault.set_emergency_pause({ paused: true });
  assert.strictEqual(vault.is_paused, true);
  global.near._caller = "agent-01.testnet";
  assert.throws(() => {
    vault.propose_payment({
      recipient: "care-clinic.testnet",
      amount: "1000000000000000000000000",
      memo: "Emergency test"
    });
  }, /SECURITY_ALERT: Vault is paused by emergency circuit breaker/);
  global.near._caller = "human-owner.testnet";
  vault.set_emergency_pause({ paused: false });
  assert.strictEqual(vault.is_paused, false);
  console.log("[PASS] Test 11: Emergency Circuit Breaker Freeze & Resume Verified (P1 Fixed)");

  // 12. Day-boundary accounting isolation
  global.near._caller = "agent-01.testnet";
  const pPast = vault.propose_payment({
    recipient: "care-clinic.testnet",
    amount: "1000000000000000000000000",
    memo: "Day D Proposal"
  });
  global.near._timestamp += DAY_IN_NANOSECONDS;
  vault._checkAndResetDailyAllowance();
  assert.strictEqual(vault.spent_today, BigInt(0));
  vault.propose_payment({
    recipient: "care-clinic.testnet",
    amount: "2000000000000000000000000",
    memo: "Day D+1 Proposal"
  });
  assert.strictEqual(vault.spent_today, BigInt("2000000000000000000000000"));
  global.near._caller = "vault.testnet";
  vault.on_transfer_callback({ proposal_id: pPast.proposal_id, amount: "1000000000000000000000000", transfer_succeeded: false });
  assert.strictEqual(vault.spent_today, BigInt("2000000000000000000000000"));
  console.log("[PASS] Test 12: Day-Boundary Accounting Isolation Verified (P0 Fixed)");

  // 13. Bounded storage memo
  global.near._caller = "agent-01.testnet";
  assert.throws(() => {
    vault.propose_payment({
      recipient: "care-clinic.testnet",
      amount: "1000000000000000000000000",
      memo: "A".repeat(300)
    });
  }, /SECURITY_ALERT: Memo exceeds 256 character limit/);
  console.log("[PASS] Test 13: Bounded Storage Memo Protection Verified (P2 Fixed)");

  // 14. [Annie Verified] Cryptographic NEP-413 Attestation Recording
  global.near._caller = "agent-01.testnet";
  const pAttest = vault.propose_payment({
    recipient: "care-clinic.testnet",
    amount: "3000000000000000000000000", // 3 NEAR > 2 NEAR threshold
    memo: "Specialist surgery approval"
  });
  global.near._caller = "human-owner.testnet";
  const testPubKey = "ed25519:6E8sCci9badyRkXb3JoRtubqwUMoVMMNaY2LTCSt6Z11";
  const testSig = "3h7Gj...validBase58Signature...";
  const approveWithAttest = vault.owner_approve({
    proposal_id: pAttest.proposal_id,
    owner_public_key: testPubKey,
    signature_b58: testSig
  });
  assert.ok(approveWithAttest.attestation, "Attestation must be recorded");
  assert.strictEqual(approveWithAttest.attestation.owner_public_key, testPubKey);
  assert.strictEqual(approveWithAttest.attestation.signature, testSig);
  const foundLog = global.near._logs.some(l => l.includes("owner_approval_attestation") && l.includes(testPubKey));
  assert.ok(foundLog, "NEP-297 event log must be emitted");
  console.log("[PASS] Test 14: On-Chain Cryptographic Attestation Recording Verified (Annie Verified)");

  // 15. [Annie Verified] Absolute Protocol Hard Caps Protection
  global.near._caller = "human-owner.testnet";
  assert.throws(() => {
    vault.request_limit_update({
      new_max_per_transfer: "15000000000000000000000000", // 15 NEAR > 10 NEAR hard cap
      new_max_daily_total: "60000000000000000000000000"   // 60 NEAR > 50 NEAR hard cap
    });
  }, /LIMIT_VIOLATION: Exceeds protocol absolute/);
  console.log("[PASS] Test 15: Absolute Protocol Hard Caps Protection Verified (Annie Verified)");

  // 16. [Annie Verified] Governance Time-Lock 24h Cooldown on Limit Increase
  const timelockRes = vault.request_limit_update({
    new_max_per_transfer: "8000000000000000000000000", // 8 NEAR > 5 NEAR (Increase!)
    new_max_daily_total: "15000000000000000000000000"  // 15 NEAR > 10 NEAR (Increase!)
  });
  assert.strictEqual(timelockRes.status, "QueuedInTimelock");
  assert.ok(vault.pending_timelock_update !== null);

  // Attempt to apply immediately before 24h cooldown -> MUST REVERT!
  assert.throws(() => {
    vault.apply_limit_update();
  }, /Timelock cooldown has not expired yet/);

  // Advance time by 24h (86400s) -> MUST SUCCEED!
  global.near._timestamp += TIMELOCK_DURATION_NS;
  const applied = vault.apply_limit_update();
  assert.strictEqual(applied.status, "Success");
  assert.strictEqual(vault.max_per_transfer, BigInt("8000000000000000000000000"));
  assert.strictEqual(vault.max_daily_total, BigInt("15000000000000000000000000"));
  assert.strictEqual(vault.pending_timelock_update, null);
  console.log("[PASS] Test 16: Governance 24h Time-Lock Cooldown Verified (Annie Verified)");

  // 17. [Annie Verified] Defensive Instant Limit Reduction & Timelock Cancellation
  // Queue another increase
  vault.request_limit_update({
    new_max_per_transfer: "9000000000000000000000000",
    new_max_daily_total: "20000000000000000000000000"
  });
  assert.ok(vault.pending_timelock_update !== null);

  // Instant emergency reduction down to 3 NEAR -> Applied immediately, cancelling pending queue!
  const redRes = vault.request_limit_update({
    new_max_per_transfer: "3000000000000000000000000",
    new_max_daily_total: "6000000000000000000000000"
  });
  assert.strictEqual(redRes.status, "AppliedImmediately");
  assert.strictEqual(vault.max_per_transfer, BigInt("3000000000000000000000000"));
  assert.strictEqual(vault.pending_timelock_update, null);
  console.log("[PASS] Test 17: Defensive Instant Limit Reduction & Cancellation Verified (Annie Verified)");

  // 18. [Terra Round 5 Fix] Approval Threshold Elevation Must Require 24h Timelock
  // Only raising owner_approval_threshold (from 2 NEAR to 4 NEAR) without changing per-tx or daily caps
  const threshRes = vault.request_limit_update({
    new_max_per_transfer: vault.max_per_transfer.toString(),
    new_max_daily_total: vault.max_daily_total.toString(),
    new_owner_threshold: "4000000000000000000000000" // 4 NEAR (Increase!)
  });
  assert.strictEqual(threshRes.status, "QueuedInTimelock", "Elevating owner approval threshold MUST require 24h timelock");
  assert.ok(vault.pending_timelock_update !== null);
  console.log("[PASS] Test 18: Owner Threshold Elevation Protected by 24h Timelock (Terra Round 5 Fixed)");

  // 19. [Terra Round 6 Fix] Owner Approve Must Re-validate Max Per Transfer Against Current Limits
  // Agent creates proposal for 2.5 NEAR (valid under current 3.0 NEAR cap, held for owner approval > 2.0 NEAR)
  global.near._caller = "agent-01.testnet";
  const heldProp = vault.propose_payment({
    recipient: "care-clinic.testnet",
    amount: "2500000000000000000000000", // 2.5 NEAR
    memo: "Specialist surgery"
  });
  assert.strictEqual(heldProp.state, "AWAITING_OWNER_APPROVAL");

  // Owner lowers max_per_transfer to 1.0 NEAR defensively
  global.near._caller = "human-owner.testnet";
  vault.request_limit_update({
    new_max_per_transfer: "1000000000000000000000000", // 1.0 NEAR
    new_max_daily_total: "4000000000000000000000000"
  });
  assert.strictEqual(vault.max_per_transfer, BigInt("1000000000000000000000000"));

  // Now owner attempts to approve the 2.5 NEAR proposal -> MUST BE REJECTED because it exceeds CURRENT limit!
  let approveBlocked = false;
  try {
    vault.owner_approve({ proposal_id: heldProp.proposal_id });
  } catch (err) {
    approveBlocked = err.message.includes("LIMIT_EXCEEDED");
  }
  assert.ok(approveBlocked, "Approval of proposal exceeding newly reduced per-transfer cap MUST FAIL");
  console.log("[PASS] Test 19: Owner Approve Re-validates Against Current Reduced Limits (Terra Round 6 Fixed)");

  // 20. [DeepSeek-V4.1-Flash Engineered] Engine Attestation Key Activation & Enforcement
  global.near._caller = "human-owner.testnet";
  const testSecret = "carerail-super-secure-secret-key-2026";
  vault.set_engine_attestation_key({ engine_attestation_key: testSecret });
  assert.strictEqual(vault.engine_attestation_key, testSecret);

  // Now, agent attempts to propose payment without attestation -> MUST BE REJECTED!
  global.near._caller = "agent-01.testnet";
  assert.throws(() => {
    vault.propose_payment({
      recipient: "care-clinic.testnet",
      amount: "500000000000000000000000", // 0.5 NEAR
      memo: "Unattested Rogue Agent Proposal"
    });
  }, /SECURITY_ALERT: Attestation required by policy vault/);
  console.log("[PASS] Test 20: Missing Attestation Rejected When Engine Key Configured");

  // 21. [DeepSeek-V4.1-Flash Engineered] Tampered, Expired, and Replayed Attestations Blocked
  const validEngineId = "carerail-engine-v1";
  const validRecipient = "care-clinic.testnet";
  const validAmt = "500000000000000000000000"; // 0.5 NEAR
  const currentTs = global.near.blockTimestamp();
  const futureExp = (currentTs + BigInt(60000000000)).toString(); // +60s
  const nonce1 = "nonce-test-uuid-001";

  // Create valid HMAC-SHA256 signature
  const canonical1 = `${validEngineId}|agent-01.testnet|${validRecipient}|${validAmt}|${nonce1}|${futureExp}`;
  const validSig = hmacSha256Hex(testSecret, canonical1);

  // A. Tampered amount in ticket -> MUST FAIL!
  const tamperedAtt = JSON.stringify({
    engine_id: validEngineId,
    agent_id: "agent-01.testnet",
    recipient: validRecipient,
    amount_yocto: "1000000000000000000000000", // Tampered amount
    nonce: nonce1,
    expires_at: futureExp,
    sig_hash: validSig
  });
  assert.throws(() => {
    vault.propose_payment({
      recipient: validRecipient,
      amount: validAmt,
      memo: "Tampered Ticket",
      attestation: tamperedAtt
    });
  }, /INVALID_ENGINE_ATTESTATION/);

  // B. Expired attestation ticket -> MUST FAIL!
  const pastExp = (currentTs - BigInt(1000000000)).toString(); // -1s
  const expiredCanonical = `${validEngineId}|agent-01.testnet|${validRecipient}|${validAmt}|${nonce1}|${pastExp}`;
  const expiredSig = hmacSha256Hex(testSecret, expiredCanonical);
  const expiredAtt = JSON.stringify({
    engine_id: validEngineId,
    agent_id: "agent-01.testnet",
    recipient: validRecipient,
    amount_yocto: validAmt,
    nonce: nonce1,
    expires_at: pastExp,
    sig_hash: expiredSig
  });
  assert.throws(() => {
    vault.propose_payment({
      recipient: validRecipient,
      amount: validAmt,
      memo: "Expired Ticket",
      attestation: expiredAtt
    });
  }, /Attestation ticket expired/);

  // C. Valid attestation -> MUST SUCCEED!
  const validAtt = JSON.stringify({
    engine_id: validEngineId,
    agent_id: "agent-01.testnet",
    recipient: validRecipient,
    amount_yocto: validAmt,
    nonce: nonce1,
    expires_at: futureExp,
    sig_hash: validSig
  });
  const attProp = vault.propose_payment({
    recipient: validRecipient,
    amount: validAmt,
    memo: "Cryptographically Attested Proposal",
    attestation: validAtt
  });
  assert.strictEqual(attProp.state, "SUBMITTED");
  console.log("[PASS] Test 21: Tampered & Expired Attestations Blocked (Fail-Closed)");

  // D. Replay of same attestation nonce -> MUST FAIL!
  assert.throws(() => {
    vault.propose_payment({
      recipient: validRecipient,
      amount: validAmt,
      memo: "Replay Attempt",
      attestation: validAtt
    });
  }, /Attestation nonce already consumed/);
  console.log("[PASS] Test 22: Attestation Nonce Replay Blocked");

  // Test 23: Non-Integer & Malformed Amount Injection Blocked (Fail-Closed)
  assert.throws(() => {
    vault.propose_payment({
      recipient: validRecipient,
      amount: "0.5",
      memo: "Float Injection"
    });
  }, /must be positive integer yoctoNEAR string/);

  assert.throws(() => {
    vault.propose_payment({
      recipient: validRecipient,
      amount: "-1000000000000000000000000",
      memo: "Negative Amount Injection"
    });
  }, /must be positive integer yoctoNEAR string/);

  assert.throws(() => {
    vault.propose_payment({
      recipient: validRecipient,
      amount: "NaN",
      memo: "NaN Injection"
    });
  }, /must be positive integer yoctoNEAR string/);
  console.log("[PASS] Test 23: Non-Integer & Malformed Amount Injection Blocked");

  // Test 24: Bounded Recipient Length Protection (1 to 64 chars)
  assert.throws(() => {
    vault.propose_payment({
      recipient: "a".repeat(65),
      amount: "1000000000000000000000",
      memo: "Recipient Over 64 Chars"
    });
  }, /must be between 1 and 64 characters/);

  assert.throws(() => {
    vault.propose_payment({
      recipient: "",
      amount: "1000000000000000000000",
      memo: "Empty Recipient"
    });
  }, /must be between 1 and 64 characters/);
  console.log("[PASS] Test 24: Bounded Recipient Account ID (1-64 chars) Verified");

  // Test 25: 10,000 Chars Memory Bombing in Memo Blocked
  assert.throws(() => {
    vault.propose_payment({
      recipient: validRecipient,
      amount: "1000000000000000000000",
      memo: "X".repeat(10000)
    });
  }, /Memo exceeds 256 character limit/);
  console.log("[PASS] Test 25: 10k Character Memory Bombing in Memo Blocked");

  console.log("\n>>> ALL 25 CONTRACT INVARIANT TESTS PASSED (100%) <<<");
}

runTests().catch(err => {
  console.error("TEST FAILED:", err);
  process.exit(1);
});
