import { NearBindgen, call, view, initialize, near, UnorderedMap, LookupMap, assert } from 'near-sdk-js';

const DAY_IN_NANOSECONDS = BigInt(86400) * BigInt(1000000000);
const MIN_TRANSFER_FLOOR = BigInt("1000000000000000000000"); // 0.001 NEAR (Anti-Dust Spam Floor)
const MAX_PENDING_PROPOSALS = 50;
const attestationNonces = new LookupMap("uan");

// Security Constants: Absolute Protocol Caps and Governance Time-Lock (Verified by Annie)
const ABSOLUTE_MAX_DAILY_LIMIT = BigInt("50000000000000000000000000"); // 50 NEAR absolute daily ceiling
const ABSOLUTE_MAX_PER_TRANSFER = BigInt("10000000000000000000000000"); // 10 NEAR absolute per-tx ceiling
const TIMELOCK_DURATION_NS = BigInt(86400) * BigInt(1000000000); // 24 hours governance cooldown

// ============ Engine Attestation Cryptographic Helpers (QuickJS-safe) ============
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
    key = near.sha256(key);
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
  const innerHash = near.sha256(inner);

  const outer = new Uint8Array(BLOCK + innerHash.length);
  outer.set(opad, 0);
  outer.set(innerHash, BLOCK);
  return near.sha256(outer);
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

class Proposal {
  constructor({ id, recipient, amount, memo, state, createdAt, submittedDay, attestation }) {
    this.id = id;
    this.recipient = recipient;
    this.amount = amount;
    this.memo = memo;
    this.state = state; // "PROPOSED", "AWAITING_OWNER_APPROVAL", "SUBMITTED", "SETTLED", "REJECTED", "FAILED"
    this.createdAt = createdAt;
    this.submittedDay = submittedDay; // Immutable day index for precise rollback accounting
    // In near-sdk-js reconstruct, fields MUST NOT be null (causes null.constructor panic)
    this.attestation = attestation || ""; // Serialized JSON or empty string
  }
}

@NearBindgen({ requireInit: true })
export class PolicyVault {
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
    // In near-sdk-js reconstruct, fields MUST NOT be null (causes null.constructor panic)
    this.pending_timelock_update = ""; // Serialized JSON string or empty string
    this.proposals = new UnorderedMap("p");
    this.proposal_nonce = 0;
    this.engine_attestation_key = ""; // Shared HMAC secret or empty string
  }

  @initialize({})
  init({ owner_id, agent_id, allowed_recipients, max_per_transfer, max_daily_total, owner_approval_threshold, engine_attestation_key }) {
    assert(owner_id.length > 0, "Owner ID cannot be empty");
    assert(agent_id.length > 0, "Agent ID cannot be empty");

    const perTransfer = BigInt(max_per_transfer);
    const dailyTotal = BigInt(max_daily_total);

    // Enforce absolute protocol hard caps even at initialization
    assert(perTransfer <= ABSOLUTE_MAX_PER_TRANSFER, "max_per_transfer exceeds absolute protocol hard cap");
    assert(dailyTotal <= ABSOLUTE_MAX_DAILY_LIMIT, "max_daily_total exceeds absolute protocol hard cap");

    this.owner_id = owner_id;
    this.agent_id = agent_id;
    this.allowed_recipients = allowed_recipients || [];
    this.max_per_transfer = perTransfer;
    this.max_daily_total = dailyTotal;
    this.owner_approval_threshold = BigInt(owner_approval_threshold);
    this.spent_today = BigInt(0);
    this.last_reset_day = near.blockTimestamp() / DAY_IN_NANOSECONDS;
    this.is_paused = false;
    this.pending_count = 0;
    this.pending_timelock_update = "";
    this.proposal_nonce = 0;
    this.engine_attestation_key = engine_attestation_key || "";
  }

  // --- Internal Guardrail Helper ---
  _checkAndResetDailyAllowance() {
    const currentDay = near.blockTimestamp() / DAY_IN_NANOSECONDS;
    if (currentDay > this.last_reset_day) {
      this.spent_today = BigInt(0);
      this.last_reset_day = currentDay;
    }
  }

  // --- Engine Attestation Verifier (Fail-Closed) ---
  _verifyAttestation(attestationStr, caller, recipient, amt) {
    assert(typeof attestationStr === 'string' && attestationStr.length > 0, "SECURITY_ALERT: Attestation required by policy vault");
    let att = null;
    try {
      att = JSON.parse(attestationStr);
    } catch (e) {
      att = null;
    }
    assert(att && typeof att === 'object', "INVALID_ENGINE_ATTESTATION: Malformed JSON");
    assert(typeof att.engine_id === 'string' && att.engine_id.length > 0, "INVALID_ENGINE_ATTESTATION: Missing engine_id");
    assert(att.agent_id === caller, "INVALID_ENGINE_ATTESTATION: Caller agent mismatch");
    assert(att.recipient === recipient, "INVALID_ENGINE_ATTESTATION: Recipient mismatch");
    assert(att.amount_yocto === amt.toString(), "INVALID_ENGINE_ATTESTATION: Amount mismatch");
    assert(typeof att.nonce === 'string' && att.nonce.length > 0, "INVALID_ENGINE_ATTESTATION: Missing nonce");
    assert(typeof att.expires_at === 'string' && /^\d+$/.test(att.expires_at), "INVALID_ENGINE_ATTESTATION: Missing or invalid expires_at");
    assert(typeof att.sig_hash === 'string' && att.sig_hash.length === 64, "INVALID_ENGINE_ATTESTATION: Invalid sig_hash format");

    // Expiry check
    const currentTs = near.blockTimestamp();
    const expiresAt = BigInt(att.expires_at);
    assert(expiresAt > currentTs, "INVALID_ENGINE_ATTESTATION: Attestation ticket expired");

    // Nonce replay check on-chain (using storage-level LookupMap)
    const nonceKey = `nonce:${att.nonce}`;
    assert(!attestationNonces.containsKey(nonceKey), "INVALID_ENGINE_ATTESTATION: Attestation nonce already consumed");

    // Cryptographic HMAC check
    const canonical = `${att.engine_id}|${att.agent_id}|${att.recipient}|${att.amount_yocto}|${att.nonce}|${att.expires_at}`;
    const expectedSig = hmacSha256Hex(this.engine_attestation_key, canonical);
    assert(constantTimeEqualHex(expectedSig, att.sig_hash), "INVALID_ENGINE_ATTESTATION: Cryptographic signature mismatch");

    attestationNonces.set(nonceKey, "1");
  }

  @call({})
  set_engine_attestation_key({ engine_attestation_key }) {
    assert(!this.is_paused, "SECURITY_ALERT: Vault is paused by emergency circuit breaker");
    const caller = near.predecessorAccountId();
    assert(caller === this.owner_id, "Only owner can set engine attestation key");
    this.engine_attestation_key = engine_attestation_key || "";
    return { engine_attestation_key: this.engine_attestation_key };
  }

  @view({})
  get_engine_attestation_key() {
    return this.engine_attestation_key || "";
  }

  // --- Emergency Circuit Breaker (P1 Feature) ---
  @call({})
  set_emergency_pause({ paused }) {
    const caller = near.predecessorAccountId();
    assert(caller === this.owner_id, "Only owner can toggle emergency pause");
    this.is_paused = !!paused;
    return { is_paused: this.is_paused };
  }

  // ==========================================
  // [보안 기능 1] 온체인 암호학적 서명 박제 (Attestation)
  // ==========================================
  @call({})
  owner_approve({ proposal_id, owner_public_key, signature_b58 }) {
    assert(!this.is_paused, "SECURITY_ALERT: Vault is paused by emergency circuit breaker");

    const caller = near.predecessorAccountId();
    assert(caller === this.owner_id, "Only owner can manually approve held proposals");

    const proposal = this.proposals.get(proposal_id);
    assert(proposal !== null, "Proposal does not exist");
    assert(proposal.state === "AWAITING_OWNER_APPROVAL", "Proposal is not awaiting approval");

    this._checkAndResetDailyAllowance();
    const amt = BigInt(proposal.amount);

    // Re-verify recipient whitelist and per-transfer limit against current live policy rules (Terra Round 6 Fixed)
    assert(this.allowed_recipients.includes(proposal.recipient), `RECIPIENT_REVOKED: Recipient ${proposal.recipient} is no longer whitelisted`);
    assert(amt <= this.max_per_transfer, `LIMIT_EXCEEDED: Proposal amount (${amt}) exceeds current max_per_transfer (${this.max_per_transfer})`);
    assert(this.spent_today + amt <= this.max_daily_total, "Daily budget would be exceeded");

    // Cryptographic attestation recording (Bounded byte lengths for DoS defense)
    if (owner_public_key && signature_b58) {
      assert(owner_public_key.length <= 128, "SECURITY_ALERT: Public key exceeds 128 characters");
      assert(signature_b58.length <= 256, "SECURITY_ALERT: Signature exceeds 256 characters");
      proposal.attestation = JSON.stringify({
        owner_public_key: owner_public_key,
        signature: signature_b58,
        approved_at: near.blockTimestamp().toString()
      });

      // Emit NEP-297 compliant event for blockchain explorers and indexers
      const eventPayload = {
        standard: "carerail",
        version: "1.0.0",
        event: "owner_approval_attestation",
        data: [{
          proposal_id: proposal_id.toString(),
          public_key: owner_public_key,
          signature: signature_b58
        }]
      };
      near.log(`EVENT_JSON:${JSON.stringify(eventPayload)}`);
    }

    this.spent_today += amt;
    proposal.state = "SUBMITTED";
    proposal.submittedDay = this.last_reset_day.toString();
    if (this.pending_count && this.pending_count > 0) this.pending_count -= 1;
    this.proposals.set(proposal_id, proposal);

    // Execute on-chain transfer with verified callback
    const promiseId = near.promiseBatchCreate(proposal.recipient);
    near.promiseBatchActionTransfer(promiseId, amt);

    const callbackPromiseId = near.promiseThen(
      promiseId,
      near.currentAccountId(),
      "on_transfer_callback",
      JSON.stringify({ proposal_id: proposal_id, amount: amt.toString() }),
      0,
      BigInt("10000000000000") // 10 Tgas
    );
    near.promiseReturn(callbackPromiseId);

    return { proposal_id, state: "SUBMITTED", settled_amount: proposal.amount, attestation: proposal.attestation };
  }

  // ==========================================
  // [보안 기능 2] 소유자 키 탈취 방어: 타임락 및 절대 상한선
  // ==========================================
  @call({})
  request_limit_update({ new_max_per_transfer, new_max_daily_total, new_owner_threshold }) {
    const caller = near.predecessorAccountId();
    assert(caller === this.owner_id, "Only owner can request limit updates");

    const reqPerTransfer = BigInt(new_max_per_transfer);
    const reqDailyTotal = BigInt(new_max_daily_total);
    const curPerTransfer = BigInt(this.max_per_transfer);
    const curDailyTotal = BigInt(this.max_daily_total);

    // 1. Enforce absolute protocol hard caps (No owner key can exceed this)
    assert(reqDailyTotal <= ABSOLUTE_MAX_DAILY_LIMIT, `LIMIT_VIOLATION: Exceeds protocol absolute daily cap (${ABSOLUTE_MAX_DAILY_LIMIT})`);
    assert(reqPerTransfer <= ABSOLUTE_MAX_PER_TRANSFER, `LIMIT_VIOLATION: Exceeds protocol absolute per-transfer cap (${ABSOLUTE_MAX_PER_TRANSFER})`);
    assert(reqPerTransfer <= reqDailyTotal, "INVALID_LIMITS: Per-transfer limit cannot exceed daily total");

    // 2. Identify if this is a limit increase or threshold elevation (requires 24h timelock)
    const reqThreshold = new_owner_threshold !== undefined ? BigInt(new_owner_threshold) : this.owner_approval_threshold;
    const isIncrease = reqPerTransfer > curPerTransfer || reqDailyTotal > curDailyTotal || reqThreshold > this.owner_approval_threshold;

    if (isIncrease) {
      const unlock_timestamp = (near.blockTimestamp() + TIMELOCK_DURATION_NS).toString();
      this.pending_timelock_update = JSON.stringify({
        new_max_per_transfer: reqPerTransfer.toString(),
        new_max_daily_total: reqDailyTotal.toString(),
        new_owner_threshold: reqThreshold.toString(),
        unlock_timestamp: unlock_timestamp
      });

      near.log(`[SECURITY TIMELOCK QUEUED] Limit increase queued. Unlocks at blockTimestamp: ${unlock_timestamp}`);
      return { status: "QueuedInTimelock", unlock_timestamp };
    } else {
      // Immediate decrease / defensive tightening: apply instantly and cancel any pending increase queue
      this.max_per_transfer = reqPerTransfer;
      this.max_daily_total = reqDailyTotal;
      if (new_owner_threshold !== undefined) {
        this.owner_approval_threshold = BigInt(new_owner_threshold);
      }
      this.pending_timelock_update = "";

      near.log(`[SECURITY LIMIT DECREASED] Instant update applied. New max_per_transfer: ${this.max_per_transfer}, daily_total: ${this.max_daily_total}`);
      return { status: "AppliedImmediately" };
    }
  }

  @call({})
  apply_limit_update() {
    const caller = near.predecessorAccountId();
    assert(caller === this.owner_id, "Only owner can apply timelock updates");
    assert(this.pending_timelock_update && this.pending_timelock_update.length > 0, "No pending timelock update found");

    const pending = JSON.parse(this.pending_timelock_update);
    const current_timestamp = near.blockTimestamp();
    const unlock_timestamp = BigInt(pending.unlock_timestamp);
    assert(current_timestamp >= unlock_timestamp, "Timelock cooldown has not expired yet");

    this.max_per_transfer = BigInt(pending.new_max_per_transfer);
    this.max_daily_total = BigInt(pending.new_max_daily_total);
    this.owner_approval_threshold = BigInt(pending.new_owner_threshold);
    this.pending_timelock_update = "";

    near.log(`[SECURITY TIMELOCK APPLIED] Limits updated successfully: per_transfer=${this.max_per_transfer}, daily_total=${this.max_daily_total}`);
    return {
      status: "Success",
      max_per_transfer: this.max_per_transfer.toString(),
      max_daily_total: this.max_daily_total.toString(),
      owner_approval_threshold: this.owner_approval_threshold.toString()
    };
  }

  @call({})
  cancel_limit_update() {
    const caller = near.predecessorAccountId();
    assert(caller === this.owner_id, "Only owner can cancel timelock updates");
    this.pending_timelock_update = "";
    near.log(`[SECURITY TIMELOCK CANCELLED] Pending limit increase queue cleared.`);
    return { status: "Cancelled" };
  }

  // --- Agent Propose Function ---
  @call({})
  propose_payment({ recipient, amount, memo, attestation }) {
    assert(!this.is_paused, "SECURITY_ALERT: Vault is paused by emergency circuit breaker");

    const caller = near.predecessorAccountId();
    assert(caller === this.agent_id || caller === this.owner_id, "Caller is not authorized agent or owner");

    this._checkAndResetDailyAllowance();

    // Input sanitization: ensure valid positive BigInt and bounded memo
    assert(typeof recipient === 'string' && recipient.length > 0, "Invalid recipient");
    assert(!memo || memo.length <= 256, "SECURITY_ALERT: Memo exceeds 256 character limit");
    assert(amount !== undefined && amount !== null, "Invalid amount: required");
    const amountStr = typeof amount === 'string' ? amount : amount.toString();
    assert(/^\d+$/.test(amountStr), "Invalid amount: must be positive integer yoctoNEAR string");
    const amt = BigInt(amountStr);
    assert(amt > BigInt(0), "Amount must be strictly positive");

    // Guardrail: Cryptographic Engine Attestation Verification (Fail-Closed)
    if (this.engine_attestation_key && this.engine_attestation_key.length > 0) {
      this._verifyAttestation(attestation, caller, recipient, amt);
    }

    // Guardrail 0: Anti-Dust Spam and Max Pending Ceiling
    assert(amt >= MIN_TRANSFER_FLOOR, `SECURITY_ALERT: Amount below minimum floor (0.001 NEAR)`);
    const currentPending = this.pending_count || 0;
    assert(currentPending < MAX_PENDING_PROPOSALS, "SECURITY_ALERT: Maximum pending proposals reached");

    // Guardrail 1: Whitelist Check
    const isWhitelisted = this.allowed_recipients.includes(recipient);
    assert(isWhitelisted, `SECURITY_VIOLATION: Recipient ${recipient} is not whitelisted`);

    // Guardrail 2: Per-transfer ceiling
    assert(amt <= this.max_per_transfer, `LIMIT_VIOLATION: Amount exceeds per-transfer ceiling of ${this.max_per_transfer}`);

    // Guardrail 3: Daily cumulative ceiling
    assert(this.spent_today + amt <= this.max_daily_total, `LIMIT_VIOLATION: Amount exceeds remaining daily budget`);

    this.proposal_nonce += 1;
    const proposalId = `prop-${this.proposal_nonce}`;

    // Guardrail 4: Human-in-the-Loop Threshold Check
    let initialState = "SUBMITTED";
    if (amt > this.owner_approval_threshold) {
      initialState = "AWAITING_OWNER_APPROVAL";
      this.pending_count = (this.pending_count || 0) + 1;
    }

    const proposal = new Proposal({
      id: proposalId,
      recipient,
      amount: amt.toString(),
      memo: memo || "",
      state: initialState,
      createdAt: near.blockTimestamp().toString(),
      submittedDay: this.last_reset_day.toString(),
      attestation: attestation || ""
    });

    this.proposals.set(proposalId, proposal);

    // If auto-approved (under threshold), initiate transfer promise with verified completion callback
    if (initialState === "SUBMITTED") {
      this.spent_today += amt;
      const promiseId = near.promiseBatchCreate(recipient);
      near.promiseBatchActionTransfer(promiseId, amt);

      const callbackPromiseId = near.promiseThen(
        promiseId,
        near.currentAccountId(),
        "on_transfer_callback",
        JSON.stringify({ proposal_id: proposalId, amount: amt.toString() }),
        0,
        BigInt("10000000000000") // 10 Tgas
      );
      near.promiseReturn(callbackPromiseId);
    }

    return { proposal_id: proposalId, state: proposal.state };
  }

  // --- Private Asynchronous Transfer Callback (P0 Protected) ---
  @call({})
  on_transfer_callback({ proposal_id, amount }) {
    // Strictly isolate callback to contract self-calls (Blocks external caller hijacking)
    assert(near.predecessorAccountId() === near.currentAccountId(), "Callback is strictly private to contract");

    const proposal = this.proposals.get(proposal_id);
    if (!proposal) return { proposal_id, state: "NOT_FOUND" };
    assert(proposal.state === "SUBMITTED", "Invalid callback state transition");

    // Terra Round 9 P1-1: Wrap ONLY near.promiseResult(0) in try/catch to isolate transfer outcome
    let transferSucceeded = false;
    try {
      near.promiseResult(0);
      transferSucceeded = true;
    } catch (e) {
      transferSucceeded = false;
    }

    if (transferSucceeded) {
      proposal.state = "SETTLED";
      this.proposals.set(proposal_id, proposal);
      return {
        proposal_id,
        state: "SETTLED",
        recipient: proposal.recipient,
        amount: proposal.amount
      };
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
      return {
        proposal_id,
        state: "FAILED",
        recipient: proposal.recipient,
        amount: proposal.amount
      };
    }
  }

  // --- Owner Rejection Function (Strict FSM Protected) ---
  @call({})
  owner_reject({ proposal_id, reason }) {
    assert(!this.is_paused, "SECURITY_ALERT: Vault is paused by emergency circuit breaker");
    const caller = near.predecessorAccountId();
    assert(caller === this.owner_id, "Only owner can reject proposals");

    assert(!reason || reason.length <= 256, "SECURITY_ALERT: Rejection reason exceeds 256 character limit");

    const proposal = this.proposals.get(proposal_id);
    assert(proposal !== null, "Proposal does not exist");

    assert(proposal.state === "AWAITING_OWNER_APPROVAL" || proposal.state === "PROPOSED", "Cannot reject settled or active transfer proposal");

    if (proposal.state === "AWAITING_OWNER_APPROVAL" && this.pending_count && this.pending_count > 0) {
      this.pending_count -= 1;
    }

    proposal.state = "REJECTED";
    proposal.memo = `${proposal.memo} [REJECTED: ${reason || "By owner"}]`;
    this.proposals.set(proposal_id, proposal);

    return { proposal_id, state: "REJECTED" };
  }

  // --- View Methods ---
  @view({})
  get_policy() {
    return {
      owner_id: this.owner_id,
      agent_id: this.agent_id,
      allowed_recipients: this.allowed_recipients,
      max_per_transfer: this.max_per_transfer.toString(),
      max_daily_total: this.max_daily_total.toString(),
      owner_approval_threshold: this.owner_approval_threshold.toString(),
      spent_today: this.spent_today.toString(),
      is_paused: this.is_paused,
      pending_count: this.pending_count,
      pending_timelock_update: this.pending_timelock_update || "",
      absolute_caps: {
        max_daily_limit: ABSOLUTE_MAX_DAILY_LIMIT.toString(),
        max_per_transfer: ABSOLUTE_MAX_PER_TRANSFER.toString()
      }
    };
  }

  @view({})
  get_proposal({ proposal_id }) {
    return this.proposals.get(proposal_id);
  }
}
