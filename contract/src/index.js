import { NearBindgen, call, view, initialize, near, UnorderedMap, assert } from 'near-sdk-js';

const DAY_IN_NANOSECONDS = BigInt(86400) * BigInt(1000000000);
const MIN_TRANSFER_FLOOR = BigInt("1000000000000000000000"); // 0.001 NEAR (Anti-Dust Spam Floor)
const MAX_PENDING_PROPOSALS = 50;

class Proposal {
  constructor({ id, recipient, amount, memo, state, createdAt, submittedDay }) {
    this.id = id;
    this.recipient = recipient;
    this.amount = amount;
    this.memo = memo;
    this.state = state; // "PROPOSED", "AWAITING_OWNER_APPROVAL", "SUBMITTED", "SETTLED", "REJECTED", "FAILED"
    this.createdAt = createdAt;
    this.submittedDay = submittedDay; // Immutable day index for precise rollback accounting
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
    this.proposals = new UnorderedMap("p");
    this.proposal_nonce = 0;
  }

  @initialize({})
  init({ owner_id, agent_id, allowed_recipients, max_per_transfer, max_daily_total, owner_approval_threshold }) {
    assert(owner_id.length > 0, "Owner ID cannot be empty");
    assert(agent_id.length > 0, "Agent ID cannot be empty");

    this.owner_id = owner_id;
    this.agent_id = agent_id;
    this.allowed_recipients = allowed_recipients || [];
    this.max_per_transfer = BigInt(max_per_transfer);
    this.max_daily_total = BigInt(max_daily_total);
    this.owner_approval_threshold = BigInt(owner_approval_threshold);
    this.spent_today = BigInt(0);
    this.last_reset_day = near.blockTimestamp() / DAY_IN_NANOSECONDS;
    this.is_paused = false;
    this.pending_count = 0;
    this.proposal_nonce = 0;
  }

  // --- Internal Guardrail Helper ---
  _checkAndResetDailyAllowance() {
    const currentDay = near.blockTimestamp() / DAY_IN_NANOSECONDS;
    if (currentDay > this.last_reset_day) {
      this.spent_today = BigInt(0);
      this.last_reset_day = currentDay;
    }
  }

  // --- Emergency Circuit Breaker (P1 Feature) ---
  @call({})
  set_emergency_pause({ paused }) {
    const caller = near.predecessorAccountId();
    assert(caller === this.owner_id, "Only owner can toggle emergency pause");
    this.is_paused = !!paused;
    return { is_paused: this.is_paused };
  }

  // --- Owner Maintenance: Reset Daily Spent (Owner Only) ---
  @call({})
  owner_reset_daily_spent() {
    const caller = near.predecessorAccountId();
    assert(caller === this.owner_id, "Only owner can reset daily spent");
    this.spent_today = BigInt(0);
    return { spent_today: this.spent_today.toString() };
  }

  // --- Agent Propose Function ---
  @call({})
  propose_payment({ recipient, amount, memo }) {
    assert(!this.is_paused, "SECURITY_ALERT: Vault is paused by emergency circuit breaker");

    const caller = near.predecessorAccountId();
    assert(caller === this.agent_id || caller === this.owner_id, "Caller is not authorized agent or owner");

    this._checkAndResetDailyAllowance();

    // Input sanitization: ensure valid positive BigInt
    assert(typeof recipient === 'string' && recipient.length > 0, "Invalid recipient");
    const amt = BigInt(amount);
    assert(amt > BigInt(0), "Amount must be strictly positive");

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
      submittedDay: this.last_reset_day.toString()
    });

    this.proposals.set(proposalId, proposal);

    // If auto-approved (under threshold), initiate transfer promise with verified completion callback
    if (initialState === "SUBMITTED") {
      this.spent_today += amt;
      const promiseId = near.promiseBatchCreate(recipient);
      near.promiseBatchActionTransfer(promiseId, amt);

      // Terra F-02 fix: Asynchronous execution callback verifies real on-chain receipt before SETTLED
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

  // --- Owner Manual Approval Function ---
  @call({})
  owner_approve({ proposal_id }) {
    assert(!this.is_paused, "SECURITY_ALERT: Vault is paused by emergency circuit breaker");

    const caller = near.predecessorAccountId();
    assert(caller === this.owner_id, "Only owner can manually approve held proposals");

    const proposal = this.proposals.get(proposal_id);
    assert(proposal !== null, "Proposal does not exist");
    assert(proposal.state === "AWAITING_OWNER_APPROVAL", "Proposal is not awaiting approval");

    this._checkAndResetDailyAllowance();
    const amt = BigInt(proposal.amount);
    assert(this.spent_today + amt <= this.max_daily_total, "Daily budget would be exceeded");

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

    return { proposal_id, state: "SUBMITTED", settled_amount: proposal.amount };
  }

  // --- Private Asynchronous Transfer Callback (P0 Protected) ---
  @call({})
  on_transfer_callback({ proposal_id, amount }) {
    // Strictly isolate callback to contract self-calls (Blocks external caller hijacking)
    assert(near.predecessorAccountId() === near.currentAccountId(), "Callback is strictly private to contract");

    const proposal = this.proposals.get(proposal_id);
    if (!proposal) return false;
    assert(proposal.state === "SUBMITTED", "Invalid callback state transition");

    // Verify whether the attached cross-account transfer receipt succeeded
    try {
      near.promiseResult(0);
      proposal.state = "SETTLED";
      this.proposals.set(proposal_id, proposal);
      return true;
    } catch (e) {
      // Transfer failed on-chain! Rollback spent_today ONLY if failure happened on same accounting day
      const amt = BigInt(amount);
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

  // --- Owner Rejection Function (Strict FSM Protected) ---
  @call({})
  owner_reject({ proposal_id, reason }) {
    const caller = near.predecessorAccountId();
    assert(caller === this.owner_id, "Only owner can reject proposals");

    const proposal = this.proposals.get(proposal_id);
    assert(proposal !== null, "Proposal does not exist");

    // Strict FSM: Only pending proposals can be rejected. Settled/Submitted/Failed are immutable.
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
      pending_count: this.pending_count
    };
  }

  @view({})
  get_proposal({ proposal_id }) {
    return this.proposals.get(proposal_id);
  }
}
