import { NearBindgen, call, view, initialize, near, UnorderedMap, assert } from 'near-sdk-js';

const DAY_IN_NANOSECONDS = BigInt(86400) * BigInt(1000000000);

class Proposal {
  constructor({ id, recipient, amount, memo, state, createdAt }) {
    this.id = id;
    this.recipient = recipient;
    this.amount = amount;
    this.memo = memo;
    this.state = state; // "PROPOSED", "APPROVED", "REJECTED", "SETTLED"
    this.createdAt = createdAt;
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

  // --- Agent Propose Function ---
  @call({})
  propose_payment({ recipient, amount, memo }) {
    const caller = near.predecessorAccountId();
    assert(caller === this.agent_id || caller === this.owner_id, "Caller is not authorized agent or owner");

    this._checkAndResetDailyAllowance();

    const amt = BigInt(amount);
    assert(amt > BigInt(0), "Amount must be strictly positive");

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
    let initialState = "APPROVED";
    if (amt > this.owner_approval_threshold) {
      initialState = "AWAITING_OWNER_APPROVAL";
    }

    const proposal = new Proposal({
      id: proposalId,
      recipient,
      amount: amt.toString(),
      memo: memo || "",
      state: initialState,
      createdAt: near.blockTimestamp().toString()
    });

    this.proposals.set(proposalId, proposal);

    // If auto-approved, execute immediate settlement
    if (initialState === "APPROVED") {
      this.spent_today += amt;
      const promiseId = near.promiseBatchCreate(recipient);
      near.promiseBatchActionTransfer(promiseId, amt);
      proposal.state = "SETTLED";
      this.proposals.set(proposalId, proposal);
    }

    return { proposal_id: proposalId, state: proposal.state };
  }

  // --- Owner Manual Approval Function ---
  @call({})
  owner_approve({ proposal_id }) {
    const caller = near.predecessorAccountId();
    assert(caller === this.owner_id, "Only owner can manually approve held proposals");

    const proposal = this.proposals.get(proposal_id);
    assert(proposal !== null, "Proposal does not exist");
    assert(proposal.state === "AWAITING_OWNER_APPROVAL", "Proposal is not awaiting approval");

    this._checkAndResetDailyAllowance();
    const amt = BigInt(proposal.amount);
    assert(this.spent_today + amt <= this.max_daily_total, "Daily budget would be exceeded");

    this.spent_today += amt;
    proposal.state = "SETTLED";
    this.proposals.set(proposal_id, proposal);

    // Execute on-chain transfer
    const promiseId = near.promiseBatchCreate(proposal.recipient);
    near.promiseBatchActionTransfer(promiseId, amt);
    return { proposal_id, state: "SETTLED", settled_amount: proposal.amount };
  }

  // --- Owner Rejection Function ---
  @call({})
  owner_reject({ proposal_id, reason }) {
    const caller = near.predecessorAccountId();
    assert(caller === this.owner_id, "Only owner can reject proposals");

    const proposal = this.proposals.get(proposal_id);
    assert(proposal !== null, "Proposal does not exist");

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
      spent_today: this.spent_today.toString()
    };
  }

  @view({})
  get_proposal({ proposal_id }) {
    return this.proposals.get(proposal_id);
  }
}
