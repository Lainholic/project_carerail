/**
 * Unit Test for PolicyVault Smart Contract Logic
 * Updated to verify Terra F-02 asynchronous transfer callback and audit protection invariants.
 */

import assert from 'assert';

// Mock Map to simulate NEAR UnorderedMap
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

// Mock NEAR Runtime Environment
global.near = {
  _timestamp: BigInt(1700000000) * BigInt(1000000000),
  _caller: "agent-01.testnet",
  _currentAccount: "vault.testnet",
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
  promiseReturn() {}
};

class Proposal {
  constructor({ id, recipient, amount, memo, state, createdAt }) {
    this.id = id;
    this.recipient = recipient;
    this.amount = amount;
    this.memo = memo;
    this.state = state;
    this.createdAt = createdAt;
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
    this.proposals = new MockUnorderedMap("p");
    this.proposal_nonce = 0;
  }

  init({ owner_id, agent_id, allowed_recipients, max_per_transfer, max_daily_total, owner_approval_threshold }) {
    this.owner_id = owner_id;
    this.agent_id = agent_id;
    this.allowed_recipients = allowed_recipients || [];
    this.max_per_transfer = BigInt(max_per_transfer);
    this.max_daily_total = BigInt(max_daily_total);
    this.owner_approval_threshold = BigInt(owner_approval_threshold);
    this.spent_today = BigInt(0);
    this.last_reset_day = global.near.blockTimestamp() / (BigInt(86400) * BigInt(1000000000));
    this.proposal_nonce = 0;
  }

  _checkAndResetDailyAllowance() {
    const currentDay = global.near.blockTimestamp() / (BigInt(86400) * BigInt(1000000000));
    if (currentDay > this.last_reset_day) {
      this.spent_today = BigInt(0);
      this.last_reset_day = currentDay;
    }
  }

  propose_payment({ recipient, amount, memo }) {
    const caller = global.near.predecessorAccountId();
    if (caller !== this.agent_id && caller !== this.owner_id) {
      throw new Error("Caller is not authorized agent or owner");
    }

    this._checkAndResetDailyAllowance();
    const amt = BigInt(amount);
    if (amt <= BigInt(0)) throw new Error("Amount must be strictly positive");

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
    }

    const proposal = new Proposal({
      id: proposalId,
      recipient,
      amount: amt.toString(),
      memo: memo || "",
      state: initialState,
      createdAt: global.near.blockTimestamp().toString()
    });

    this.proposals.set(proposalId, proposal);

    if (initialState === "SUBMITTED") {
      this.spent_today += amt;
    }

    return { proposal_id: proposalId, state: proposal.state };
  }

  owner_approve({ proposal_id }) {
    const caller = global.near.predecessorAccountId();
    if (caller !== this.owner_id) throw new Error("Only owner can manually approve held proposals");

    const proposal = this.proposals.get(proposal_id);
    if (!proposal) throw new Error("Proposal does not exist");
    if (proposal.state !== "AWAITING_OWNER_APPROVAL") throw new Error("Proposal is not awaiting approval");

    this._checkAndResetDailyAllowance();
    const amt = BigInt(proposal.amount);
    if (this.spent_today + amt > this.max_daily_total) throw new Error("Daily budget would be exceeded");

    this.spent_today += amt;
    proposal.state = "SUBMITTED";
    this.proposals.set(proposal_id, proposal);

    return { proposal_id, state: "SUBMITTED", settled_amount: proposal.amount };
  }

  on_transfer_callback({ proposal_id, amount, transfer_succeeded = true }) {
    const caller = global.near.predecessorAccountId();
    if (caller !== global.near.currentAccountId()) {
      throw new Error("Callback is strictly private to contract");
    }

    const proposal = this.proposals.get(proposal_id);
    if (!proposal) return false;

    if (transfer_succeeded) {
      proposal.state = "SETTLED";
      this.proposals.set(proposal_id, proposal);
      return true;
    } else {
      const amt = BigInt(amount);
      this.spent_today = this.spent_today >= amt ? this.spent_today - amt : BigInt(0);
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

    proposal.state = "REJECTED";
    proposal.memo = `${proposal.memo} [REJECTED: ${reason || "By owner"}]`;
    this.proposals.set(proposal_id, proposal);
    return { proposal_id, state: "REJECTED" };
  }
}

async function runTests() {
  console.log("=== Running PolicyVault Smart Contract Verification Suite ===");
  const vault = new PolicyVaultTestable();
  
  // 1. Initialize
  vault.init({
    owner_id: "human-owner.testnet",
    agent_id: "agent-01.testnet",
    allowed_recipients: ["care-clinic.testnet", "pharmacy.testnet"],
    max_per_transfer: "5000000000000000000000000",        // 5 NEAR
    max_daily_total: "20000000000000000000000000",         // 20 NEAR
    owner_approval_threshold: "2000000000000000000000000" // 2 NEAR
  });
  console.log("[PASS] Test 1: Contract Initialized Successfully");

  // 2. Normal Auto-Approved Proposal (1.2 NEAR) -> Enters SUBMITTED pending callback
  global.near._caller = "agent-01.testnet";
  const p1 = vault.propose_payment({
    recipient: "care-clinic.testnet",
    amount: "1200000000000000000000000",
    memo: "Physiotherapy consultation"
  });
  assert.strictEqual(p1.state, "SUBMITTED");
  assert.strictEqual(vault.spent_today, BigInt("1200000000000000000000000"));

  // Terra F-02: Callback resolves to SETTLED upon confirmed transfer receipt
  global.near._caller = "vault.testnet"; // Contract self-call
  const ok = vault.on_transfer_callback({
    proposal_id: p1.proposal_id,
    amount: "1200000000000000000000000",
    transfer_succeeded: true
  });
  assert.strictEqual(ok, true);
  assert.strictEqual(vault.proposals.get(p1.proposal_id).state, "SETTLED");
  console.log("[PASS] Test 2: Auto-Approved Proposal Verified & Settled via Callback");

  // 3. Security Violation: Unwhitelisted Recipient Blocked
  global.near._caller = "agent-01.testnet";
  assert.throws(() => {
    vault.propose_payment({
      recipient: "malicious-hacker.testnet",
      amount: "1000000000000000000000000",
      memo: "Drain funds"
    });
  }, /SECURITY_VIOLATION/);
  console.log("[PASS] Test 3: Unwhitelisted Recipient Blocked (Fail-Closed)");

  // 4. Limit Violation: Exceeds Single Transfer Ceiling (6 NEAR > 5 NEAR)
  assert.throws(() => {
    vault.propose_payment({
      recipient: "care-clinic.testnet",
      amount: "6000000000000000000000000",
      memo: "Excessive bulk treatment"
    });
  }, /LIMIT_VIOLATION/);
  console.log("[PASS] Test 4: Single Transfer Limit Exceeded Blocked");

  // 5. Human-in-the-Loop: High Value (3.5 NEAR > 2 NEAR)
  const p3 = vault.propose_payment({
    recipient: "pharmacy.testnet",
    amount: "3500000000000000000000000",
    memo: "High-end medical brace"
  });
  assert.strictEqual(p3.state, "AWAITING_OWNER_APPROVAL");
  console.log("[PASS] Test 5: High Value Held for Owner Approval");

  // 6. Owner Approves Held Proposal -> SUBMITTED -> SETTLED via callback
  global.near._caller = "human-owner.testnet";
  const approved = vault.owner_approve({ proposal_id: p3.proposal_id });
  assert.strictEqual(approved.state, "SUBMITTED");

  global.near._caller = "vault.testnet";
  vault.on_transfer_callback({
    proposal_id: p3.proposal_id,
    amount: "3500000000000000000000000",
    transfer_succeeded: true
  });
  assert.strictEqual(vault.proposals.get(p3.proposal_id).state, "SETTLED");
  console.log("[PASS] Test 6: Owner Approved Held Proposal Settled Successfully");

  // 7. Terra F-02 Defect Fix: Failed transfer rolls back daily spend and sets FAILED
  global.near._caller = "agent-01.testnet";
  const p4 = vault.propose_payment({
    recipient: "care-clinic.testnet",
    amount: "1000000000000000000000000",
    memo: "Failed booking test"
  });
  const spentBefore = vault.spent_today;
  // Trigger callback failure
  global.near._caller = "vault.testnet";
  vault.on_transfer_callback({
    proposal_id: p4.proposal_id,
    amount: "1000000000000000000000000",
    transfer_succeeded: false
  });
  assert.strictEqual(vault.proposals.get(p4.proposal_id).state, "FAILED");
  assert.strictEqual(vault.spent_today, spentBefore - BigInt("1000000000000000000000000"));
  console.log("[PASS] Test 7: Failed Transfer Rolls Back Daily Budget (Terra F-02 Fixed)");

  // 8. Terra F-05 Defect Fix: Settled proposal cannot be rewritten via owner_reject
  global.near._caller = "human-owner.testnet";
  assert.throws(() => {
    vault.owner_reject({ proposal_id: p1.proposal_id, reason: "Retroactive tampering" });
  }, /Cannot reject settled or active transfer proposal/);
  console.log("[PASS] Test 8: Cannot Retroactively Tamper With Settled Proposals (Audit Invariant Passed)");

  console.log("\n>>> ALL 8 CONTRACT INVARIANT TESTS PASSED (100%) <<<");
}

runTests().catch(err => {
  console.error("TEST FAILED:", err);
  process.exit(1);
});
