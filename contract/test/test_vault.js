/**
 * Unit Test for PolicyVault Smart Contract Logic
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

// Global near mock
global.near = {
  _timestamp: BigInt(1730811600) * BigInt(1000000000), // Fixed timestamp
  _caller: "agent-01.testnet",
  blockTimestamp() {
    return this._timestamp;
  },
  predecessorAccountId() {
    return this._caller;
  },
  promiseBatchCreate(recipient) {
    return 1;
  },
  promiseBatchActionTransfer(promiseId, amount) {
    return 2;
  }
};

const DAY_IN_NANOSECONDS = BigInt(86400) * BigInt(1000000000);

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
    if (!owner_id || !agent_id) throw new Error("Owner and Agent IDs required");
    this.owner_id = owner_id;
    this.agent_id = agent_id;
    this.allowed_recipients = allowed_recipients || [];
    this.max_per_transfer = BigInt(max_per_transfer);
    this.max_daily_total = BigInt(max_daily_total);
    this.owner_approval_threshold = BigInt(owner_approval_threshold);
    this.spent_today = BigInt(0);
    this.last_reset_day = global.near.blockTimestamp() / DAY_IN_NANOSECONDS;
    this.proposal_nonce = 0;
  }

  _checkAndResetDailyAllowance() {
    const currentDay = global.near.blockTimestamp() / DAY_IN_NANOSECONDS;
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
      throw new Error("LIMIT_VIOLATION: Amount exceeds per-transfer ceiling");
    }

    if (this.spent_today + amt > this.max_daily_total) {
      throw new Error("LIMIT_VIOLATION: Amount exceeds remaining daily budget");
    }

    this.proposal_nonce += 1;
    const proposalId = `prop-${this.proposal_nonce}`;

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
      createdAt: global.near.blockTimestamp().toString()
    });

    this.proposals.set(proposalId, proposal);

    if (initialState === "APPROVED") {
      this.spent_today += amt;
      proposal.state = "SETTLED";
      this.proposals.set(proposalId, proposal);
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
    proposal.state = "SETTLED";
    this.proposals.set(proposal_id, proposal);

    return { proposal_id, state: "SETTLED", settled_amount: proposal.amount };
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
    max_per_transfer: "5000000000000000000000000", // 5 NEAR in yocto
    max_daily_total: "20000000000000000000000000", // 20 NEAR in yocto
    owner_approval_threshold: "2000000000000000000000000" // 2 NEAR in yocto
  });
  console.log("[PASS] Test 1: Contract Initialized Successfully");

  // 2. Normal Auto-Approved Proposal (1.2 NEAR)
  global.near._caller = "agent-01.testnet";
  const p1 = vault.propose_payment({
    recipient: "care-clinic.testnet",
    amount: "1200000000000000000000000",
    memo: "Physiotherapy consultation"
  });
  assert.strictEqual(p1.state, "SETTLED");
  assert.strictEqual(vault.spent_today, BigInt("1200000000000000000000000"));
  console.log("[PASS] Test 2: Auto-Approved Proposal Settled Immediately");

  // 3. Security Violation: Unwhitelisted Recipient Blocked
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

  // 6. Owner Approves Held Proposal
  global.near._caller = "human-owner.testnet";
  const approved = vault.owner_approve({ proposal_id: p3.proposal_id });
  assert.strictEqual(approved.state, "SETTLED");
  console.log("[PASS] Test 6: Owner Approved Held Proposal Successfully");

  console.log("\n>>> ALL 6 CONTRACT INVARIANT TESTS PASSED (100%) <<<");
}

runTests().catch(err => {
  console.error("TEST FAILED:", err);
  process.exit(1);
});
