const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { KeyPair, KeyPairSigner, JsonRpcProvider, Account, parseNearAmount, actions } = require('near-api-js');

// 1. Read .env file safely - Key Isolation Invariant
const envPath = path.resolve(__dirname, '..', '.env');
const envContent = fs.readFileSync(envPath, 'utf8');
const envVars = {};
envContent.split('\n').forEach(line => {
  const parts = line.split('=');
  if (parts.length >= 2) {
    envVars[parts[0].trim()] = parts.slice(1).join('=').trim();
  }
});

const accountId = envVars.CARERAIL_TESTNET_ACCOUNT_ID;
const ownerPrivKey = envVars.CARERAIL_TESTNET_PRIVATE_KEY;
const agentPrivKey = envVars.CARERAIL_AGENT_PRIVATE_KEY;

if (!accountId || !ownerPrivKey || !agentPrivKey) {
  console.error("Missing required environment credentials in .env");
  process.exit(1);
}

async function viewCall(provider, contractId, methodName, args = {}) {
  const rawResult = await provider.query({
    request_type: 'call_function',
    account_id: contractId,
    method_name: methodName,
    args_base64: Buffer.from(JSON.stringify(args)).toString('base64'),
    finality: 'optimistic'
  });
  return JSON.parse(Buffer.from(rawResult.result).toString());
}

async function runHumanInTheLoopTest() {
  console.log("===============================================================================");
  console.log(" CareRail On-Chain Human-in-the-Loop Threshold Verification");
  console.log(" Target Vault Contract:", accountId);
  console.log("===============================================================================\n");

  const provider = new JsonRpcProvider({ url: 'https://test.rpc.fastnear.com' });
  const ownerSigner = new KeyPairSigner(KeyPair.fromString(ownerPrivKey));
  const ownerAccount = new Account(accountId, provider, ownerSigner);

  const agentSigner = new KeyPairSigner(KeyPair.fromString(agentPrivKey));
  const agentAccount = new Account(accountId, provider, agentSigner);

  const gasLimit = BigInt("30000000000000");

  // 1. Agent proposes high-value payment (0.12 NEAR > 0.1 NEAR threshold)
  console.log("[Step 1] Agent proposes 0.12 NEAR to whitelisted 'hotel.testnet' (> 0.1 NEAR threshold)...");
  const yocto = parseNearAmount("0.12");
  
  const proposeResult = await agentAccount.signAndSendTransaction({
    receiverId: accountId,
    actions: [actions.functionCall('propose_payment', {
      recipient: "hotel.testnet",
      amount: yocto,
      memo: "Team hotel booking requiring human sign-off"
    }, gasLimit, BigInt(0))]
  });

  const proposeTxHash = proposeResult.transaction ? proposeResult.transaction.hash : (proposeResult.transaction_outcome ? proposeResult.transaction_outcome.id : "CONFIRMED");
  console.log(`  Proposed on-chain. Tx: ${proposeTxHash}`);

  let proposalId = null;
  if (proposeResult.status && proposeResult.status.SuccessValue) {
    const parsedReturn = JSON.parse(Buffer.from(proposeResult.status.SuccessValue, 'base64').toString());
    proposalId = parsedReturn.proposal_id;
    console.log(`  Proposal on-chain return value:`, parsedReturn);
    assert.strictEqual(parsedReturn.state, "AWAITING_OWNER_APPROVAL", "Proposal must be held in AWAITING_OWNER_APPROVAL state");
  } else if (proposeResult.status && proposeResult.status.Failure) {
    throw new Error(`Proposal execution failed on-chain: ${JSON.stringify(proposeResult.status.Failure)}`);
  }

  // 2. Query proposal state directly from contract storage (with retry for block indexing)
  let heldProposal = null;
  for (let attempt = 0; attempt < 5; attempt++) {
    heldProposal = await viewCall(provider, accountId, 'get_proposal', { proposal_id: proposalId });
    if (heldProposal) break;
    await new Promise(r => setTimeout(r, 1000));
  }
  assert.ok(heldProposal, `Proposal ${proposalId} not found in contract storage`);
  assert.strictEqual(heldProposal.state, "AWAITING_OWNER_APPROVAL", "Stored proposal state must be AWAITING_OWNER_APPROVAL");
  console.log(`  [PASS] Stored proposal ${heldProposal.id} is held in state: ${heldProposal.state}`);
  console.log(`  Details: ${heldProposal.amount} yoctoNEAR to ${heldProposal.recipient}`);

  // 3. Owner manually executes owner_approve with cryptographic attestation
  console.log(`\n[Step 2] Owner submits cryptographic approval & attestation for ${heldProposal.id}...`);
  const ownerKeyPair = KeyPair.fromString(ownerPrivKey);
  const ownerPubKey = ownerKeyPair.getPublicKey().toString();
  const challengeMsg = Buffer.from(`carerail:approval:${heldProposal.id}:${heldProposal.amount}:${heldProposal.recipient}`);
  const signedSig = ownerKeyPair.sign(challengeMsg);
  const sigB58 = Buffer.from(signedSig.signature).toString('base64');

  const approveResult = await ownerAccount.signAndSendTransaction({
    receiverId: accountId,
    actions: [actions.functionCall('owner_approve', {
      proposal_id: heldProposal.id,
      owner_public_key: ownerPubKey,
      signature_b58: sigB58
    }, gasLimit, BigInt(0))]
  });

  const approveTxHash = approveResult.transaction ? approveResult.transaction.hash : (approveResult.transaction_outcome ? approveResult.transaction_outcome.id : "CONFIRMED");
  console.log(`  Approved on-chain! Tx: ${approveTxHash}`);
  console.log(`  Explorer: https://testnet.nearblocks.io/txns/${approveTxHash}`);

  // 4. Verify post-approval state and on-chain attestation
  const updatedProposal = await viewCall(provider, accountId, 'get_proposal', { proposal_id: heldProposal.id });
  assert.ok(updatedProposal.state === "SUBMITTED" || updatedProposal.state === "SETTLED", `Unexpected post-approval state: ${updatedProposal.state}`);
  assert.ok(updatedProposal.attestation, "Cryptographic attestation must be permanently recorded on-chain");
  console.log(`  [PASS] Verified post-approval state: ${updatedProposal.state}`);
  console.log(`  [PASS] Verified on-chain attestation: ${updatedProposal.attestation}`);

  console.log("\n===============================================================================");
  console.log(" Human-in-the-Loop On-Chain Verification: PASS (Strict Invariants Enforced)");
  console.log("===============================================================================");
}

runHumanInTheLoopTest().catch(err => {
  console.error("Test failed:", err);
  process.exit(1);
});
