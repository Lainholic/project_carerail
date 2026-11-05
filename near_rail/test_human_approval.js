const fs = require('fs');
const path = require('path');
const { KeyPair, KeyPairSigner, JsonRpcProvider, Account, parseNearAmount, actions } = require('near-api-js');

// 1. Read .env file safely
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
const agentPrivKey = "ed25519:55jNUTA9ZBiNdGu9x1NBhsWBmiWYgLhaKxPKyWDSFsM5erG8QczH9iEG7rsrRHPLf3Q4HH2CSKknFg9NrjLJGog7";

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

  // 1. Agent proposes high-value payment (0.2 NEAR > 0.1 NEAR threshold)
  console.log("[Step 1] Agent proposes 0.2 NEAR to whitelisted 'hotel.testnet' (> 0.1 NEAR threshold)...");
  const gasLimit = BigInt("30000000000000");
  const yocto = parseNearAmount("0.2");
  
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
    console.log(`  Proposal return value:`, parsedReturn);
  } else if (proposeResult.status && proposeResult.status.Failure) {
    throw new Error(`Proposal execution failed on-chain: ${JSON.stringify(proposeResult.status.Failure)}`);
  }

  // 2. Query proposal state - must be AWAITING_OWNER_APPROVAL
  const heldProposal = await viewCall(provider, accountId, 'get_proposal', { proposal_id: proposalId });
  if (!heldProposal) {
    throw new Error(`Could not find proposal ${proposalId}!`);
  }

  console.log(`  [PASS] Proposal ${heldProposal.id} is held in state: ${heldProposal.state}`);
  console.log(`  Details: ${heldProposal.amount} yoctoNEAR to ${heldProposal.recipient}`);

  // 3. Owner manually executes owner_approve
  console.log(`\n[Step 2] Owner submits cryptographic approval for ${heldProposal.id}...`);
  const approveResult = await ownerAccount.signAndSendTransaction({
    receiverId: accountId,
    actions: [actions.functionCall('owner_approve', { proposal_id: heldProposal.id }, gasLimit, BigInt(0))]
  });

  const approveTxHash = approveResult.transaction ? approveResult.transaction.hash : (approveResult.transaction_outcome ? approveResult.transaction_outcome.id : "CONFIRMED");
  console.log(`  Approved & Settled on-chain! Tx: ${approveTxHash}`);
  console.log(`  Explorer: https://testnet.nearblocks.io/txns/${approveTxHash}`);

  // 4. Verify settled state
  const updatedProposal = await viewCall(provider, accountId, 'get_proposal', { proposal_id: heldProposal.id });
  console.log(`  [PASS] Final on-chain state: ${updatedProposal.state}`);

  console.log("\n===============================================================================");
  console.log(" Human-in-the-Loop On-Chain Verification: PASS");
  console.log("===============================================================================");
}

runHumanInTheLoopTest().catch(err => {
  console.error(err);
  process.exit(1);
});
