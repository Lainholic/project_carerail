const fs = require('fs');
const path = require('path');
const { KeyPair, KeyPairSigner, Account, parseNearAmount, actions } = require('near-api-js');
const { FailoverJsonRpcProvider } = require('./rpc_provider');

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

// Load agent keys strictly from isolated environment credentials
const agentPrivKey = envVars.CARERAIL_AGENT_PRIVATE_KEY;
const agentPubKey = envVars.CARERAIL_AGENT_PUBLIC_KEY;

if (!accountId || !ownerPrivKey || !agentPrivKey || !agentPubKey) {
  console.error("Missing required environment credentials in .env");
  process.exit(1);
}

async function runSecurityAudit() {
  console.log("===============================================================================");
  console.log(" CareRail On-Chain Red-Team Security & Protocol Isolation Audit");
  console.log(" Target Vault Contract:", accountId);
  console.log(" Restricted Agent PubKey:", agentPubKey);
  console.log("===============================================================================\n");

  const provider = new FailoverJsonRpcProvider();

  // Setup accounts
  const ownerSigner = new KeyPairSigner(KeyPair.fromString(ownerPrivKey));
  const ownerAccount = new Account(accountId, provider, ownerSigner);

  const agentSigner = new KeyPairSigner(KeyPair.fromString(agentPrivKey));
  const agentAccount = new Account(accountId, provider, agentSigner);

  let passed = 0;
  let total = 0;

  // TEST 1: Protocol Isolation - Direct Transfer Attempt by Agent
  total++;
  console.log(`[TEST 1] Protocol Level Defense: Agent attempts direct on-chain Transfer to attacker`);
  try {
    const yocto = parseNearAmount("1.0");
    await agentAccount.signAndSendTransaction({
      receiverId: "attacker.testnet",
      actions: [actions.transfer(BigInt(yocto))]
    });
    console.error("  [FAIL] Malicious transfer was NOT blocked by NEAR protocol!");
  } catch (err) {
    const isExactProtocolBlock =
      err.message.includes("Not enough allowance") ||
      err.message.includes("ActionIsNotAllowed") ||
      err.message.includes("Transaction has a signature from a key with limited access") ||
      err.message.includes("InvalidAccessKeyError") ||
      err.message.includes("ReceiverMismatch");

    if (isExactProtocolBlock) {
      console.log(`  [PASS] Blocked by NEAR Protocol Layer!`);
      console.log(`  Reason: ${err.message.split('\n')[0]}`);
      passed++;
    } else {
      console.error(`  [FAIL] Unexpected or unhandled failure type: ${err.message}`);
    }
  }

  // TEST 2: Unauthorized Method Call by Agent
  total++;
  console.log(`\n[TEST 2] Protocol Level Defense: Agent attempts to call privileged owner_approve directly`);
  try {
    const gasLimit = BigInt("30000000000000");
    await agentAccount.signAndSendTransaction({
      receiverId: accountId,
      actions: [actions.functionCall('owner_approve', { proposal_id: 'prop-1' }, gasLimit, BigInt(0))]
    });
    console.error("  [FAIL] Privileged call was NOT blocked by NEAR protocol!");
  } catch (err) {
    const isExactMethodBlock =
      err.message.includes("Access key does not allow method") ||
      err.message.includes("MethodNameMismatch") ||
      err.message.includes("ActionIsNotAllowed");

    if (isExactMethodBlock) {
      console.log(`  [PASS] Blocked by NEAR Protocol Layer!`);
      console.log(`  Reason: ${err.message.split('\n')[0]}`);
      passed++;
    } else {
      console.error(`  [FAIL] Unexpected or unhandled failure type: ${err.message}`);
    }
  }

  // TEST 3: Smart Contract Policy Violation - Agent proposes payment to unwhitelisted target
  total++;
  console.log(`\n[TEST 3] Smart Contract Guardrail: Agent proposes payment to unwhitelisted 'attacker-stealth.testnet'`);
  try {
    const gasLimit = BigInt("30000000000000");
    const yocto = parseNearAmount("0.05");
    const result = await agentAccount.signAndSendTransaction({
      receiverId: accountId,
      actions: [actions.functionCall('propose_payment', {
        recipient: "attacker-stealth.testnet",
        amount: yocto,
        memo: "Prompt Injection Exfiltration"
      }, gasLimit, BigInt(0))]
    });

    if (result.status && result.status.Failure) {
      const failureStr = JSON.stringify(result.status.Failure);
      if (failureStr.includes("SECURITY_VIOLATION") || failureStr.includes("not whitelisted") || failureStr.includes("GuestPanic")) {
        console.log(`  [PASS] Blocked by Smart Contract Guardrail!`);
        console.log(`  Panic: ${failureStr}`);
        passed++;
      } else {
        console.error(`  [FAIL] Contract failed with unexpected reason: ${failureStr}`);
      }
    } else {
      console.error("  [FAIL] Payment to unwhitelisted recipient succeeded!");
    }
  } catch (err) {
    if (err.message.includes("SECURITY_VIOLATION") || err.message.includes("not whitelisted") || err.message.includes("GuestPanic")) {
      console.log(`  [PASS] Blocked by Smart Contract Guardrail!`);
      console.log(`  Panic: ${err.message.split('\n')[0]}`);
      passed++;
    } else {
      console.error(`  [FAIL] Unexpected error type: ${err.message}`);
    }
  }

  // TEST 4: Valid Proposal through Restricted Agent Key
  total++;
  console.log(`\n[TEST 4] Legitimate Operation: Agent proposes valid payment to whitelisted 'aws.testnet' (0.0015 NEAR)`);
  try {
    const gasLimit = BigInt("30000000000000");
    const yocto = parseNearAmount("0.0015");
    const result = await agentAccount.signAndSendTransaction({
      receiverId: accountId,
      actions: [actions.functionCall('propose_payment', {
        recipient: "aws.testnet",
        amount: yocto,
        memo: "Legitimate agent compute refill"
      }, gasLimit, BigInt(0))]
    });

    if (result.status && result.status.SuccessValue) {
      const decoded = JSON.parse(Buffer.from(result.status.SuccessValue, 'base64').toString());
      const txHash = result.transaction ? result.transaction.hash : (result.transaction_outcome ? result.transaction_outcome.id : "CONFIRMED");
      console.log(`  [PASS] Successfully proposed to Smart Contract (State: ${decoded.state})!`);
      console.log(`  Tx Hash: ${txHash}`);
      console.log(`  Explorer: https://testnet.nearblocks.io/txns/${txHash}`);
      passed++;
    } else {
      throw new Error(`Transaction returned unexpected status: ${JSON.stringify(result.status)}`);
    }
  } catch (err) {
    console.error(`  [FAIL] Legitimate proposal failed: ${err.message}`);
  }

  console.log("\n===============================================================================");
  console.log(` Red-Team Security Audit Results: ${passed}/${total} PASS`);
  console.log("===============================================================================");

  if (passed === total) {
    process.exit(0);
  } else {
    process.exit(1);
  }
}

runSecurityAudit();
