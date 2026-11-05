const fs = require('fs');
const path = require('path');
const { KeyPair, KeyPairSigner, JsonRpcProvider, Account, parseNearAmount, actions, PublicKey } = require('near-api-js');

// 1. Read .env file safely
const envPath = path.resolve(__dirname, '..', '.env');
if (!fs.existsSync(envPath)) {
  console.error(JSON.stringify({ success: false, error: ".env file not found" }));
  process.exit(1);
}

const envContent = fs.readFileSync(envPath, 'utf8');
const envVars = {};
envContent.split('\n').forEach(line => {
  const parts = line.split('=');
  if (parts.length >= 2) {
    envVars[parts[0].trim()] = parts.slice(1).join('=').trim();
  }
});

const accountId = envVars.CARERAIL_TESTNET_ACCOUNT_ID;
const privKey = envVars.CARERAIL_TESTNET_PRIVATE_KEY;

if (!accountId || !privKey) {
  console.error(JSON.stringify({ success: false, error: "Missing required credentials in .env" }));
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

async function main() {
  const [action, ...args] = process.argv.slice(2);
  const keyPair = KeyPair.fromString(privKey);
  const signer = new KeyPairSigner(keyPair);
  const provider = new JsonRpcProvider({ url: 'https://test.rpc.fastnear.com' });
  const account = new Account(accountId, provider, signer);

  try {
    if (action === 'get_policy') {
      const res = await viewCall(provider, accountId, 'get_policy', {});
      console.log(JSON.stringify({ success: true, policy: res }, null, 2));

    } else if (action === 'get_proposal') {
      const proposalId = args[0] || 'prop-1';
      const res = await viewCall(provider, accountId, 'get_proposal', { proposal_id: proposalId });
      console.log(JSON.stringify({ success: true, proposal: res }, null, 2));

    } else if (action === 'propose') {
      const recipient = args[0] || "uber.testnet";
      const amountNear = args[1] || "0.05";
      const memo = args[2] || "Automated agent payment";
      const yocto = parseNearAmount(amountNear);

      console.log(`[Contract] Calling propose_payment(${recipient}, ${amountNear} NEAR)...`);
      const gasLimit = BigInt("30000000000000"); // 30 Tgas
      const result = await account.signAndSendTransaction({
        receiverId: accountId,
        actions: [actions.functionCall('propose_payment', { recipient, amount: yocto, memo }, gasLimit, BigInt(0))]
      });

      const txHash = result.transaction ? result.transaction.hash : (result.transaction_outcome ? result.transaction_outcome.id : (result.final_execution_status || "CONFIRMED"));
      console.log(JSON.stringify({
        success: true,
        transaction_hash: txHash,
        explorer_url: `https://testnet.nearblocks.io/txns/${txHash}`,
        status: result.status || result.final_execution_status,
        recipient,
        amount_near: amountNear
      }, null, 2));

    } else if (action === 'owner_approve') {
      const proposalId = args[0] || 'prop-1';
      console.log(`[Contract] Calling owner_approve(${proposalId})...`);
      const gasLimit = BigInt("30000000000000");
      const result = await account.signAndSendTransaction({
        receiverId: accountId,
        actions: [actions.functionCall('owner_approve', { proposal_id: proposalId }, gasLimit, BigInt(0))]
      });

      const txHash = result.transaction ? result.transaction.hash : (result.transaction_outcome ? result.transaction_outcome.id : (result.final_execution_status || "CONFIRMED"));
      console.log(JSON.stringify({
        success: true,
        action: "owner_approve",
        proposal_id: proposalId,
        transaction_hash: txHash,
        explorer_url: `https://testnet.nearblocks.io/txns/${txHash}`
      }, null, 2));

    } else if (action === 'owner_reject') {
      const proposalId = args[0] || 'prop-1';
      const reason = args[1] || "Security policy violation";
      console.log(`[Contract] Calling owner_reject(${proposalId})...`);
      const gasLimit = BigInt("30000000000000");
      const result = await account.signAndSendTransaction({
        receiverId: accountId,
        actions: [actions.functionCall('owner_reject', { proposal_id: proposalId, reason }, gasLimit, BigInt(0))]
      });

      const txHash = result.transaction ? result.transaction.hash : (result.transaction_outcome ? result.transaction_outcome.id : (result.final_execution_status || "CONFIRMED"));
      console.log(JSON.stringify({
        success: true,
        action: "owner_reject",
        proposal_id: proposalId,
        reason,
        transaction_hash: txHash,
        explorer_url: `https://testnet.nearblocks.io/txns/${txHash}`
      }, null, 2));

    } else if (action === 'add_agent_key') {
      const agentPublicKey = args[0];
      if (!agentPublicKey) {
        throw new Error("Missing agentPublicKey argument");
      }
      console.log(`[Contract] Adding Function Call Access Key for ${agentPublicKey}...`);
      // Allowance of 0.25 NEAR for gas
      const allowance = BigInt(parseNearAmount("0.25"));
      const result = await account.signAndSendTransaction({
        receiverId: accountId,
        actions: [
          actions.addFunctionCallAccessKey(
            PublicKey.fromString(agentPublicKey),
            accountId,
            ['propose_payment'],
            allowance
          )
        ]
      });

      const txHash = result.transaction ? result.transaction.hash : (result.transaction_outcome ? result.transaction_outcome.id : (result.final_execution_status || "CONFIRMED"));
      console.log(JSON.stringify({
        success: true,
        action: "add_agent_key",
        agent_public_key: agentPublicKey,
        transaction_hash: txHash,
        explorer_url: `https://testnet.nearblocks.io/txns/${txHash}`
      }, null, 2));

    } else {
      console.log(`Usage: node interact_contract.js [get_policy|get_proposal <id>|propose <recipient> <amount>|owner_approve <id>|owner_reject <id> <reason>|add_agent_key <pubKey>]`);
    }

  } catch (err) {
    console.error(JSON.stringify({
      success: false,
      error: err.message,
      stack: err.stack
    }));
    process.exit(1);
  }
}

main();
