const fs = require('fs');
const path = require('path');
const { KeyPair, KeyPairSigner, JsonRpcProvider, Account, parseNearAmount, actions } = require('near-api-js');

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

async function sendTransfer(recipient, amountNear) {
  try {
    const keyPair = KeyPair.fromString(privKey);
    const signer = new KeyPairSigner(keyPair);
    const provider = new JsonRpcProvider({ url: 'https://rpc.testnet.near.org' });

    const account = new Account(accountId, provider, signer);

    // Convert NEAR to yoctoNEAR
    const yoctoAmount = parseNearAmount(amountNear.toString());

    // Execute live on-chain transfer
    let result;
    if (typeof account.sendMoney === 'function') {
      result = await account.sendMoney(recipient, yoctoAmount);
    } else {
      result = await account.signAndSendTransaction({
        receiverId: recipient,
        actions: [actions.transfer(yoctoAmount)]
      });
    }

    const txHash = result.transaction ? result.transaction.hash : (result.transaction_outcome ? result.transaction_outcome.id : (result.final_execution_status || "CONFIRMED"));

    console.log(JSON.stringify({
      success: true,
      status: "CONFIRMED",
      transaction_hash: txHash,
      explorer_url: `https://testnet.nearblocks.io/txns/${txHash}`,
      amount_near: amountNear,
      recipient: recipient,
      sender: accountId
    }));
  } catch (err) {
    console.error(JSON.stringify({
      success: false,
      error: err.message
    }));
    process.exit(1);
  }
}

// Command line args: recipient, amount
const args = process.argv.slice(2);
const targetRecipient = args[0] || "testnet";
const targetAmount = parseFloat(args[1]) || 0.05;

sendTransfer(targetRecipient, targetAmount);
