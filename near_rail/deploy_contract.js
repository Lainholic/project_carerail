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

async function deployAndInit() {
  try {
    const keyPair = KeyPair.fromString(privKey);
    const signer = new KeyPairSigner(keyPair);
    const provider = new JsonRpcProvider({ url: 'https://test.rpc.fastnear.com' });
    const account = new Account(accountId, provider, signer);

    const wasmPath = path.resolve(__dirname, '..', 'contract', 'build', 'policy_vault.wasm');
    if (!fs.existsSync(wasmPath)) {
      throw new Error(`WASM file not found at ${wasmPath}. Run npm run build first.`);
    }

    const wasmBinary = fs.readFileSync(wasmPath);
    console.log(`[Deploy] Read WASM file: ${wasmPath} (${wasmBinary.length} bytes)`);

    // 1. Deploy Contract
    console.log(`[Deploy] Deploying contract to ${accountId}...`);
    let deployResult;
    if (typeof account.deployContract === 'function') {
      deployResult = await account.deployContract(wasmBinary);
    } else {
      deployResult = await account.signAndSendTransaction({
        receiverId: accountId,
        actions: [actions.deployContract(wasmBinary)]
      });
    }

    const deployTxHash = deployResult.transaction ? deployResult.transaction.hash : (deployResult.transaction_outcome ? deployResult.transaction_outcome.id : (deployResult.final_execution_status || "CONFIRMED"));
    console.log(`[Deploy] Contract deployed. Tx: ${deployTxHash}`);

    // 2. Initialize PolicyVault Contract (Ignore if already initialized)
    console.log(`[Deploy] Initializing PolicyVault contract...`);
    const initArgs = {
      owner_id: accountId,
      agent_id: accountId,
      allowed_recipients: [
        "uber.testnet",
        "aws.testnet",
        "openai.testnet",
        "airline.testnet",
        "hotel.testnet"
      ],
      max_per_transfer: parseNearAmount("0.5"),
      max_daily_total: parseNearAmount("2.0"),
      owner_approval_threshold: parseNearAmount("0.1")
    };

    let initTxHash = "ALREADY_INITIALIZED";
    const gasLimit = BigInt("30000000000000"); // 30 Tgas
    try {
      let initResult;
      if (typeof account.functionCall === 'function') {
        initResult = await account.functionCall({
          contractId: accountId,
          methodName: 'init',
          args: initArgs,
          gas: gasLimit,
          attachedDeposit: BigInt(0)
        });
      } else {
        initResult = await account.signAndSendTransaction({
          receiverId: accountId,
          actions: [actions.functionCall('init', initArgs, gasLimit, BigInt(0))]
        });
      }
      initTxHash = initResult.transaction ? initResult.transaction.hash : (initResult.transaction_outcome ? initResult.transaction_outcome.id : (initResult.final_execution_status || "CONFIRMED"));
      console.log(`[Deploy] PolicyVault initialized. Tx: ${initTxHash}`);
    } catch (err) {
      if (err.message && err.message.includes("Contract already initialized")) {
        console.log(`[Deploy] Contract already initialized. Keeping existing on-chain policy.`);
      } else {
        throw err;
      }
    }

    console.log(JSON.stringify({
      success: true,
      status: "DEPLOYED_AND_INITIALIZED",
      account_id: accountId,
      deploy_tx: deployTxHash,
      init_tx: initTxHash,
      explorer_deploy_url: `https://testnet.nearblocks.io/txns/${deployTxHash}`,
      explorer_init_url: `https://testnet.nearblocks.io/txns/${initTxHash}`,
      policy: initArgs
    }, null, 2));

  } catch (err) {
    console.error(JSON.stringify({
      success: false,
      error: err.message,
      stack: err.stack
    }));
    process.exit(1);
  }
}

deployAndInit();
