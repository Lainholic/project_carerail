# Reasoning Trace
The user wants production-grade code for two tasks. Let me carefully design this.

Key constraints:
- near-sdk-js 2.0.0, QuickJS WASM environment
- No strikethrough
- No premature praise
- Real working code

Let me think about the architecture:

**Task 1: Engine Attestation**

The attestation needs to be verifiable on-chain. Since near-sdk-js 2.0.0 runs in QuickJS, we have `near.sha256` available. We don't have HMAC-SHA256 natively, but we can construct a hash chain: `sha256(engine_secret || proposal_id || recipient || amount || nonce || expires_at)`.

Wait, but the engine_secret needs to be on-chain too (as `engine_attestation_key`). So the contract stores the shared secret, and the engine uses the same secret to compute the hash. This is essentially a keyed hash (not HMAC but a simple construction). For production we'd want HMAC, but in QuickJS we can implement HMAC-SHA256 manually using near.sha256 as the hash primitive.

Actually, let me implement HMAC-SHA256 properly in JS using near.sha256. HMAC construction:
- K' = key padded to block size (64 bytes for SHA-256)
- ipad = K' XOR 0x36 repeated
- opad = K' XOR 0x5c repeated
- HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))

We can do this with near.sha256. But we need byte manipulation. near-sdk-js has Uint8Array support.

Actually, let me think about whether HMAC is necessary. The task says "HMAC-SHA256 방식 또는 sha256 해시 체인". So either is acceptable. Let me implement HMAC-SHA256 properly for security.

But wait - the attestation is passed as a string. We need to parse it. Let me use a JSON-like format or a delimited format. Since QuickJS has JSON.parse, we can use JSON.

Actually, let me use a compact format: `engine_id|proposal_id|recipient|amount|nonce|expires_at|sig_hash`. Or JSON. JSON is cleaner.

Let me design:

```js
// Attestation format (JSON string):
// {"engine_id":"...","proposal_id":"...","recipient":"...","amount":"...","nonce":123,"expires_at":1234567890,"sig_hash":"hex"}
```

On-chain verification:
1. Parse JSON
2. Check expires_at > near.blockTimestamp
3. Check proposal_id, recipient, amount match the actual call args
4. Recompute HMAC-SHA256 over the canonical payload using engine_attestation_key
5. Compare with sig_hash (constant-time comparison ideally)

For the Python side, use `hmac` module with sha256.

Let me write the HMAC in JS:

```js
function hmacSha256(keyBytes, messageBytes) {
  const blockSize = 64;
  let key = keyBytes;
  if (key.length > blockSize) {
    key = near.sha256(key);
  }
  const paddedKey = new Uint8Array(blockSize);
  paddedKey.set(key);
  
  const ipad = new Uint8Array(blockSize);
  const opad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    ipad[i] = paddedKey[i] ^ 0x36;
    opad[i] = paddedKey[i] ^ 0x5c;
  }
  
  const innerInput = new Uint8Array(blockSize + messageBytes.length);
  innerInput.set(ipad, 0);
  innerInput.set(messageBytes, blockSize);
  const innerHash = near.sha256(innerInput);
  
  const outerInput = new Uint8Array(blockSize + innerHash.length);
  outerInput.set(opad, 0);
  outerInput.set(innerHash, blockSize);
  return near.sha256(outerInput);
}
```

Wait, does near.sha256 accept Uint8Array? In near-sdk-js 2.0.0, `near.sha256(value)` accepts Uint8Array or string. Let me check... Actually in near-sdk-js, `near.sha256` takes a Uint8Array and returns Uint8Array. Let me verify.

Looking at near-sdk-js source: `near.sha256(value: Uint8Array): Uint8Array`. Yes, it takes Uint8Array.

For string to bytes, we need to encode. near-sdk-js has `near.stringify` and there's `Buffer` polyfill? Actually in QuickJS environment, we have TextEncoder? Hmm, not sure. Let me use a manual UTF-8 encoder or use the fact that near-sdk-js provides some utilities.

Actually, near-sdk-js provides `near.sha256` which internally uses the host function `sha256`. The input needs to be Uint8Array. For string conversion, we can use `new TextEncoder().encode(str)` if TextEncoder is available in QuickJS. In near-sdk-js 2.0.0, I believe TextEncoder is polyfilled or available.

Actually, looking at near-sdk-js, they have `util.ts` with `encode` function. Let me just use a simple approach - near-sdk-js has `near.sha256` and we can pass strings? Let me check the actual signature.

From near-sdk-js 2.0.0:
```typescript
export function sha256(value: Uint8Array): Uint8Array {
    return env.sha256(value);
}
```

So it takes Uint8Array. For string encoding, we need to convert. near-sdk-js has `near.stringify` for JSON. For UTF-8 encoding, we can use `new TextEncoder().encode(str)` - TextEncoder should be available in QuickJS.

Actually, let me be safe and write a manual UTF-8 encoder, or use the fact that near-sdk-js provides `base58` and other utilities. Hmm.

Actually, in near-sdk-js 2.0.0, there's `near.sha256` and the SDK provides `Buffer` from `buffer` package. Let me check... near-sdk-js uses `@noble/hashes` internally? No.

Let me just use TextEncoder. In QuickJS WASM environment provided by near-sdk-js, TextEncoder is available (it's part of the polyfill). Actually, I recall near-sdk-js includes `TextEncoder` and `TextDecoder` polyfills.

Hmm, to be safe, let me write a small UTF-8 encoder:

```js
function utf8Encode(str) {
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    let code = str.charCodeAt(i);
    if (code < 0x80) {
      bytes.push(code);
    } else if (code < 0x800) {
      bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code < 0xd800 || code >= 0xe000) {
      bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      i++;
      const next = str.charCodeAt(i);
      const cp = 0x10000 + (((code & 0x3ff) << 10) | (next & 0x3ff));
      bytes.push(
        0xf0 | (cp >> 18),
        0x80 | ((cp >> 12) & 0x3f),
        0x80 | ((cp >> 6) & 0x3f),
        0x80 | (cp & 0x3f)
      );
    }
  }
  return new Uint8Array(bytes);
}
```

OK that's safe.

For hex encoding/decoding:
```js
function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}
```

Constant-time comparison:
```js
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
```

Now for the contract structure. Let me look at what a typical PolicyVault contract looks like. The user mentioned `propose_payment`, `initialize`, `set_attestation_key`, `unconfirmed_reservation`, `UNKNOWN/PENDING_RECONCILIATION`.

Let me design the contract:

```js
import { NearBindgen, near, call, view, initialize, assert, LookupMap, UnorderedMap } from 'near-sdk-js';

@NearBindgen({})
class PolicyVault {
  constructor() {
    this.owner = '';
    this.engine_attestation_key = '';
    this.agents = new LookupMap('agents');
    this.policies = new LookupMap('policies');
    this.proposals = new LookupMap('proposals');
    this.nonces = new LookupMap('nonces');
    this.reservations = new LookupMap('reservations');
    this.proposal_counter = 0;
  }

  @initialize({})
  init({ owner, engine_attestation_key }) {
    this.owner = owner;
    this.engine_attestation_key = engine_attestation_key;
  }

  @call({})
  set_attestation_key({ new_key }) {
    assert(near.predecessorAccountId() === this.owner, 'ONLY_OWNER');
    this.engine_attestation_key = new_key;
  }

  @call({})
  propose_payment({ proposal_id, recipient, amount, attestation }) {
    // ... verify attestation
  }
}
```

Wait, but the user says "initialize 시 engine_attestation_key 등록". So the initialize function should take it.

Let me think about the attestation verification flow more carefully.

The attestation is created by the off-chain engine. It contains:
- engine_id
- proposal_id
- recipient
- amount
- nonce
- expires_at
- sig_hash

The sig_hash is HMAC-SHA256(engine_secret, canonical_payload) where canonical_payload is a deterministic serialization of the other fields.

On-chain:
1. Parse attestation JSON
2. Check expires_at > near.blockTimestamp (in nanoseconds)
3. Check proposal_id, recipient, amount match the call args
4. Recompute HMAC and compare

For canonical payload, we need a deterministic format. Let me use:
`engine_id|proposal_id|recipient|amount|nonce|expires_at`

Where amount is a string (to avoid float issues).

Now, the nonce. The user mentions nonce in the attestation. We should also track nonces on-chain to prevent replay. Let me add a nonce registry per engine_id or globally.

Actually, the task says "동시성 공격: 10개 스레드가 동일한 논스나 예산 초과 결제를 동시 폭격할 때 SQLite BEGIN IMMEDIATE 원자성에 의해 정확히 1개만 성공하고 9개는 거절되는지 검증." - this is about the off-chain SQLite, not on-chain nonce. But we should still track nonces on-chain to prevent replay.

Let me add nonce tracking:
```js
this.used_nonces = new LookupMap('used_nonces');
```

And check `assert(!this.used_nonces.get(nonce), 'NONCE_REPLAY')`.

Now for the Python engine side. Let me design `policy/engine.py`:

```python
import hmac
import hashlib
import json
import time
import secrets

class AttestationEngine:
    def __init__(self, engine_id, shared_secret):
        self.engine_id = engine_id
        self.shared_secret = shared_secret.encode() if isinstance(shared_secret, str) else shared_secret

    def _canonical_payload(self, proposal_id, recipient, amount, nonce, expires_at):
        return f"{self.engine_id}|{proposal_id}|{recipient}|{amount}|{nonce}|{expires_at}".encode()

    def create_attestation(self, proposal_id, recipient, amount, ttl_ns=60_000_000_000):
        nonce = secrets.randbits(63)
        expires_at = time.time_ns() + ttl_ns
        payload = self._canonical_payload(proposal_id, recipient, amount, nonce, expires_at)
        sig = hmac.new(self.shared_secret, payload, hashlib.sha256).hexdigest()
        return {
            "engine_id": self.engine_id,
            "proposal_id": proposal_id,
            "recipient": recipient,
            "amount": str(amount),
            "nonce": nonce,
            "expires_at": expires_at,
            "sig_hash": sig,
        }

    def serialize(self, attestation):
        return json.dumps(attestation, separators=(',', ':'), sort_keys=True)
```

Wait, but the on-chain HMAC needs to match. The canonical payload format must be identical. Let me be careful about the amount format - it should be a string on both sides.

Also, the expires_at is in nanoseconds (near.blockTimestamp is in nanoseconds). Python's time.time_ns() gives nanoseconds. Good.

Now for the on-chain HMAC verification:

```js
function verifyAttestation(attestationStr, expectedProposalId, expectedRecipient, expectedAmount, engineKey, blockTimestamp) {
  let att;
  try {
    att = JSON.parse(attestationStr);
  } catch (e) {
    assert(false, 'INVALID_ENGINE_ATTESTATION');
  }
  
  assert(att.engine_id && att.proposal_id && att.recipient && att.amount && att.nonce !== undefined && att.expires_at && att.sig_hash, 'INVALID_ENGINE_ATTESTATION');
  assert(att.proposal_id === expectedProposalId, 'INVALID_ENGINE_ATTESTATION');
  assert(att.recipient === expectedRecipient, 'INVALID_ENGINE_ATTESTATION');
  assert(att.amount === expectedAmount, 'INVALID_ENGINE_ATTESTATION');
  assert(BigInt(att.expires_at) > BigInt(blockTimestamp), 'INVALID_ENGINE_ATTESTATION');
  
  const canonical = `${att.engine_id}|${att.proposal_id}|${att.recipient}|${att.amount}|${att.nonce}|${att.expires_at}`;
  const expectedSig = hmacSha256Hex(engineKey, canonical);
  assert(constantTimeEqual(expectedSig, att.sig_hash), 'INVALID_ENGINE_ATTESTATION');
  
  return att;
}
```

Hmm, but there's a subtlety with JSON parsing in QuickJS. JSON.parse should work fine.

Also, the amount comparison - if the caller passes amount as a string, we compare strings. If as a number, we need to convert. Let me require amount as string in the contract API to avoid precision issues.

Actually, looking at typical NEAR contracts, amounts are usually passed as strings (U128). Let me require string.

Now, there's a concern: `near.blockTimestamp()` returns a BigInt in near-sdk-js 2.0.0. Let me verify. Yes, `near.blockTimestamp(): bigint`.

For JSON.parse, the expires_at will be a number (or string if we serialize it as string). If expires_at is a large number like 1700000000000000000 (nanoseconds), JSON.parse will lose precision because JS numbers are doubles. So we should serialize expires_at as a string in the attestation.

Let me update the Python side to use string for expires_at and nonce too, to be safe. Actually nonce can be up to 2^63 which also exceeds safe integer range. Let me use strings for both.

Updated attestation:
```python
{
    "engine_id": "...",
    "proposal_id": "...",
    "recipient": "...",
    "amount": "...",
    "nonce": "1234567890123456789",  # string
    "expires_at": "1700000000000000000",  # string
    "sig_hash": "..."
}
```

And canonical payload uses these strings directly.

On-chain:
```js
const canonical = `${att.engine_id}|${att.proposal_id}|${att.recipient}|${att.amount}|${att.nonce}|${att.expires_at}`;
```

Good, all strings.

Now for the nonce replay protection on-chain. We need to store used nonces. But LookupMap with string keys works.

```js
assert(!this.used_nonces.get(att.nonce), 'NONCE_REPLAY');
this.used_nonces.set(att.nonce, true);
```

Now, let me think about the full contract. The user mentioned `unconfirmed_reservation` and `UNKNOWN/PENDING_RECONCILIATION` states. These are for the off-chain engine's state machine. Let me focus on the contract's propose_payment and the off-chain engine.

Let me also think about what `propose_payment` does after verification. It should:
1. Verify attestation
2. Check policy (budget, allowlist, etc.)
3. Create a reservation
4. Return proposal_id

Let me write a reasonable implementation.

Now for Task 2: Adversarial Stress Test.

The test file `test_adversarial_stress.py` needs to test:
1. Forged attestation rejection (tampered amount, expired timestamp, bad signature)
2. Concurrency attack: 10 threads, same nonce or budget overrun, only 1 succeeds
3. Network failure/gas exhaustion: unconfirmed_reservation doesn't leak, goes to UNKNOWN/PENDING_RECONCILIATION

For the concurrency test, we need SQLite with BEGIN IMMEDIATE. Let me design `policy/storage.py`:

```python
import sqlite3
import threading
import time
from contextlib import contextmanager

class PolicyStorage:
    def __init__(self, db_path):
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()

    def _get_conn(self):
        if not hasattr(self._local, 'conn'):
            self._local.conn = sqlite3.connect(self.db_path, timeout=30.0, isolation_level=None)
            self._local.conn.execute('PRAGMA journal_mode=WAL')
            self._local.conn.execute('PRAGMA busy_timeout=30000')
        return self._local.conn

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS reservations (
                proposal_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                recipient TEXT NOT NULL,
                amount TEXT NOT NULL,
                nonce TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS budgets (
                agent_id TEXT PRIMARY KEY,
                total_budget TEXT NOT NULL,
                spent TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_reservations_status ON reservations(status);
        ''')
        conn.commit()
        conn.close()

    @contextmanager
    def immediate_transaction(self):
        conn = self._get_conn()
        conn.execute('BEGIN IMMEDIATE')
        try:
            yield conn
            conn.execute('COMMIT')
        except Exception:
            conn.execute('ROLLBACK')
            raise
```

For the concurrency test, we need to simulate 10 threads trying to reserve the same budget. With BEGIN IMMEDIATE, only one thread can hold the write lock at a time. The others will wait (busy_timeout). Then each checks the budget and either succeeds or fails.

Wait, but if all 10 threads try to reserve the same amount and the budget only allows 1, then:
- Thread 1: BEGIN IMMEDIATE, check budget (ok), insert reservation, update budget, COMMIT
- Thread 2: BEGIN IMMEDIATE (waits for thread 1), check budget (now insufficient), ROLLBACK
- etc.

So exactly 1 succeeds. Good.

But we need to be careful about the amount comparison. If amounts are strings, we need to convert to int for comparison. Let me use integer amounts (in yoctoNEAR or smallest unit).

Actually, let me use integer amounts throughout for simplicity. The contract can accept strings but internally convert.

Hmm, but the attestation has amount as string. Let me keep it as string in the attestation but convert to int for budget checks.

Let me now write the full code.

Actually, let me reconsider the structure. The user wants:
- `contract/src/index.js` - smart contract
- `policy/engine.py` - off-chain engine
- `policy/storage.py` - storage layer
- `sdk/carerail_tool.py` - SDK
- `test_adversarial_stress.py` - tests

Let me write each file.

**contract/src/index.js**

```js
import {
  NearBindgen,
  near,
  call,
  view,
  initialize,
  assert,
  LookupMap,
} from 'near-sdk-js';

// ============ Crypto helpers (QuickJS-safe) ============

function utf8Encode(str) {
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    let code = str.charCodeAt(i);
    if (code < 0x80) {
      bytes.push(code);
    } else if (code < 0x800) {
      bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code < 0xd800 || code >= 0xe000) {
      bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      i++;
      const next = str.charCodeAt(i);
      const cp = 0x10000 + (((code & 0x3ff) << 10) | (next & 0x3ff));
      bytes.push(
        0xf0 | (cp >> 18),
        0x80 | ((cp >> 12) & 0x3f),
        0x80 | ((cp >> 6) & 0x3f),
        0x80 | (cp & 0x3f)
      );
    }
  }
  return new Uint8Array(bytes);
}

function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function hexToBytes(hex) {
  if (hex.length % 2 !== 0) return null;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    const b = parseInt(hex.substr(i, 2), 16);
    if (isNaN(b)) return null;
    bytes[i / 2] = b;
  }
  return bytes;
}

function hmacSha256(keyBytes, messageBytes) {
  const BLOCK = 64;
  let key = keyBytes;
  if (key.length > BLOCK) {
    key = near.sha256(key);
  }
  const paddedKey = new Uint8Array(BLOCK);
  paddedKey.set(key);

  const ipad = new Uint8Array(BLOCK);
  const opad = new Uint8Array(BLOCK);
  for (let i = 0; i < BLOCK; i++) {
    ipad[i] = paddedKey[i] ^ 0x36;
    opad[i] = paddedKey[i] ^ 0x5c;
  }

  const inner = new Uint8Array(BLOCK + messageBytes.length);
  inner.set(ipad, 0);
  inner.set(messageBytes, BLOCK);
  const innerHash = near.sha256(inner);

  const outer = new Uint8Array(BLOCK + innerHash.length);
  outer.set(opad, 0);
  outer.set(innerHash, BLOCK);
  return near.sha256(outer);
}

function hmacSha256Hex(keyStr, messageStr) {
  const keyBytes = utf8Encode(keyStr);
  const msgBytes = utf8Encode(messageStr);
  return bytesToHex(hmacSha256(keyBytes, msgBytes));
}

function constantTimeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ============ Attestation verification ============

function canonicalPayload(att) {
  return `${att.engine_id}|${att.proposal_id}|${att.recipient}|${att.amount}|${att.nonce}|${att.expires_at}`;
}

function verifyAttestation(attestationStr, expected, engineKey, blockTimestamp) {
  let att;
  try {
    att = JSON.parse(attestationStr);
  } catch (e) {
    assert(false, 'INVALID_ENGINE_ATTESTATION');
  }
  assert(att && typeof att === 'object', 'INVALID_ENGINE_ATTESTATION');
  assert(typeof att.engine_id === 'string' && att.engine_id.length > 0, 'INVALID_ENGINE_ATTESTATION');
  assert(typeof att.proposal_id === 'string', 'INVALID_ENGINE_ATTESTATION');
  assert(typeof att.recipient === 'string', 'INVALID_ENGINE_ATTESTATION');
  assert(typeof att.amount === 'string', 'INVALID_ENGINE_ATTESTATION');
  assert(typeof att.nonce === 'string', 'INVALID_ENGINE_ATTESTATION');
  assert(typeof att.expires_at === 'string', 'INVALID_ENGINE_ATTESTATION');
  assert(typeof att.sig_hash === 'string', 'INVALID_ENGINE_ATTESTATION');

  // Binding checks
  assert(att.proposal_id === expected.proposal_id, 'INVALID_ENGINE_ATTESTATION');
  assert(att.recipient === expected.recipient, 'INVALID_ENGINE_ATTESTATION');
  assert(att.amount === expected.amount, 'INVALID_ENGINE_ATTESTATION');

  // Expiry check (nanoseconds)
  const expiresAt = BigInt(att.expires_at);
  assert(expiresAt > BigInt(blockTimestamp), 'INVALID_ENGINE_ATTESTATION');

  // Signature check
  const expectedSig = hmacSha256Hex(engineKey, canonicalPayload(att));
  assert(constantTimeEqualHex(expectedSig, att.sig_hash), 'INVALID_ENGINE_ATTESTATION');

  return att;
}
```

Wait, there's an issue with `assert(false, ...)` inside a try-catch. If `assert` throws, the catch will catch it and then call `assert(false, ...)` again. That's fine, but it's redundant. Let me restructure:

```js
let att;
try {
  att = JSON.parse(attestationStr);
} catch (e) {
  att = null;
}
assert(att && typeof att === 'object', 'INVALID_ENGINE_ATTESTATION');
```

Better.

Now the contract class:

```js
@NearBindgen({})
class PolicyVault {
  constructor() {
    this.owner = '';
    this.engine_attestation_key = '';
    this.agents = new LookupMap('agents');
    this.policies = new LookupMap('policies');
    this.proposals = new LookupMap('proposals');
    this.used_nonces = new LookupMap('used_nonces');
    this.reservations = new LookupMap('reservations');
    this.proposal_counter = 0;
  }

  @initialize({})
  init({ owner, engine_attestation_key }) {
    assert(owner && engine_attestation_key, 'INVALID_INIT');
    this.owner = owner;
    this.engine_attestation_key = engine_attestation_key;
  }

  @call({})
  set_attestation_key({ new_key }) {
    assert(near.predecessorAccountId() === this.owner, 'ONLY_OWNER');
    assert(new_key && new_key.length > 0, 'INVALID_KEY');
    this.engine_attestation_key = new_key;
  }

  @call({})
  register_agent({ agent_id, total_budget }) {
    assert(near.predecessorAccountId() === this.owner, 'ONLY_OWNER');
    assert(!this.agents.get(agent_id), 'AGENT_EXISTS');
    this.agents.set(agent_id, { total_budget, spent: '0', active: true });
  }

  @call({})
  propose_payment({ proposal_id, recipient, amount, attestation }) {
    const caller = near.predecessorAccountId();
    const agent = this.agents.get(caller);
    assert(agent && agent.active, 'UNKNOWN_AGENT');

    // Verify attestation (fail-closed)
    const att = verifyAttestation(
      attestation,
      { proposal_id, recipient, amount },
      this.engine_attestation_key,
      near.blockTimestamp()
    );

    // Nonce replay protection
    assert(!this.used_nonces.get(att.nonce), 'NONCE_REPLAY');

    // Budget check
    const totalBudget = BigInt(agent.total_budget);
    const spent = BigInt(agent.spent);
    const amt = BigInt(amount);
    assert(amt > 0n, 'INVALID_AMOUNT');
    assert(spent + amt <= totalBudget, 'BUDGET_EXCEEDED');

    // Reserve
    this.used_nonces.set(att.nonce, true);
    this.agents.set(caller, {
      total_budget: agent.total_budget,
      spent: (spent + amt).toString(),
      active: true,
    });

    this.reservations.set(proposal_id, {
      agent_id: caller,
      recipient,
      amount,
      nonce: att.nonce,
      status: 'RESERVED',
      created_at: near.blockTimestamp().toString(),
    });

    return { proposal_id, status: 'RESERVED' };
  }

  @view({})
  get_reservation({ proposal_id }) {
    return this.reservations.get(proposal_id) || null;
  }

  @view({})
  get_agent({ agent_id }) {
    return this.agents.get(agent_id) || null;
  }
}
```

Hmm, but the user mentioned `unconfirmed_reservation` and `UNKNOWN/PENDING_RECONCILIATION`. These are off-chain states. Let me add a `confirm_payment` and `reconcile` function to the contract for completeness.

Actually, let me focus on what's asked. The contract needs:
- initialize with engine_attestation_key
- set_attestation_key
- propose_payment with attestation verification

Let me also add `confirm_payment` and `cancel_reservation` for the state machine.

Actually, let me keep it focused but complete. Let me add:
- `confirm_payment({ proposal_id, tx_hash })` - called by owner/engine to confirm
- `reconcile_reservation({ proposal_id, status })` - for UNKNOWN/PENDING_RECONCILIATION

Hmm, but the user's task 2 is about the off-chain SQLite state machine. Let me focus on that.

Let me now write the Python engine.

**policy/engine.py**

```python
import hmac
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class Attestation:
    engine_id: str
    proposal_id: str
    recipient: str
    amount: str
    nonce: str
    expires_at: str
    sig_hash: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(',', ':'), sort_keys=True)


class AttestationEngine:
    """
    Off-chain engine that produces HMAC-SHA256 attestations.
    The canonical payload MUST match contract/src/index.js canonicalPayload().
    """

    def __init__(self, engine_id: str, shared_secret: str, default_ttl_ns: int = 60_000_000_000):
        if not engine_id:
            raise ValueError("engine_id required")
        if not shared_secret:
            raise ValueError("shared_secret required")
        self.engine_id = engine_id
        self.shared_secret = shared_secret.encode("utf-8")
        self.default_ttl_ns = default_ttl_ns

    @staticmethod
    def _canonical_payload(engine_id, proposal_id, recipient, amount, nonce, expires_at) -> bytes:
        return f"{engine_id}|{proposal_id}|{recipient}|{amount}|{nonce}|{expires_at}".encode("utf-8")

    def _sign(self, payload: bytes) -> str:
        return hmac.new(self.shared_secret, payload, hashlib.sha256).hexdigest()

    def create_attestation(
        self,
        proposal_id: str,
        recipient: str,
        amount: str,
        ttl_ns: Optional[int] = None,
    ) -> Attestation:
        ttl = ttl_ns if ttl_ns is not None else self.default_ttl_ns
        nonce = str(secrets.randbits(63))
        expires_at = str(time.time_ns() + ttl)
        payload = self._canonical_payload(
            self.engine_id, proposal_id, recipient, amount, nonce, expires_at
        )
        sig = self._sign(payload)
        return Attestation(
            engine_id=self.engine_id,
            proposal_id=proposal_id,
            recipient=recipient,
            amount=amount,
            nonce=nonce,
            expires_at=expires_at,
            sig_hash=sig,
        )

    def verify_attestation(self, att: Attestation, now_ns: Optional[int] = None) -> bool:
        now = now_ns if now_ns is not None else time.time_ns()
        if int(att.expires_at) <= now:
            return False
        payload = self._canonical_payload(
            att.engine_id, att.proposal_id, att.recipient, att.amount, att.nonce, att.expires_at
        )
        expected = self._sign(payload)
        return hmac.compare_digest(expected, att.sig_hash)
```

Now the storage layer.

**policy/storage.py**

```python
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Optional


class ReservationStatus:
    RESERVED = "RESERVED"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"
    PENDING_RECONCILIATION = "PENDING_RECONCILIATION"


class PolicyStorage:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                self.db_path,
                timeout=30.0,
                isolation_level=None,  # manual transaction control
                check_same_thread=False,
            )
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("PRAGMA foreign