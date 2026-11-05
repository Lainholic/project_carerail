const { JsonRpcProvider } = require('near-api-js');

const DEFAULT_RPC_ENDPOINTS = [
  'https://test.rpc.fastnear.com',
  'https://rpc.testnet.near.org'
];

/**
 * Creates a transparent Proxy over JsonRpcProvider that intercepts all method calls
 * (query, viewBlock, sendTransaction, etc.) and automatically fails over across
 * multiple RPC endpoints if any endpoint throws a network error or times out.
 */
function createFailoverProvider(urls = DEFAULT_RPC_ENDPOINTS) {
  const endpoints = Array.isArray(urls) && urls.length > 0 ? urls : DEFAULT_RPC_ENDPOINTS;
  const providers = endpoints.map(url => new JsonRpcProvider({ url }));
  let currentIndex = 0;

  return new Proxy(providers[0], {
    get(target, prop) {
      const currentProvider = providers[currentIndex];
      const member = currentProvider[prop];
      if (typeof member === 'function') {
        return async function (...args) {
          let lastErr = null;
          const startIdx = currentIndex;
          for (let i = 0; i < providers.length; i++) {
            const idx = (startIdx + i) % providers.length;
            const p = providers[idx];
            try {
              return await p[prop](...args);
            } catch (err) {
              lastErr = err;
              const msg = err.message || '';
              const isNetworkError =
                err.name === 'FetchError' ||
                err.code === 'ECONNRESET' ||
                err.code === 'ECONNREFUSED' ||
                err.code === 'ETIMEDOUT' ||
                msg.includes('fetch failed') ||
                msg.includes('ETIMEDOUT') ||
                msg.includes('ECONNRESET') ||
                msg.includes('ECONNREFUSED') ||
                msg.includes('Server error: 502') ||
                msg.includes('Server error: 503') ||
                msg.includes('Server error: 504') ||
                msg.includes('429 Too Many Requests');

              if (isNetworkError) {
                const nextIdx = (idx + 1) % providers.length;
                console.warn(`[Multi-RPC Failover] RPC ${endpoints[idx]} network failure (${msg}). Failing over to ${endpoints[nextIdx]}...`);
                currentIndex = nextIdx;
                continue;
              }
              // Legitimate blockchain/contract exception: do not treat as RPC network fault
              throw err;
            }
          }
          throw lastErr;
        };
      }
      return currentProvider[prop];
    }
  });
}

class FailoverJsonRpcProvider {
  constructor(urls = DEFAULT_RPC_ENDPOINTS) {
    return createFailoverProvider(urls);
  }
}

module.exports = {
  createFailoverProvider,
  FailoverJsonRpcProvider,
  DEFAULT_RPC_ENDPOINTS
};
