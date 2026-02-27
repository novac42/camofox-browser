#!/usr/bin/env node

function parseArgs(argv) {
  const options = {
    baseUrl: 'http://localhost:9377',
    userId: 'agent1',
    sessionKey: 'demo1',
    query: 'weather today',
    keepOpen: false,
    warmupMinMs: 4000,
    warmupMaxMs: 8000,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--base-url' && argv[i + 1]) options.baseUrl = argv[++i];
    else if (arg === '--user-id' && argv[i + 1]) options.userId = argv[++i];
    else if (arg === '--session-key' && argv[i + 1]) options.sessionKey = argv[++i];
    else if (arg === '--query' && argv[i + 1]) options.query = argv[++i];
    else if (arg === '--keep-open') options.keepOpen = true;
    else if (arg === '--warmup-min-ms' && argv[i + 1]) options.warmupMinMs = Number(argv[++i]);
    else if (arg === '--warmup-max-ms' && argv[i + 1]) options.warmupMaxMs = Number(argv[++i]);
  }

  return options;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function pickDelayMs(minMs, maxMs, randomFn = Math.random) {
  if (!Number.isFinite(minMs) || minMs < 0) throw new Error('warmupMinMs must be a non-negative number');
  if (!Number.isFinite(maxMs) || maxMs < 0) throw new Error('warmupMaxMs must be a non-negative number');
  if (maxMs < minMs) throw new Error('warmupMaxMs must be greater than or equal to warmupMinMs');
  if (maxMs === minMs) return Math.floor(minMs);
  const span = maxMs - minMs;
  return Math.floor(minMs + randomFn() * span);
}

async function requestJson(fetchImpl, url, options = {}) {
  const response = await fetchImpl(url, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = data && data.error ? data.error : `HTTP ${response.status}`;
    throw new Error(`${options.method || 'GET'} ${url} failed: ${detail}`);
  }
  return data;
}

async function runDemo({
  fetchImpl = globalThis.fetch,
  baseUrl = 'http://localhost:9377',
  userId = 'agent1',
  sessionKey = 'demo1',
  query = 'weather today',
  keepOpen = false,
  warmupMinMs = 4000,
  warmupMaxMs = 8000,
  sleepFn = sleep,
  randomFn = Math.random,
} = {}) {
  if (typeof fetchImpl !== 'function') {
    throw new Error('fetch is not available. Use Node.js 18+ or pass fetchImpl.');
  }

  const createData = await requestJson(fetchImpl, `${baseUrl}/tabs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      userId,
      sessionKey,
      url: 'https://www.google.com',
    }),
  });

  const tabId = createData.tabId;
  const warmupDelayMs = pickDelayMs(warmupMinMs, warmupMaxMs, randomFn);
  if (warmupDelayMs > 0) {
    await sleepFn(warmupDelayMs);
  }

  await requestJson(fetchImpl, `${baseUrl}/tabs/${tabId}/navigate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      userId,
      macro: '@google_search',
      query,
    }),
  });

  const snapshotData = await requestJson(
    fetchImpl,
    `${baseUrl}/tabs/${tabId}/snapshot?userId=${encodeURIComponent(userId)}`,
    { method: 'GET' }
  );

  if (!keepOpen) {
    await requestJson(
      fetchImpl,
      `${baseUrl}/tabs/${tabId}?userId=${encodeURIComponent(userId)}`,
      { method: 'DELETE' }
    );
  }

  return {
    tabId,
    snapshot: snapshotData.snapshot || '',
    closed: !keepOpen,
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const result = await runDemo(options);
  process.stdout.write(`tabId: ${result.tabId}\n`);
  process.stdout.write(`closed: ${result.closed}\n`);
  process.stdout.write('snapshot preview:\n');
  process.stdout.write(`${result.snapshot.split('\n').slice(0, 12).join('\n')}\n`);
}

if (require.main === module) {
  main().catch((err) => {
    process.stderr.write(`${err.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { parseArgs, runDemo, pickDelayMs };
