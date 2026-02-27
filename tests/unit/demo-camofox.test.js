const { runDemo } = require('../../demo/codex-camofox-demo');

describe('demo camofox script', () => {
  test('runs the basic workflow and closes the tab by default', async () => {
    const calls = [];
    const fetchImpl = jest.fn(async (url, options = {}) => {
      calls.push({ url, options });
      if (url.endsWith('/tabs') && options.method === 'POST') {
        return { ok: true, status: 200, json: async () => ({ tabId: 't1', url: 'https://example.com' }) };
      }
      if (url.endsWith('/tabs/t1/navigate') && options.method === 'POST') {
        return { ok: true, status: 200, json: async () => ({ ok: true }) };
      }
      if (url.endsWith('/tabs/t1/snapshot?userId=agent1') && options.method === 'GET') {
        return { ok: true, status: 200, json: async () => ({ snapshot: '[link e1] result' }) };
      }
      if (url.endsWith('/tabs/t1?userId=agent1') && options.method === 'DELETE') {
        return { ok: true, status: 200, json: async () => ({ ok: true }) };
      }
      return { ok: false, status: 404, json: async () => ({ error: 'unexpected request' }) };
    });

    const result = await runDemo({
      fetchImpl,
      baseUrl: 'http://localhost:9377',
      userId: 'agent1',
      sessionKey: 'task1',
      query: 'weather today',
    });

    expect(result.tabId).toBe('t1');
    expect(result.snapshot).toContain('e1');
    expect(calls).toHaveLength(4);
    expect(calls[0].url).toBe('http://localhost:9377/tabs');
    expect(calls[1].url).toBe('http://localhost:9377/tabs/t1/navigate');
    expect(calls[2].url).toBe('http://localhost:9377/tabs/t1/snapshot?userId=agent1');
    expect(calls[3].url).toBe('http://localhost:9377/tabs/t1?userId=agent1');
  });
});
