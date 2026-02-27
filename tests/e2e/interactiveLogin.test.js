const crypto = require('crypto');
const { startServer, stopServer, getServerUrl } = require('../helpers/startServer');
const { startTestSite, stopTestSite, getTestSiteUrl } = require('../helpers/testSite');

const TEST_API_KEY = 'interactive-login-test-key';

async function requestJson(method, url, body, headers = {}) {
  const res = await fetch(url, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
    body: body != null ? JSON.stringify(body) : undefined,
    redirect: 'manual',
  });

  const contentType = res.headers.get('content-type') || '';
  let data;
  if (contentType.includes('application/json')) {
    data = await res.json();
  } else {
    data = await res.text();
  }
  return { res, data };
}

function extractCookie(setCookieHeader) {
  if (!setCookieHeader) return null;
  return setCookieHeader.split(';')[0];
}

function extractCsrfToken(html) {
  const match = html.match(/const CSRF_TOKEN = (.+?);/);
  if (!match) return null;
  return JSON.parse(match[1]);
}

describe('Interactive Login', () => {
  let serverUrl;
  let testSiteUrl;

  beforeAll(async () => {
    await startServer(0, {
      CAMOFOX_INTERACTIVE_LOGIN: 'true',
      CAMOFOX_API_KEY: TEST_API_KEY,
      DEBUG_RESPONSES: 'false',
    });
    serverUrl = getServerUrl();
    await startTestSite();
    testSiteUrl = getTestSiteUrl();
  }, 120000);

  afterAll(async () => {
    await stopTestSite();
    await stopServer();
  }, 30000);

  test('requires API key for login session start', async () => {
    const userId = crypto.randomUUID();
    const { res, data } = await requestJson(
      'POST',
      `${serverUrl}/sessions/${encodeURIComponent(userId)}/login/start`,
      { sessionKey: 's1', url: `${testSiteUrl}/pageA` }
    );

    expect(res.status).toBe(403);
    expect(data.error).toBe('Forbidden');
  });

  test('full interactive login flow with UI bootstrap and completion', async () => {
    const userId = crypto.randomUUID();

    const start = await requestJson(
      'POST',
      `${serverUrl}/sessions/${encodeURIComponent(userId)}/login/start`,
      { sessionKey: 's1', url: `${testSiteUrl}/pageA` },
      { Authorization: `Bearer ${TEST_API_KEY}` }
    );
    expect(start.res.status).toBe(200);
    expect(start.data.ok).toBe(true);
    expect(start.data.status).toBe('pending');
    expect(start.data.loginId).toBeDefined();
    expect(start.data.loginUrl).toContain('/login/');

    const loginId = start.data.loginId;
    const loginUrl = start.data.loginUrl;

    const status1 = await requestJson(
      'GET',
      `${serverUrl}/sessions/${encodeURIComponent(userId)}/login/${encodeURIComponent(loginId)}/status`,
      null,
      { Authorization: `Bearer ${TEST_API_KEY}` }
    );
    expect(status1.res.status).toBe(200);
    expect(status1.data.status).toBe('pending');

    const bootstrapRes = await fetch(loginUrl, { redirect: 'manual' });
    expect(bootstrapRes.status).toBe(302);
    const cookie = extractCookie(bootstrapRes.headers.get('set-cookie'));
    expect(cookie).toBeTruthy();
    const location = bootstrapRes.headers.get('location');
    expect(location).toBe(`/login/${encodeURIComponent(loginId)}`);

    const htmlRes = await fetch(`${serverUrl}${location}`, {
      headers: { Cookie: cookie },
    });
    expect(htmlRes.status).toBe(200);
    const html = await htmlRes.text();
    expect(html).toContain('Interactive Login Session');
    const csrfToken = extractCsrfToken(html);
    expect(csrfToken).toBeTruthy();

    const state1 = await fetch(`${serverUrl}/login/${encodeURIComponent(loginId)}/state`, {
      headers: { Cookie: cookie },
    });
    expect(state1.status).toBe(200);
    const state1Data = await state1.json();
    expect(state1Data.status).toBe('pending');
    expect(state1Data.snapshot).toContain('Page A');

    const navRes = await requestJson(
      'POST',
      `${serverUrl}/login/${encodeURIComponent(loginId)}/act`,
      { kind: 'navigate', url: `${testSiteUrl}/pageB` },
      {
        Cookie: cookie,
        'x-csrf-token': csrfToken,
      }
    );
    expect(navRes.res.status).toBe(200);
    expect(navRes.data.ok).toBe(true);

    const state2 = await fetch(`${serverUrl}/login/${encodeURIComponent(loginId)}/state`, {
      headers: { Cookie: cookie },
    });
    const state2Data = await state2.json();
    expect(state2Data.snapshot).toContain('Page B');

    const blockedNav = await requestJson(
      'POST',
      `${serverUrl}/login/${encodeURIComponent(loginId)}/act`,
      { kind: 'navigate', url: 'https://example.org/' },
      {
        Cookie: cookie,
        'x-csrf-token': csrfToken,
      }
    );
    expect(blockedNav.res.status).toBe(400);
    expect(blockedNav.data.error).toContain('Navigation blocked');

    const complete = await requestJson(
      'POST',
      `${serverUrl}/login/${encodeURIComponent(loginId)}/complete`,
      {},
      {
        Cookie: cookie,
        'x-csrf-token': csrfToken,
      }
    );
    expect(complete.res.status).toBe(200);
    expect(complete.data.status).toBe('completed');

    const status2 = await requestJson(
      'GET',
      `${serverUrl}/sessions/${encodeURIComponent(userId)}/login/${encodeURIComponent(loginId)}/status`,
      null,
      { Authorization: `Bearer ${TEST_API_KEY}` }
    );
    expect(status2.res.status).toBe(200);
    expect(status2.data.status).toBe('completed');
  }, 120000);
});
