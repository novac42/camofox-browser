describe('Config loading', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };
    delete process.env.CAMOFOX_HEADLESS;
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  test('defaults to headless mode when CAMOFOX_HEADLESS is unset', () => {
    const { loadConfig } = require('../../lib/config');
    const cfg = loadConfig();
    expect(cfg.headless).toBe(true);
  });

  test('allows forcing headed mode via CAMOFOX_HEADLESS=false', () => {
    process.env.CAMOFOX_HEADLESS = 'false';
    const { loadConfig } = require('../../lib/config');
    const cfg = loadConfig();
    expect(cfg.headless).toBe(false);
  });

  test('forwards CAMOFOX_HEADLESS to server subprocess env', () => {
    process.env.CAMOFOX_HEADLESS = 'false';
    const { loadConfig } = require('../../lib/config');
    const cfg = loadConfig();
    expect(cfg.serverEnv.CAMOFOX_HEADLESS).toBe('false');
  });
});
