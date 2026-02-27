# Interactive Login Project Doc (Camofox Browser)

## 1) Background

Current auth flow relies on imported cookie files (`cookies.txt` style), which has two issues:

1. Usability: users must manually export/import cookies.
2. Security: cookie files are sensitive credential material at rest.

Goal is to keep Camoufox headless automation, but let users complete login on demand through a controlled interface tied to the same browser session (`userId`) used by agents.

## 2) Goals / Non-goals

### Goals

1. Agent can request human login only when needed.
2. User completes login through a temporary interface.
3. Login result persists in the existing isolated browser context (no cookie file import required).
4. Strong access controls for the temporary login channel.
5. Backward compatibility with existing API and plugin tools.

### Non-goals (MVP)

1. No full desktop/VNC stream.
2. No long-lived public login portal.
3. No change to existing session isolation model.

## 3) High-level Design

1. Agent calls `start login` endpoint for a `userId` + target site.
2. Server creates a short-lived `loginSession` and returns a one-time login URL.
3. User opens the URL, interacts with page via controlled actions (snapshot/screenshot/click/type/press/scroll).
4. User clicks `Complete Login`.
5. Agent polls login status and resumes automation in same browser context.

## 4) API Contract Draft

### 4.1 Start Login Session

`POST /sessions/:userId/login/start`

Auth:

1. If `CAMOFOX_API_KEY` is configured, require `Authorization: Bearer <CAMOFOX_API_KEY>`.
2. If no API key is configured, endpoint should be disabled by default in non-local environments.

Request:

```json
{
  "sessionKey": "task1",
  "url": "https://example.com/login",
  "allowedDomain": "example.com",
  "ttlSec": 600
}
```

Response:

```json
{
  "ok": true,
  "loginId": "lg_abc123",
  "tabId": "tab_xyz",
  "expiresAt": "2026-02-27T12:34:56.000Z",
  "loginUrl": "http://localhost:9377/login/lg_abc123?t=<bootstrap_token>"
}
```

### 4.2 Login Status

`GET /sessions/:userId/login/:loginId/status`

Auth:

1. Same as `start` endpoint.

Response:

```json
{
  "ok": true,
  "status": "pending",
  "expiresAt": "2026-02-27T12:34:56.000Z",
  "completedAt": null
}
```

Status values: `pending | completed | canceled | expired`

### 4.3 Complete / Cancel

`POST /sessions/:userId/login/:loginId/complete`
`POST /sessions/:userId/login/:loginId/cancel`

Auth:

1. Same as `start` endpoint.

### 4.4 User-facing Login UI Endpoints

1. `GET /login/:loginId?t=<bootstrap_token>` (one-time token exchange + serves HTML)
2. `GET /login/:loginId/state` (snapshot + screenshot + url)
3. `POST /login/:loginId/act` (`click | type | press | scroll | navigate`)
4. `POST /login/:loginId/complete`
5. `POST /login/:loginId/cancel`

All `/login/:loginId/*` endpoints require login UI session cookie (after bootstrap exchange).

## 5) Data Model

In-memory `loginSessions` map (MVP):

```text
loginId -> {
  loginId,
  userId,
  tabId,
  sessionKey,
  status,
  allowedDomain,
  expiresAt,
  createdAt,
  completedAt,
  tokenHash,
  lastAccessIp,
  lastAccessAt
}
```

Notes:

1. Store only hashed token (e.g., SHA-256 with server secret pepper).
2. Auto-expire and cleanup with existing session cleanup loop.
3. Keep independent from cookie import endpoint.

## 6) Security Review (Expert Pass)

### 6.1 Threat Model

Assets:

1. Authenticated browser context/cookies.
2. Temporary login URL token.
3. User identity and browsing actions.

Adversaries:

1. Attacker with leaked login URL.
2. CSRF attacker from third-party site.
3. Internal abuse/misuse of login control channel.

### 6.2 High Priority Risks and Required Mitigations

1. Token leakage in logs, referrers, browser history.
   - Mitigation:
     - Never log raw query token.
     - Redact `t` from request logs.
     - Serve UI with `Referrer-Policy: no-referrer`.
     - One-time token exchange: URL token used once to get short-lived session cookie; subsequent auth via `HttpOnly; Secure; SameSite=Strict` cookie.

2. CSRF against login action endpoints.
   - Mitigation:
     - Require same-site session cookie + CSRF token header for `POST`.
     - Reject requests without origin checks (`Origin` / `Referer`).

3. Session takeover via guessed/reused `loginId` or token replay.
   - Mitigation:
     - Use cryptographically strong random IDs/tokens.
     - Bind token to `loginId` and expiration.
     - Mark token as consumed on successful bootstrap.
     - Rate-limit failed auth attempts per IP/loginId.

4. Scope breakout from intended site.
   - Mitigation:
     - Enforce `allowedDomain` allowlist for `navigate`.
     - Block cross-domain jumps unless explicitly allowed.
     - Keep URL scheme validation (`http/https`) and apply to login actions.

5. Unauthorized long-lived access.
   - Mitigation:
     - Tight TTL default (10 minutes).
     - Manual cancel + automatic expiry.
     - Invalidate login session immediately on complete/cancel/expire.

6. SSRF pivot through login `navigate`.
   - Mitigation:
     - Restrict navigation to `allowedDomain` (exact host or approved subdomains).
     - Block localhost, private CIDRs, link-local, and metadata endpoints.
     - Resolve and re-check DNS on each navigation to reduce DNS-rebind risk.

7. Privilege overreach from weak caller identity (`userId` spoofing).
   - Mitigation:
     - Do not trust caller-provided `userId` alone on networked deployments.
     - Require API key for all login-management endpoints when feature is enabled.
     - Prefer gateway-signed identity headers (or internal-only binding on localhost).

### 6.3 Medium Priority Risks

1. Clickjacking of login UI.
   - Mitigation: `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'`.

2. Sensitive data persistence in logs/snapshots.
   - Mitigation: avoid logging typed content; redact secrets in debug payloads; keep snapshot size limits.

3. Brute-force / abuse.
   - Mitigation: per-IP and per-user rate limits for login endpoints.

4. DoS via excessive login sessions/screenshot polling.
   - Mitigation:
     - Add `MAX_LOGIN_SESSIONS` cap and per-session request QPS limits.
     - Fail fast with `429` when caps are reached.

5. XSS in login UI leading to session cookie theft.
   - Mitigation:
     - Serve static UI with strict CSP (`default-src 'self'; script-src 'self'; object-src 'none'`).
     - No inline unsanitized rendering of URL/snapshot fields.
     - Use `HttpOnly` auth cookie and avoid exposing sensitive tokens to JS.

## 7) Implementation Plan

### Phase 1: Server-side MVP

1. Add login session store + TTL cleanup.
2. Add `/sessions/:userId/login/start|status|complete|cancel`.
3. Add `/login/:loginId/*` minimal UI and action endpoints.
4. Reuse existing tab/session locking (`withUserLimit`, `withTabLock`).

### Phase 2: Plugin Tooling

1. Add `camofox_start_login`.
2. Add `camofox_check_login`.
3. Add `camofox_cancel_login`.
4. Keep existing `camofox_import_cookies` as fallback path.

### Phase 3: Security Hardening

1. One-time bootstrap token -> strict session cookie.
2. CSRF protection + origin checks.
3. Rate limiting and auth failure metrics.
4. Audit log events (start/complete/cancel/expire) without secret material.
5. SSRF hardening for login navigation.

### Phase 4: Tests and Docs

1. Unit tests for login token validation, expiry, and state transitions.
2. E2E test with local login page simulation:
   - start login -> user action -> complete -> agent resumes.
3. Security tests:
   - invalid/expired token, cross-origin post, domain escape, replay attempt.
4. README section: "On-demand Interactive Login".

## 8) OpenClaw Scanner Constraint Compliance

1. Keep all `process.env` reads only in `lib/config.js`.
2. Do not add `child_process` usage in `server.js`.
3. `server.js` only handles routes/orchestration, imports helper modules for any sensitive logic.

## 9) Rollout Strategy

1. Feature flag: `CAMOFOX_INTERACTIVE_LOGIN=true` (default off for first release).
2. Require `CAMOFOX_API_KEY` when feature flag is on (fail fast at startup otherwise).
3. Internal test release.
4. Enable by default after security test pass and docs update.

## 10) Security Gates (Release Blocking)

1. Token replay test passes.
2. Expired token rejection test passes.
3. CSRF / cross-origin POST rejection test passes.
4. Domain escape + private-network SSRF tests pass.
5. Log redaction test confirms no token leakage.
6. Unauthenticated access to agent login endpoints rejected when API key is configured.

## 11) Acceptance Criteria

1. Agent can trigger login and receive a temporary login URL.
2. User can complete login without cookie file export.
3. Agent detects completion and continues browsing authenticated pages.
4. Token replay, expired token, and cross-origin attacks are rejected.
5. Existing cookie import flow remains functional.
