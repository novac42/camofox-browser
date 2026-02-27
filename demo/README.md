# Demo Scripts

## codex-camofox-demo.js

Minimal demo script that drives `camofox-browser` over HTTP:

1. `POST /tabs`
2. `POST /tabs/:tabId/navigate` with `@google_search`
3. `GET /tabs/:tabId/snapshot`
4. `DELETE /tabs/:tabId` (default)

Before running the search, it waits a randomized warmup delay (`4000-8000ms` by default)
to reduce bot-like request timing.

### Run

```bash
node demo/codex-camofox-demo.js
```

### Common options

```bash
node demo/codex-camofox-demo.js \
  --base-url http://localhost:9377 \
  --user-id agent1 \
  --session-key demo1 \
  --query "openai gpt-5" \
  --warmup-min-ms 4000 \
  --warmup-max-ms 8000 \
  --keep-open
```
