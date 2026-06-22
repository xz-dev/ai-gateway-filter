# Local implementation context: Phase 1 core primitives + Phase 0 APISIX capability spike

Task source: `CONTEXT.md` and `plans/apisix-ai-gateway-privacy-plugin.md`. This handoff is for planning the first safe implementation milestone. No source files were changed; this file is the requested handoff artifact.

## 1. High-level conclusion

The safest first milestone is **Phase 1 core-library direction-aware primitives only**. Do not change APISIX routes/compose yet.

Why:

- The current APISIX example is still a catch-all APISIX route plus a `privacy-proxy` sidecar, not `ai-proxy` (`apisix-plugin-example/init/configure_routes.py:52-83`, `apisix-plugin-example/compose.yaml:11-61`).
- Current core has useful token/PII/injection primitives, but its public privacy helpers still conflict with the new security-boundary contract in two key ways:
  - `check_text()` also checks a token-masked candidate (`src/privacy_gateway/lib.py:393-404`), while the new contract requires direction-specific injection checks on current semantic content without token masking/pre-normalization (`CONTEXT.md:31-41`).
  - `process_inbound_privacy_text()` fails on any structurally valid but undecryptable token (`src/privacy_gateway/lib.py:349-367`), while the new contract requires best-effort restore and preserving undecryptable tokens (`CONTEXT.md:39-41`).
- APISIX Phase 0 evidence strongly suggests the **Python external runner is not sufficient for request-body rewrite + response/SSE mutation** in the current stack. A native APISIX/Lua hook is likely needed for APISIX response/SSE rewriting, with a later decision on how Lua calls Python/core primitives. That decision should not block Phase 1 core work.

## 2. Requirement facts from project docs

Key invariants from `CONTEXT.md`:

- Provider auth belongs to APISIX `ai-proxy` route/config or client pass-through; privacy plugin/library must not inspect/transform provider `Authorization` headers (`CONTEXT.md:23-25`).
- Outbound external traffic is **internal client -> injection check -> reversible tokenization -> provider**; never restore/normalize outbound tokens; existing `<secret:1:...>` tokens pass unchanged and are not decrypted/re-encrypted/double-tokenized/masked before injection checks (`CONTEXT.md:31-37`).
- Inbound provider traffic is **provider -> best-effort token restore/normalize -> injection check -> internal client**; undecryptable tokens are preserved unchanged; inbound provider-generated plaintext PII is allowed and not tokenized/masked solely because it is PII (`CONTEXT.md:39-41`).
- Supported agent-action endpoints are only `/v1/chat/completions` and `/v1/responses`; embeddings/images/files/arbitrary `/v1/*` are out of scope (`CONTEXT.md:71-73`).
- Streaming inbound must restore tokens incrementally with a sliding-window assembler and buffer complete semantic answer for post-completion injection check; after SSE starts, failures must be stream-level errors/final events, not changed HTTP status (`CONTEXT.md:47-60`).
- Semantic content includes message/instruction/user/assistant/tool argument text and inline/base64/data URL image content, not model/stream/temp/tool schemas/tool names/headers/route/config (`CONTEXT.md:79-81`).
- Core library may expose direction-aware semantic-content helpers but must not provide routing, HTTP server, APISIX plugin implementation, or network proxy behavior (`CONTEXT.md:83-89`).

Plan facts from `plans/apisix-ai-gateway-privacy-plugin.md`:

- Phase 0 exit criteria: document hook choice for request rewrite, non-streaming response rewrite, and streaming SSE rewrite (`plans/apisix-ai-gateway-privacy-plugin.md:23-37`).
- Phase 1 API additions should include raw injection check, outbound semantic text processing, inbound semantic text processing, and streaming inbound token restorer (`plans/apisix-ai-gateway-privacy-plugin.md:39-60`).
- Phase 1 tests required: outbound blocks before tokenization; outbound never restores tokens; no double-tokenizing token bodies; inbound restores before injection; inbound preserves undecryptable tokens; inbound does not tokenize provider-generated plaintext PII; no token masking before injection checks (`plans/apisix-ai-gateway-privacy-plugin.md:62-70`).

## 3. Current core-library file map and behavior

### Public package/API

- `src/privacy_gateway/__init__.py`
  - Re-exports `PrivacyGatewayFilter`, `FilterDecision`, `SensitiveTextStreamDetector`, `TextProcessingResult`, errors, etc.
  - Any new public classes/functions for Phase 1 should be exported here if intended for plugins.

- `src/privacy_gateway/lib.py`
  - Dataclasses:
    - `FilterDecision` (`lib.py:60-73`)
    - `TextProcessingError` (`lib.py:76-81`)
    - `TextProcessingResult` (`lib.py:84-95`)
  - Existing streaming phrase detector: `SensitiveTextStreamDetector.feed()` checks combined buffer then truncates (`lib.py:98-123`). This is **only injection phrase streaming**, not token restore.
  - `PrivacyGatewayFilter.__init__()` wires sensitive words, `SecretTokenService`, `PiiDetectionService`, `TextPrivacyService`, and image crypto (`lib.py:126-175`).
  - Settings constructor uses env-backed values (`lib.py:177-194`). Note: it defaults `require_spacy_model` from settings, with fallback handling.
  - Legacy whole-text crypto helpers remain (`lib.py:212-264`). Avoid changing these for Phase 1.
  - Existing privacy helpers:
    - `restore_privacy_text()` restores all tokens and raises on invalid ciphertext (`lib.py:333-339`).
    - `protect_privacy_text()` PII-tokenizes text (`lib.py:341-347`).
    - `process_inbound_privacy_text()` restores all tokens then calls `check_text`; catches any `TextCryptoError` as `secret_token_decryption_failed` (`lib.py:349-367`). This conflicts with new best-effort inbound contract.
    - `process_outbound_privacy_text()` calls `check_text` then tokenizes PII (`lib.py:369-391`). Mostly aligned except `check_text` masks tokens as an extra candidate.
    - `check_text()` checks raw text **and then token-stripped text** (`lib.py:393-404`). For Phase 1, add a raw/no-mask check and make new direction-aware APIs use that. Keep `check_text()` unchanged unless intentionally migrating legacy tests/docs.

### Token service

- `src/privacy_gateway/services/privacy_tokens.py`
  - Token format constants: `TOKEN_BODY_PATTERN`, `GENERIC_TOKEN_PATTERN` (`privacy_tokens.py:18-23`). Valid supported token shape is `<label:version:salt.ciphertext>`.
  - `SecretTokenService.iter_tokens()` returns supported tokens with offsets (`privacy_tokens.py:122-133`).
  - `is_token()` detects complete token strings (`privacy_tokens.py:138-142`).
  - `encrypt_secret()` is idempotent for already-supported tokens (`privacy_tokens.py:154-166`).
  - `decrypt_token()` derives token-specific AES key and decrypts (`privacy_tokens.py:168-174`).
  - `restore_text()` restores all matched tokens but raises on any invalid ciphertext/password (`privacy_tokens.py:176-193`). New Phase 1 inbound should not use this fail-closed all-or-nothing behavior; add a best-effort restore path.
  - `strip_tokens()` replaces supported token ranges (`privacy_tokens.py:195-203`). Do not use this in new direction-aware injection checks.
  - `replace_spans()` skips spans that are already whole tokens (`privacy_tokens.py:205-228`). Combined with PII detector token-range exclusion, this helps outbound preserve existing tokens and avoid double-tokenization.

### PII detection

- `src/privacy_gateway/services/pii_detection.py`
  - Uses Presidio/spaCy when available; can fall back to deterministic regex if `require_spacy_model=False` (`pii_detection.py:123-149`, `pii_detection.py:157-168`).
  - Regex rules cover email, Chinese ID/phone, secret-value contexts, English/Chinese person/location contexts (`pii_detection.py:207-275`).
  - Important: `detect()` excludes spans overlapping supported secret tokens (`pii_detection.py:287-300`). This is key for outbound “preserve existing tokens / no double-tokenize token bodies.”

### Sensitive-word/injection detection

- `src/privacy_gateway/services/sensitive_words.py`
  - `SensitiveWordService.find()` performs case-insensitive matching and also compact whitespace-insensitive matching (`sensitive_words.py:14-48`).
  - A raw check on token text can still match compact phrases inside token-looking text; this is expected if the current semantic content literally contains that text and no masking is applied.

### Settings and HTTP adapter

- `src/privacy_gateway/config.py`
  - Default prompt-injection phrases (`config.py:7-15`).
  - `PRIVACY_GATEWAY_PASSWORD` is password for reversible tokens; `PRIVACY_GATEWAY_CRYPTO_KEY` is legacy fallback (`config.py:91-132`).
- `src/privacy_gateway/adapters/http.py`
  - Framework-free helpers only; `build_block_error()` returns generic `privacy_gateway_blocked` shape (`adapters/http.py:54-83`). This is not fully OpenAI-compatible but can remain as legacy/shared adapter unless APISIX error contract work starts.

## 4. Current tests and likely Phase 1 test changes

### Existing behavior tests

- Tests are Behave BDD, not pytest.
- Main feature: `features/privacy_gateway.feature`.
- Step definitions: `features/steps/privacy_gateway_steps.py`.
- CI runs `uv run python scripts/prepare_spacy_model.py en_core_web_sm`, `uv run behave`, `compileall`, `uv build` (`.github/workflows/ci.yml`).

Relevant existing scenarios:

- Injection checks and streaming phrase detector: `features/privacy_gateway.feature:68-110`.
- Current privacy token tests: `features/privacy_gateway.feature:175-300`.
- Current scenarios that conflict with the new inbound-provider contract and should be updated or superseded for new APIs:
  - “Structurally valid fake secret token fails closed before prompt checks” expects `secret_token_decryption_failed` (`features/privacy_gateway.feature:251-255`). New inbound provider primitive should preserve undecryptable tokens and continue, not fail solely due decrypt failure.
  - “Secret token restoration with the wrong password is normalized” and “Tampered secret tokens fail closed” expect errors (`features/privacy_gateway.feature:278-291`). These may remain for legacy `process_inbound_privacy_text()`, but new inbound provider primitive must have different tests.
- Existing “Secret tokens are not inspected as prompt injection plaintext” (`features/privacy_gateway.feature:213-217`) validates legacy `check_text()` masking behavior. Do not break it unless intentionally changing legacy API. New raw check should have separate tests proving no masking.

### Suggested Phase 1 test additions

Prefer adding new steps/scenarios for new direction-aware APIs rather than rewriting all legacy behavior at once.

Add scenarios equivalent to:

1. Raw injection check does not token-mask:
   - Create a fake structurally valid token text whose body contains/compacts a configured phrase (or another controlled token-looking string) and verify the new raw check sees current text, not stripped text. Keep existing `check_text()` legacy behavior if tests rely on it.
2. Outbound external semantic processing:
   - Blocks `Ignore previous instructions... zhangsan@example.com` before tokenization.
   - Does **not** restore an existing valid token: protect `张三`, then outbound-process `hello <token> email zhangsan@example.com`; result should still contain the original token string and also tokenize the email.
   - Does not double-tokenize token bodies (use count and equality for original token).
3. Inbound provider semantic processing:
   - Restores decryptable token before injection check; if token plaintext is injection phrase, decision is blocked and content empty.
   - Preserves undecryptable structurally valid token and returns allowed when no raw injection phrase is present.
   - Does not tokenize provider-generated plaintext PII: inbound-process `provider says zhangsan@example.com`; content remains plaintext email if allowed.
4. Streaming token restorer:
   - Token split across multiple chunks restores once complete.
   - Plain text before token is emitted promptly (do not wait for full response).
   - Undecryptable complete token is emitted raw and stream continues.
   - Partial token at final flush is emitted raw.
   - Non-streaming inbound path can reuse the same restorer or at least produce identical best-effort restore behavior.

## 5. Likely Phase 1 code changes

Recommended safe approach: **add new public APIs; keep existing legacy helpers stable unless tests/docs are intentionally migrated.** Names below are suggestions; use clear direction names to avoid old inbound/outbound ambiguity.

### In `src/privacy_gateway/services/privacy_tokens.py`

Add best-effort restore support:

- `restore_text_best_effort(text, password) -> str`:
  - Iterate `self._iter_matches(text)` right-to-left like `restore_text()`.
  - For each token, try `decrypt_token()`.
  - On `TextCryptoError` (including wrong password, tamper, invalid salt), leave that token unchanged and continue.
  - If password is missing, either:
    - preserve tokens unchanged and continue (most consistent with “cannot be decrypted -> preserved”), or
    - only raise when caller explicitly requires restoration. For the new inbound-provider primitive, preserve is preferable.
- Optional: expose a small helper for supported token prefix/pattern, useful for stream assembler.

Add streaming restorer class, probably in `privacy_tokens.py` or new `services/streaming_tokens.py`:

- Suggested public-ish class: `StreamingSecretTokenRestorer` or `SecretTokenStreamRestorer`.
- Constructor accepts `SecretTokenService`, `password`, and max pending chars/window.
- `feed(chunk: str) -> str` emits restored/plain text that is safe to forward now.
- `flush() -> str` emits any remaining buffered text raw/best-effort restored.
- Behavior:
  - Hold potential token fragments beginning with `<secret:1:` until a complete `>` arrives or a max-window policy forces raw output.
  - Restore complete valid tokens; preserve raw token text when decryption fails.
  - Do not PII-tokenize; this is inbound restore only.
  - Bound memory. Token ciphertext length is variable, so choose/document a conservative max pending length and test overflow behavior.

### In `src/privacy_gateway/services/privacy_text.py`

Add methods that delegate to token service best-effort / streaming-compatible restore:

- `restore_text_best_effort(text, password) -> str`
- Optional `stream_restorer(password, ...)` factory if needed.

### In `src/privacy_gateway/lib.py`

Add raw/no-mask check and direction-aware APIs:

- `check_text_raw(text: str) -> FilterDecision` or `check_semantic_text(text: str) -> FilterDecision`:
  - Directly call `self._sensitive.find(text)` and return `FilterDecision.block/allow`.
  - Do **not** call `self._privacy_text.strip_tokens()`.
  - Leave `check_text()` legacy behavior unchanged unless deliberately migrating existing callers.

- New outbound external semantic API, suggested name `process_outbound_external_text()` or `process_outbound_semantic_text()`:
  - Resolve privacy password only if tokenization is needed; consider whether empty/no-PII text with no password should still pass.
  - `decision = check_text_raw(content)` first.
  - If blocked, return `TextProcessingResult(content="", decision=decision)`.
  - Then call `protect_privacy_text()` / `TextPrivacyService.protect_text()` to tokenize new PII.
  - Do not call restore/normalize.
  - Existing tokens should stay unchanged because `PiiDetectionService.detect()` excludes token ranges and `encrypt_secret()` is idempotent for whole tokens.

- New inbound provider semantic API, suggested name `process_inbound_provider_text()` or `process_inbound_semantic_text()`:
  - Best-effort restore known tokens using streaming-compatible restorer or new token service best-effort method.
  - Do not PII-tokenize plaintext PII.
  - Run `check_text_raw(restored_or_current_text)` after restore.
  - If blocked, content should be empty; if allowed, content should be restored/current text.
  - Undecryptable tokens should not produce `error` solely because they cannot decrypt.

- New streaming factory, suggested name `inbound_token_restorer()` / `streaming_inbound_restorer()`:
  - Returns the streaming restorer wired with current token service and password.
  - Export any public result class if the restorer needs structured output; keep simple string output if possible.

### In `src/privacy_gateway/__init__.py`

- Re-export any new public restorer/result classes and include them in `__all__`.

### Avoid in Phase 1

- Do not add JSON/OpenAI semantic extractors to `src/privacy_gateway`; that belongs to APISIX plugin layer per `CONTEXT.md:83-89` and README JSON guidance.
- Do not add HTTP server, proxy, route config, provider endpoint logic, or APISIX imports to core.
- Do not mutate APISIX example yet unless the milestone explicitly changes after review.

## 6. APISIX example current state

### Current stack

- `apisix-plugin-example/compose.yaml`
  - APISIX image is `apache/apisix:3.16.0-debian` (`compose.yaml:11-18`).
  - APISIX currently depends on `plugin-runner` and `privacy-proxy` (`compose.yaml:13-17`).
  - `privacy-proxy` and `upstream` are local Python services (`compose.yaml:42-61`).
  - Secrets are hard-coded demo values in compose for current demo (`compose.yaml:30-36`, `compose.yaml:46-53`, `compose.yaml:88-94`). Later Phase 4 should move real provider values to env/.env.example without committing secrets.
- `apisix-plugin-example/apisix/conf/config.yaml`
  - Enables APISIX Admin API wide open for local example (`config.yaml:14-23`).
  - Only ext-plugin socket setting is present (`config.yaml:30-31`); no explicit APISIX plugin list and no native custom plugin mount yet.
- `apisix-plugin-example/init/configure_routes.py`
  - Creates one catch-all route `/*` named/id `privacy-gateway-proxy` (`configure_routes.py:52-83`).
  - Route attaches only `ext-plugin-pre-req` and forwards to upstream node `privacy-proxy:8080` (`configure_routes.py:65-81`).
  - It prints the Admin API response body (`configure_routes.py:83-85`); later with provider secrets this must not print full route config/secrets.
- `apisix-plugin-example/runner/apisix/plugins/privacy_gateway_guard.py`
  - External Python plugin only blocks obvious plaintext prompt injection (`privacy_gateway_guard.py:69-117`).
  - It reads request body via `request.get_body()` (`privacy_gateway_guard.py:97-101`).
  - It does not rewrite request body or response body.
- `apisix-plugin-example/privacy_proxy/server.py`
  - This is the old hand-written proxy sidecar; it owns request restore, upstream forwarding, response tokenization (`server.py:295-350`).
  - It recursively walks generic JSON keys (`server.py:22-74`, `server.py:169-226`) rather than OpenAI-specific semantic structures.
  - It reads the full upstream response into memory (`server.py:321-336`) and sends a complete response; no SSE/chunk-safe behavior.
  - Direction naming is old/inverted relative to new CONTEXT: `_transform_text_value(inbound=True)` restores request tokens (`server.py:144-147`), and response path tokenizes outbound-to-client (`server.py:334-350`). New contract defines outbound as internal->provider and inbound as provider->internal.

### Current APISIX tests

- `apisix-plugin-example/tests/integration_test.py` asserts old `/echo` behavior and sidecar markers (`integration_test.py:80-183`). These tests become obsolete when moving to real `ai-proxy` routes.

## 7. Phase 0 APISIX capability findings

I fetched current APISIX docs through Context7 and also inspected Apache APISIX source at tag `3.16.0` to match the current compose image. Important: APISIX master/latest docs and source are ahead of 3.16; do not assume latest `openai-responses` support exists in `apache/apisix:3.16.0-debian`.

### APISIX 3.16 image likely includes AI Gateway plugins

Local source for APISIX tag `3.16.0` has the default plugin list containing:

- `ai-proxy-multi` priority 1041 and `ai-proxy` priority 1040 (`/tmp/apisix/conf/config.yaml.example:512-515`).
- AI plugins around it: `ai-prompt-template`, `ai-prompt-decorator`, `ai-prompt-guard`, `ai-rag`, `ai-aws-content-moderation`, `ai-rate-limiting` (`/tmp/apisix/conf/config.yaml.example:509-516`).

Runtime verification still needed against the actual container image because the example uses a custom config file without explicit `plugins:` list. Likely default plugins apply, but Phase 0 should prove via Admin API route creation or APISIX startup logs.

### APISIX 3.16 `ai-proxy` route schema for OpenAI-compatible endpoints

APISIX 3.16 source:

- `ai-proxy` requires only `provider` and `auth` (`/tmp/apisix/apisix/plugins/ai-proxy/schema.lua:168-190` plus required line later in same schema). It has `auth.header` / `auth.query` object support (`schema.lua:22-61`).
- Provider enum includes `openai-compatible` (`/tmp/apisix/apisix/plugins/ai-drivers/schema.lua:17-40`).
- `openai-compatible` driver is `openai-base.new({})` with no default host/path (`/tmp/apisix/apisix/plugins/ai-drivers/openai-compatible.lua:18`). Therefore `override.endpoint` should be a full URL including path, e.g. `https://host/v1/chat/completions` or `https://host/v1/responses`.
- `openai` driver has default host `api.openai.com`, path `/v1/chat/completions`, port 443 (`/tmp/apisix/apisix/plugins/ai-drivers/openai.lua:18-24`). For OmniRoute/OpenAI-compatible endpoints, prefer `provider: "openai-compatible"` + full `override.endpoint` unless runtime schema rejects it.
- `openai-base` parses JSON request bodies and only requires `Content-Type: application/json` at runtime (`/tmp/apisix/apisix/plugins/ai-drivers/openai-base.lua:54-66`). It does not validate `/v1/responses` request shape in 3.16.
- `openai-base` builds upstream URL from `override.endpoint` parsed scheme/host/port/path (`openai-base.lua:299-341`) and sends `params.body` JSON (`openai-base.lua:370-388`).
- `options.model` overwrites request body fields if configured (`openai-base.lua:344-347`). The project contract says do not require gateway-level model; omit `options.model` for normal proxying.

### Responses API support is uncertain in APISIX 3.16

APISIX 3.16 source inspected here uses `ai-drivers/openai-base.lua` oriented around chat completions:

- Streaming parser extracts `choices[*].delta.content` only (`openai-base.lua:106-150`).
- Non-streaming response text extraction reads `choices[*].message.content` only (`openai-base.lua:198-208`).
- There is no `ai-protocols/openai-responses.lua` in tag 3.16 source; that exists in newer APISIX master, not current image.

A `/v1/responses` route may still forward JSON to a full override endpoint, but APISIX 3.16 built-in AI logging/parsing may not understand Responses API semantic deltas. The privacy plugin must not rely on APISIX 3.16 extracting responses semantic content for it.

### Python external plugin runner limitations

Evidence from current runner source and APISIX ext-plugin code:

- APISIX `ext-plugin-pre-req` runs in `rewrite` phase with priority 12000 (`/tmp/apisix/apisix/plugins/ext-plugin-pre-req.lua:21-37`).
- APISIX ext-plugin core can accept a rewrite body if a runner sends one: it checks `rewrite:BodyLength()` and calls `ngx.req.set_body_data(body)` (`/tmp/apisix/apisix/plugins/ext-plugin/init.lua:635-664`).
- However, the Python runner `Request.call_handler()` only serializes path, headers, and args into the Rewrite response; it does **not** serialize request body (`/tmp/apisix-python-plugin-runner/apisix/runner/http/request.py:428-451`). `Request.set_body()` only caches the body locally for the plugin (`request.py:133-150`), so current Python plugin code cannot rewrite the APISIX request body before `ai-proxy` without patching the runner.
- Python runner `Response` only models Stop responses for HTTP request calls (`/tmp/apisix-python-plugin-runner/apisix/runner/http/response.py:29-160`). No `HTTPRespCall` support was found in the Python runner source, even though APISIX Lua `ext-plugin-post-resp` can initiate response RPC.
- APISIX `ext-plugin-post-resp` is a separate before-proxy implementation that performs its own upstream request and can buffer/read response body for external runner (`/tmp/apisix/apisix/plugins/ext-plugin-post-resp.lua:54-180`). This is not suitable with `ai-proxy` because `ai-proxy` itself bypasses nginx upstream and calls the provider in `before_proxy` (`/tmp/apisix/apisix/init.lua:493-497`, `/tmp/apisix/apisix/plugins/ai-proxy/base.lua:51-89`). It also does not give Python per-SSE-chunk mutation.

Likely conclusion for Phase 0: **do not bet on Python external runner for mutation**. Use a native APISIX/Lua plugin for request body rewrite and response/SSE body filtering, or explicitly patch/prove a runner path before committing. This aligns with the plan instruction not to resurrect the old proxy sidecar (`plans/apisix-ai-gateway-privacy-plugin.md:35`, `plans/apisix-ai-gateway-privacy-plugin.md:121`).

### Native APISIX/Lua hook evidence

- APISIX runs route plugin `rewrite` phase before `access` phase (`/tmp/apisix/apisix/init.lua:800-837`), so a native plugin can parse JSON and call `ngx.req.set_body_data()` before `ai-proxy` reads/sends the request body.
- APISIX `body-transformer` shows a native plugin rewriting request body in `rewrite` with `ngx.req.set_body_data(out)` and response body in `body_filter` (`/tmp/apisix/apisix/plugins/body-transformer.lua` in inspected source; relevant pattern: request transform in rewrite, response hold/transform in body_filter).
- APISIX `ai-proxy` bypasses nginx upstream and sends provider response chunks through `plugin.lua_response_filter(ctx, headers, body)`:
  - Streaming chunks: `openai-base.lua:87-151` reads `body_reader()` chunks, parses some SSE content for logging, then calls `plugin.lua_response_filter(ctx, res.headers, chunk)`.
  - Non-streaming: `openai-base.lua:154-211` reads full body and calls `plugin.lua_response_filter(ctx, headers, raw_res_body)`.
- `plugin.lua_response_filter()` invokes each plugin’s `lua_body_filter(conf, ctx, headers, body)`, allowing returned `new_body` to replace the body/chunk before `ngx.print()` (`/tmp/apisix/apisix/plugin.lua:1372-1405`).

Likely Phase 0 hook choice to validate in a spike:

- Request rewrite: native APISIX/Lua plugin `rewrite` phase, priority high enough to run before `ai-proxy` access/before_proxy. It should parse full JSON request body and `ngx.req.set_body_data()` transformed JSON.
- Non-streaming response rewrite: same native plugin implements `lua_body_filter`; with `ai-proxy`, it receives full raw response body for non-streaming.
- Streaming SSE rewrite: same native plugin implements `lua_body_filter`; with `ai-proxy`, it receives provider chunks as they are read. It must implement SSE framing/remainder handling because chunks may split events/tokens.
- Python core boundary: unresolved. Options include a small local RPC/Unix-socket service for privacy primitives (not a proxy), runner patch, or a Lua-native reimplementation/FFI bridge. This is a product/architecture decision after Phase 1 core is ready.

## 8. Later APISIX route/compose likely changes (not first milestone)

When Phase 0 hook is resolved, likely changes are:

- `apisix-plugin-example/init/configure_routes.py`
  - Replace catch-all `/*` route with two `POST` routes:
    - `/v1/chat/completions`
    - `/v1/responses`
  - Attach privacy plugin config and `ai-proxy` config.
  - Use `provider: "openai-compatible"`, `auth.header.Authorization: "Bearer <key>"`, and full `override.endpoint` per route.
  - Do not set `options.model` for normal proxying; model comes from request body.
  - Do not print provider auth or full route config once secrets are included.
  - Remove stale route id(s) or overwrite known ids safely.
- `apisix-plugin-example/compose.yaml`
  - Remove/disable `privacy-proxy` and local `upstream` from the AI path.
  - Keep APISIX + etcd; keep plugin-runner only if still needed for request decisions or Python bridge.
  - Add APISIX volume for native Lua plugin if selected; update `apisix/conf/config.yaml` to enable custom plugin if needed.
  - Provider endpoint/API key env should be passed only to init/config component unless APISIX needs runtime env directly.
  - Add `.env.example` with placeholders; root `.gitignore` already ignores `.env` (`.gitignore:17`).

Do not implement these before Phase 0 hook proof and secret-handling decisions.

## 9. Validation commands

Core first milestone:

```bash
cd /root/ai/ai-gateway-filter
uv run python scripts/prepare_spacy_model.py en_core_web_sm
uv run behave
uv run python -m compileall -q src/privacy_gateway
uv build --out-dir /tmp/ai-gateway-filter-build
```

If touching APISIX example Python files later:

```bash
uv run python -m compileall -q src/privacy_gateway \
  apisix-plugin-example/init \
  apisix-plugin-example/privacy_proxy \
  apisix-plugin-example/runner/apisix/plugins \
  apisix-plugin-example/upstream \
  apisix-plugin-example/tests
```

Current full APISIX demo integration (old behavior; likely obsolete after route changes):

```bash
podman compose -f apisix-plugin-example/compose.yaml up --build
podman compose -f apisix-plugin-example/compose.yaml run --rm integration-test
podman compose -f apisix-plugin-example/compose.yaml down -v
```

Phase 0 spike validation ideas:

- Create a minimal APISIX route with `ai-proxy` against a local echo/OpenAI-compatible stub or real gated provider and verify schema accepts `provider: openai-compatible`, `auth.header.Authorization`, and full `override.endpoint`.
- Add a tiny native Lua plugin proof that rewrites request JSON body before `ai-proxy` and modifies a non-streaming response body through `lua_body_filter`.
- Add a streaming SSE stub and prove `lua_body_filter` sees chunks and can change only semantic SSE `data` fields without buffering the entire stream.

## 10. Risky unknowns / decisions to escalate

1. **APISIX 3.16 Responses API support**: source indicates chat-completion-oriented parsing; `/v1/responses` may only be raw-forwarded via override endpoint, not first-class AI protocol. Decide whether to stay on 3.16 and implement privacy extraction independently, or move APISIX image version after verifying docs/schema.
2. **Python core boundary from Lua**: native Lua hooks likely solve APISIX phases, but Python core primitives are not directly callable from Lua. Need architecture decision for bridge (Unix socket RPC service, runner patch, Lua port, etc.). Do not reintroduce old provider proxy as the AI path.
3. **Streaming token assembler limits**: token length is variable; implementation needs bounded pending buffer without corrupting long valid tokens. Choose conservative max and failure/flush semantics.
4. **Legacy API compatibility**: existing tests/docs expect `check_text()` to mask token bodies and `process_inbound_privacy_text()` to fail on wrong password/tamper. New contract needs different behavior. Prefer additive APIs first.
5. **False positives in raw token text**: no-masking raw injection checks can match phrase-like text in ciphertext or fake token body. This is consistent with “current semantic content” but should be documented/tested enough to avoid surprise.
6. **OpenAI-compatible error contract**: `build_block_error()` is generic, not OpenAI-compatible. Leave for later gateway/APISIX error contract unless first milestone touches adapter errors.
7. **Provider secrets in route config**: APISIX Admin API stores route config including auth headers; later docs should note local example limitations or use APISIX secret refs if available.

## 11. Compact worker meta-prompt for first safe implementation milestone

Goal: Implement Phase 1 core-library direction-aware text primitives in `/root/ai/ai-gateway-filter` without changing APISIX routes/compose or adding any HTTP/proxy infrastructure.

Context/evidence:

- Contract requires outbound external text: raw injection check, preserve existing `<secret:1:...>` tokens, tokenize newly detected PII, no restore/normalize (`CONTEXT.md:31-37`).
- Contract requires inbound provider text: best-effort restore known tokens, preserve undecryptable tokens, raw injection check after restore/current text, no PII tokenization (`CONTEXT.md:39-41`).
- Current `PrivacyGatewayFilter.check_text()` checks raw and token-stripped candidates (`src/privacy_gateway/lib.py:393-404`); add a raw/no-mask check for new direction-specific APIs rather than breaking legacy callers unless tests are intentionally migrated.
- Current `process_inbound_privacy_text()` fails on any decrypt error (`src/privacy_gateway/lib.py:349-367`); new inbound provider API must not fail solely due undecryptable tokens.
- `PiiDetectionService.detect()` already excludes token ranges (`src/privacy_gateway/services/pii_detection.py:287-300`), and `SecretTokenService.encrypt_secret()`/`replace_spans()` are idempotent around tokens (`src/privacy_gateway/services/privacy_tokens.py:154-166`, `205-228`). Reuse these for outbound token preservation.
- Existing tests are Behave (`features/privacy_gateway.feature`, `features/steps/privacy_gateway_steps.py`); CI runs `uv run behave` and compileall.

Success criteria:

- New raw/no-mask injection check exists and new direction-aware APIs use it.
- Outbound external API blocks injection before tokenization; never restores existing tokens; does not double-tokenize token bodies; tokenizes newly detected PII.
- Inbound provider API restores decryptable tokens before injection check; preserves undecryptable structurally valid tokens and continues; does not tokenize plaintext provider PII.
- Streaming inbound token restorer exists with tests for split token restore, raw emission on decrypt failure, partial-token final flush, and prompt incremental output.
- Existing legacy APIs either keep passing existing tests or tests/docs are deliberately updated with clear backward-compatibility rationale.
- `src/privacy_gateway` remains framework/gateway-agnostic: no APISIX imports, no HTTP server, no route/provider config.

Suggested approach:

1. Add best-effort token restore and streaming token restorer in token/privacy text services.
2. Add additive `PrivacyGatewayFilter` methods with clear direction names (for example `check_text_raw`, `process_outbound_external_text`, `process_inbound_provider_text`, and a stream restorer factory). Keep old helpers unless intentionally migrating.
3. Export new public classes/methods as needed from `privacy_gateway.__init__`.
4. Add Behave scenarios/steps for the Phase 1 requirements; keep legacy scenarios intact where possible.
5. Do not touch `apisix-plugin-example/` in this milestone except possibly compileall if no files changed there.

Validation:

```bash
uv run python scripts/prepare_spacy_model.py en_core_web_sm
uv run behave
uv run python -m compileall -q src/privacy_gateway
uv build --out-dir /tmp/ai-gateway-filter-build
```

Stop/escalation rules:

- If choosing to change existing public helper semantics instead of adding new methods, stop and escalate because existing README/tests currently encode legacy behavior.
- If streaming restorer needs a max-token/window policy that can drop or corrupt valid tokens, document the tradeoff and escalate if not obvious.
- Stop after Phase 1 core/tests pass; do not start APISIX route/compose/native plugin work in this milestone.
