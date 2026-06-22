# APISIX AI Gateway Privacy Plugin implementation plan

## Goal

Turn `apisix-plugin-example/` into a usable APISIX AI proxy gateway for real OpenAI-compatible provider traffic while preserving the project's security-boundary privacy contract:

- supported agent/action endpoints: `/v1/chat/completions` and `/v1/responses`
- outbound internal -> external provider: injection check, then reversible tokenization of Semantic Content; never restore/normalize outbound tokens
- inbound external provider -> internal: best-effort token restore/normalize, then injection check; never PII-tokenize inbound provider text
- streaming responses are supported
- core library remains injection-checking and secret-guarding primitives, not routing/proxy infrastructure

## Key design constraints from `CONTEXT.md`

- Use APISIX AI Gateway components for routing/provider proxying; do not replace `ai-proxy` with a hand-written proxy sidecar.
- Keep a single APISIX Privacy Plugin as glue. Direction-specific behavior lives in code paths, not separate plugins.
- The plugin processes only Semantic Content, including system/developer/user/assistant content, tool/function-call arguments, prompts, and inline/base64/data URL image content.
- The plugin never processes protocol/control fields, tool schemas, tool/function names, or `tools[].function.description`.
- Embeddings, image generation, files API, arbitrary `/v1/*`, and remote image downloading are out of scope.
- Unknown maybe-semantic structures on supported endpoints fail closed.
- Errors should be OpenAI-compatible where a normal HTTP error can still be sent.

## Phase 0 — APISIX capability spike

Before writing the full implementation, verify the APISIX integration hook can actually transform what we need:

1. Confirm the APISIX image used by the example includes `ai-proxy` and any needed AI Gateway plugins.
2. Confirm route schema for the real provider endpoint:
   - provider value for OmniRoute/OpenAI-compatible endpoint (`openai` + `override.endpoint` vs `openai-compatible`, depending on APISIX schema)
   - endpoint should be the full chat/responses URL or derived from base URL safely
3. Confirm the Python external plugin runner can mutate:
   - request body before `ai-proxy`
   - non-streaming response body after `ai-proxy`
   - streaming SSE response chunks after `ai-proxy`
4. If the Python runner cannot mutate response chunks/SSE, do not resurrect the old proxy sidecar. Use the smallest APISIX plugin strategy that can run in the right phase and call the privacy primitives, likely a native APISIX/Lua body-filter bridge plus Python/core-lib boundary only if necessary.

Exit criteria: a documented hook choice for request rewrite, non-streaming response rewrite, and streaming SSE rewrite.

## Phase 1 — Core library direction-aware primitives

Add primitives to `src/privacy_gateway` without adding routing, HTTP server, or provider logic.

Likely API additions:

- raw injection check that does not mask `<secret:1:...>` tokens before checking
- outbound semantic text processing:
  - injection check on current text
  - preserve existing tokens unchanged
  - reversible PII tokenization for newly detected sensitive values
  - no restore/normalize
- inbound semantic text processing:
  - best-effort restore known tokens
  - undecryptable structurally valid tokens remain unchanged
  - injection check after restore
  - no PII tokenization
- streaming inbound token restorer:
  - sliding-window assembler for `<secret:1:...>` token fragments
  - emits restored text incrementally
  - emits raw token text when decrypt fails
  - can be reused by non-streaming processing for consistent restore semantics

Tests:

- outbound blocks injection before tokenization
- outbound never restores existing tokens
- outbound does not double-tokenize token bodies
- inbound restores decryptable tokens before injection check
- inbound preserves undecryptable tokens and continues
- inbound does not tokenize provider-generated plaintext PII
- injection checks do not use token masking as a pre-check step

## Phase 2 — Semantic extractors/rewriters for OpenAI-compatible agent APIs

Implement pure data transformation code in the APISIX plugin layer, not as generic route infrastructure.

Supported request extractors:

- `/v1/chat/completions`
  - message content strings and content arrays
  - system/developer/user/assistant message content
  - inline/base64/data URL image content in message content arrays
  - tool/function-call arguments where they are semantic values
  - exclude role, model, stream, temperatures, tool schema, function name, `tools[].function.description`
- `/v1/responses`
  - `instructions` and input text content
  - output/input item content that is semantically text or inline image content
  - function-call arguments and tool output content where relevant
  - exclude ids, status, model, tool schema/name/description, metadata/control fields

Supported response extractors:

- non-streaming chat completions: assistant message content and tool-call/function arguments
- non-streaming responses: output text/content and function-call argument semantic fields
- streaming chat completions: `choices[*].delta.content`, `choices[*].delta.tool_calls[*].function.arguments`
- streaming responses: `response.output_text.delta`, `response.function_call_arguments.delta`, and equivalent output/message content deltas

Unknown maybe-semantic structure on supported endpoints fails closed. Clearly non-semantic metadata passes through.

## Phase 3 — Single APISIX Privacy Plugin

Replace the current example plugin behavior with one plugin that has explicit direction handlers:

- outbound handler:
  - runs before `ai-proxy`
  - parses full JSON request body
  - applies endpoint-specific semantic extractor
  - calls core outbound primitives
  - writes transformed JSON body back for `ai-proxy`
- inbound non-stream handler:
  - runs after provider response
  - applies endpoint-specific response extractor
  - uses the same streaming-compatible restore logic internally
  - injection-checks the complete restored semantic answer before returning body
- inbound streaming handler:
  - transforms only semantic SSE deltas
  - restores token fragments incrementally with sliding window
  - forwards restored chunks promptly
  - buffers complete semantic answer for post-completion injection check
  - on injection failure after stream starts, emits stream-level error/final error event and closes

Important: if APISIX Python runner cannot handle any required phase, implement that phase with an APISIX-native hook rather than reintroducing `privacy_proxy` as a provider proxy.

## Phase 4 — Route and compose changes

Update `apisix-plugin-example/init/configure_routes.py`:

- create routes for:
  - `POST /v1/chat/completions`
  - `POST /v1/responses`
- configure APISIX `ai-proxy` to the real OpenAI-compatible provider endpoint from env
- configure the APISIX Privacy Plugin in the needed pre/post phases
- remove stale route IDs from older catch-all/proxy-sidecar versions
- never print provider auth secrets or full route config containing secrets
- do not configure a gateway-level model; model comes from request body

Update `apisix-plugin-example/compose.yaml`:

- keep APISIX, etcd, plugin-runner if the selected plugin hook requires it
- remove or disable `privacy-proxy` and local echo `upstream` from the AI path
- pass provider endpoint/API-key env only to the init/config component that writes APISIX route config, unless APISIX needs runtime env directly
- keep `.env` ignored and add `.env.example` with placeholders only

Update APISIX config only as needed for plugin runner / AI Gateway plugin availability.

## Phase 5 — Tests and validation

Core/unit tests:

- direction-aware core primitives
- semantic extractors for chat completions and responses
- streaming token assembler edge cases
- unknown semantic structure fail-closed behavior

Local syntax/config checks:

- `uv run python -m compileall -q src/privacy_gateway apisix-plugin-example/init apisix-plugin-example/runner apisix-plugin-example/tests`
- APISIX route creation should fail clearly when env vars are missing, without echoing values

Real-provider integration tests, gated by env:

- non-streaming `/v1/chat/completions` happy path with request body model set by caller
- non-streaming `/v1/responses` happy path if provider supports it
- streaming chat completions happy path
- streaming responses happy path if provider supports it
- outbound injection rejection before provider call
- transparent token round-trip scenario where feasible: prompt asks model to echo a tokenized sensitive value, gateway restores it inbound

Security checks:

- no real API key committed
- init logs do not print provider auth headers
- APISIX Admin API exposure and route config secret storage documented as example limitations or hardened if feasible

## Phase 6 — Documentation

Update `apisix-plugin-example/README.md` to describe:

- functional APISIX AI proxy gateway, not mock-only demo
- supported endpoints and unsupported endpoints
- direction rules for outbound/inbound processing
- streaming behavior and stream-level error semantics
- env setup using `.env.example` placeholders
- real-provider smoke tests and cost/flakiness caveats

Update root docs only where they describe the example contract or core library APIs.

## Main risks

- APISIX Python runner may not support response/SSE mutation; this must be proven before implementation commits to the hook.
- APISIX `ai-proxy` route schema for custom OpenAI-compatible endpoints may differ from the assumed config.
- Streaming post-completion injection detection cannot change HTTP status once chunks are sent; stream-level error semantics must be tested against real clients.
- Existing `check_text()` masks tokens before checking; new direction-specific checks must avoid that behavior.
- Real-provider tests can be slow, flaky, or billable; keep them opt-in/gated.
