# Research: Apache APISIX 3.16 AI Gateway + external plugin capabilities for privacy-gateway

## Summary
The repository currently does **not** configure APISIX `ai-proxy`; all traffic is funneled through a custom `privacy-proxy` upstream and only uses `ext-plugin-pre-req` for early rejection. This means request/response body transformation and non-stream response rewriting are implemented in the sidecar, not in an APISIX plugin. For this stack, there is clear evidence of whole-body request/response processing in Python, but no evidence of SSE/chunk-safe mutation in the external-plugin path.

## Findings

1. **No `ai-proxy` route in current APISIX config.**
   The route bootstrap config created by `apisix-init` attaches only `ext-plugin-pre-req` and points upstream to `privacy-proxy:8080`; there is no `ai-proxy` plugin block or model-provider/OpenAI configuration in repo routes. [Source](apisix-plugin-example/init/configure_routes.py)

2. **Current route uses `ext-plugin-pre-req` first, then forwards to custom upstream proxy.**
   APISIX container is v3.16 (`apache/apisix:3.16.0-debian`), and the route is configured with `ext-plugin-pre-req` plus upstream `privacy-proxy`, indicating the Python runner executes before proxying to the sidecar. Integration tests expect 4xx rejections from the runner at APISIX edge. [Source](apisix-plugin-example/compose.yaml), [Source](apisix-plugin-example/init/configure_routes.py), [Source](apisix-plugin-example/tests/integration_test.py)

3. **`ext-plugin-pre-req` can inspect request body in this implementation, but Python runner-side response filtering is intentionally split out.**
   The custom plugin reads full request content via `request.get_body()` and can terminate/rewrite the client response using `response.set_status_code` / `response.set_body`, but APISIX plugin-runner example explicitly states the stable public API is for fast request inspection and not simple request/response body rewrite, which is why a separate privacy proxy sidecar is used for transformations. [Source](apisix-plugin-example/runner/apisix/plugins/privacy_gateway_guard.py), [Source](apisix-plugin-example/README.md)

4. **Response mutation is currently whole-body, non-streaming.**
   `privacy-proxy/server.py` reads the upstream response via `upstream_response.read()` into memory, parses/transforms via `_transform_body()`, then sends one complete response payload. This cannot preserve per-chunk behavior for SSE/streaming outputs, and it forces buffering of full responses. [Source](apisix-plugin-example/privacy_proxy/server.py)

5. **SSE and streaming-safe reverse/forward filtering are not currently handled by ext-plugin stage.**
   The proxy determines `response_was_json` and forces one-shot body transformation with `_is_json_body` + `_transform_body`; there is no incremental parsing, no chunk callbacks, and no streaming flush logic. So SSE chunk mutation would need additional design (e.g., native streaming hook at APISIX/Nginx layer). [Source](apisix-plugin-example/privacy_proxy/server.py)

## Sources
- **Kept: APISIX example route bootstrap** — `apisix-plugin-example/init/configure_routes.py` (shows only `ext-plugin-pre-req` plugin + custom upstream, proves current setup and phase shape).
- **Kept: APISIX runtime composition** — `apisix-plugin-example/compose.yaml` (shows APISIX 3.16 image and service wiring).
- **Kept: Python ext-plugin guard code** — `apisix-plugin-example/runner/apisix/plugins/privacy_gateway_guard.py` (shows what ext-plugin-pre-req receives/does, and confirms request-body-based checks).
- **Kept: Project integration rationale** — `apisix-plugin-example/README.md` (explicitly states stable public Python runner API is for request decisions, not stable body rewrite; explains why sidecar handles transformation).
- **Kept: Sidecar processing path** — `apisix-plugin-example/privacy_proxy/server.py` (shows complete-buffer request/response transformation logic).
- **Kept: Behavioral assertions** — `apisix-plugin-example/tests/integration_test.py` (validates runner-block and proxy-block behavior, implying runner-first edge rejection).
- **Dropped: Apache APISIX official docs for `ai-proxy` / `ext-plugin-*` / body filter phases** — unable to fetch from internet in this environment; no remote doc content retrieval tool was available for this run. (To be added once network docs access is available.)

## Gaps
- No authoritative APISIX 3.16 docs were fetched locally, so exact `ai-proxy` schema for OpenAI-compatible custom endpoints (`provider`, `path`, `auth`, streaming flags, etc.) is **not confirmed** here.
- No verified source was retrievable for exact `ext-plugin-pre-req` vs `ext-plugin-post-resp` execution order relative to `ai-proxy` when both are used together in one route.
- No verified proof of APISIX runner/SDK methods for request-body mutation (`set_body`/`set_ctx`) or response-body mutation in `ext-plugin-post-resp` from upstream docs.
- SSE-specific APISIX behavior (native chunking hooks, proxy buffering, and interaction with plugin phases) was not validated from official source in this pass.

## Supervisor coordination
I already escalated tool-limited evidence constraints and received guidance to proceed with local-source-backed findings and explicitly flag unknowns instead of inventing facts. No further coordination required.
