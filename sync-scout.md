# Code Context

## Files Retrieved

1. `/root/ai/ai-api-gateway/init/configure_routes.py` (lines 52-114) - new two-route APISIX topology and legacy route cleanup.
2. `/root/ai/ai-gateway-filter/apisix-plugin-example/init/configure_routes.py` (lines 52-87) - current single catch-all route through privacy proxy.
3. `/root/ai/ai-api-gateway/privacy_proxy/server.py` (lines 82-166, 332-479) - targeted `/v1/*` processing, pass-through behavior, and audit/observability additions.
4. `/root/ai/ai-gateway-filter/apisix-plugin-example/privacy_proxy/server.py` (lines 98-129, 295-350) - current all-path transform behavior.
5. `/root/ai/ai-api-gateway/runner/apisix/plugins/privacy_gateway_guard.py` (lines 23-50, 96-200) - audit-only additions around otherwise same guard decision path.
6. `/root/ai/ai-gateway-filter/apisix-plugin-example/runner/apisix/plugins/privacy_gateway_guard.py` (lines 93-117) - current guard decision path without audit.
7. `/root/ai/ai-api-gateway/tests/integration_test.py` (lines 61-130, 208-220) - tests updated for `/v1/*` processing and non-`/v1` pass-through.
8. `/root/ai/ai-gateway-filter/apisix-plugin-example/tests/integration_test.py` (lines 61-125, 204-215) - current all-path tests and marker-independent restore regression.
9. `/root/ai/ai-api-gateway/compose.yaml` (lines 26-55) - flattened build context and audit env vars; mostly excluded.
10. `/root/ai/ai-gateway-filter/apisix-plugin-example/compose.yaml` (lines 26-53) - example build context and no audit env vars.
11. `/root/ai/ai-api-gateway/runner/Dockerfile` (lines 21-27) - flattened COPY paths; excluded.
12. `/root/ai/ai-gateway-filter/apisix-plugin-example/runner/Dockerfile` (lines 21-27) - subdirectory COPY paths; excluded.
13. `/root/ai/ai-api-gateway/README.md` (lines 1-31, 111-151, 203-240, 379-419) - documents `/v1/*` routing, pass-through, image/audit sections, and two APISIX routes.
14. `/root/ai/ai-gateway-filter/apisix-plugin-example/README.md` (lines 1-26, 284-320) - documents current all-path route.

Also compared `/root/ai/ai-api-gateway/src` against `/root/ai/ai-gateway-filter/src` with `diff -ruN --exclude='__pycache__'`: no differences. The apparent `src/` additions in the directory-to-directory diff are because `apisix-plugin-example` uses the parent repo’s `src/` via Docker build context, not because the library implementation differs.

## Relevant File Mappings

| ai-api-gateway | apisix-plugin-example / parent mapping | Sync relevance |
|---|---|---|
| `init/configure_routes.py` | `apisix-plugin-example/init/configure_routes.py` | **Functional sync candidate**: route split and legacy route cleanup. |
| `privacy_proxy/server.py` | `apisix-plugin-example/privacy_proxy/server.py` | **Functional sync candidate**: only process `/v1/*`; pass through non-target paths. Omit audit/log-only parts. |
| `tests/integration_test.py` | `apisix-plugin-example/tests/integration_test.py` | **Test sync candidate**: endpoint paths and pass-through assertions. Be careful not to drop marker-independent restore coverage unless intended. |
| `README.md` | `apisix-plugin-example/README.md` | **Docs sync candidate** for behavior/route docs only; exclude enterprise audit/deployment-specific text. |
| `runner/apisix/plugins/privacy_gateway_guard.py` | same path under example | Mostly **do not sync**: differences are audit/log metadata, not filtering behavior. |
| `compose.yaml` | `apisix-plugin-example/compose.yaml` | Mostly **do not sync**: build context/network names and audit env vars are deployment/env-specific. |
| `runner/Dockerfile`, `privacy_proxy/Dockerfile`, `tests/Dockerfile` | same paths under example | **Do not sync flattened COPY paths**; example paths are correct for parent build context. |
| `src/privacy_gateway/**`, `pyproject.toml`, `scripts/prepare_spacy_model.py` | parent `/root/ai/ai-gateway-filter/src`, `/pyproject.toml`, `/scripts/prepare_spacy_model.py` | No functional library sync needed; parent repo already has matching source/script. |

## Key Code / Evidence

### 1. APISIX route topology changed from all-path proxying to `/v1/*` privacy processing + direct pass-through

Current example uses one catch-all route through the guard and privacy proxy:

- `/root/ai/ai-gateway-filter/apisix-plugin-example/init/configure_routes.py` lines 62-83: route name `privacy-gateway-proxy`, `uri: "/*"`, `ext-plugin-pre-req`, upstream `privacy-proxy:8080`.

ai-api-gateway uses two routes:

- `/root/ai/ai-api-gateway/init/configure_routes.py` lines 70-91: `privacy-gateway-proxy-v1`, `uri: "/v1/*"`, `priority: 100`, guard plugin, upstream `privacy-proxy:8080`.
- `/root/ai/ai-api-gateway/init/configure_routes.py` lines 93-103: `privacy-gateway-pass-through`, `uri: "/*"`, `priority: 1`, direct upstream `upstream:8081`.
- `/root/ai/ai-api-gateway/init/configure_routes.py` lines 52-56 and 105-114: best-effort delete of legacy route `privacy-gateway-proxy` before installing the new route names.

**Functional direction:** privacy handling is narrowed to API paths under `/v1/*`; everything else is transparent direct upstream pass-through.

### 2. Privacy proxy now mirrors that route scope internally

Current example always transforms inbound and outbound bodies:

- `/root/ai/ai-gateway-filter/apisix-plugin-example/privacy_proxy/server.py` lines 302-313: always calls `_transform_body(..., inbound=True)` and always forwards transformed body with `X-Privacy-Proxy: restored`.
- `/root/ai/ai-gateway-filter/apisix-plugin-example/privacy_proxy/server.py` lines 334-350: always transforms upstream response, sets `X-Privacy-Protection`, and sends transformed body.

ai-api-gateway adds target detection and conditional processing:

- `/root/ai/ai-api-gateway/privacy_proxy/server.py` lines 146-148: `_is_targeted_path()` returns `route_path.startswith("/v1/")`.
- `/root/ai/ai-api-gateway/privacy_proxy/server.py` lines 151-166: `_headers_for_upstream(..., is_target=...)` strips `X-Privacy-Encrypted` and adds `X-Privacy-Proxy: restored` only for targeted paths.
- `/root/ai/ai-api-gateway/privacy_proxy/server.py` lines 355-387: targeted paths are restored/checked; non-target paths use raw `incoming_body` unchanged.
- `/root/ai/ai-api-gateway/privacy_proxy/server.py` lines 428-467: targeted responses are checked/tokenized; non-target responses return raw `response_body` unchanged.

**Functional direction:** even if traffic reaches the proxy directly, non-`/v1/*` paths are transparent and do not get privacy headers/body transforms.

### 3. Tests changed to prove route scoping

ai-api-gateway tests now warm up and exercise `/v1/*`:

- `/root/ai/ai-api-gateway/tests/integration_test.py` lines 75-79: waits on `/v1/echo` and requires `X-Privacy-Protection`.
- `/root/ai/ai-api-gateway/tests/integration_test.py` lines 86-97: plaintext PII test moved to `/v1/echo`.
- `/root/ai/ai-api-gateway/tests/integration_test.py` lines 100-110: new non-`/v1` `/health` test asserts no `<secret:1:...>`, no `x-privacy-proxy`, no `x-privacy-protection`.
- `/root/ai/ai-api-gateway/tests/integration_test.py` lines 122-130: new `/v1/chat/completions` test asserts route processing works beyond `/v1/echo`.
- `/root/ai/ai-api-gateway/tests/integration_test.py` lines 210-220: includes new pass-through and `/v1` route checks.

Current example tests still assume all paths are privacy-processed:

- `/root/ai/ai-gateway-filter/apisix-plugin-example/tests/integration_test.py` lines 81-84: warmup uses `/echo` and only needs HTTP 200.
- `/root/ai/ai-gateway-filter/apisix-plugin-example/tests/integration_test.py` lines 92-104: plaintext PII test uses `/echo` and expects privacy proxy processing.
- `/root/ai/ai-gateway-filter/apisix-plugin-example/tests/integration_test.py` lines 204-215: no non-`/v1` pass-through or general `/v1/*` route test.

**Test caveat:** ai-api-gateway also changed `restore_response_text()` to assert `x-privacy-protection` before restoring (`tests/integration_test.py` lines 61-63), while the example intentionally has a marker-independent restore test (`apisix-plugin-example/tests/integration_test.py` lines 61-65 and 107-117). The token format is still self-describing; dropping that regression is not required by the route-scope behavior.

### 4. Runner plugin differences are audit/log-only, not filtering behavior

ai-api-gateway adds audit env/config and request metadata extraction:

- `/root/ai/ai-api-gateway/runner/apisix/plugins/privacy_gateway_guard.py` lines 23-50: `PRIVACY_AUDIT_LOG_ENABLED`, component name, `_audit()` writer.
- `/root/ai/ai-api-gateway/runner/apisix/plugins/privacy_gateway_guard.py` lines 96-114: best-effort method/path/body-size helpers for audit fields.
- `/root/ai/ai-api-gateway/runner/apisix/plugins/privacy_gateway_guard.py` lines 141-190: emits audit records on skipped/allowed/blocked decisions.

The actual block response path remains the same as the example:

- Example: `/root/ai/ai-gateway-filter/apisix-plugin-example/runner/apisix/plugins/privacy_gateway_guard.py` lines 101-117 checks text, builds `privacy_gateway_blocked`, sets status/header/body.
- ai-api-gateway: `/root/ai/ai-api-gateway/runner/apisix/plugins/privacy_gateway_guard.py` lines 167-200 performs the same check/block path with audit calls before it.

**Conclusion:** no non-log functional guard change to sync.

### 5. README documents the new behavior, but includes excluded enterprise/deployment content

Behavior docs worth syncing if route behavior is synced:

- `/root/ai/ai-api-gateway/README.md` lines 16-23: `/v1/*` gets privacy handling; other paths direct upstream.
- `/root/ai/ai-api-gateway/README.md` lines 206-223: manual non-target pass-through and `/v1` processing smoke tests.
- `/root/ai/ai-api-gateway/README.md` lines 379-419: two APISIX route examples.

Current example docs still describe all allowed traffic going through the privacy proxy and a single catch-all route:

- `/root/ai/ai-gateway-filter/apisix-plugin-example/README.md` lines 14-18 and 284-309.

Exclude from sync:

- `/root/ai/ai-api-gateway/README.md` lines 126-151: enterprise audit logging section.
- Flattened repository wording/layout, deployment-specific commands, and root-relative paths that do not fit `apisix-plugin-example`.

## Architecture

Current `apisix-plugin-example` architecture:

1. `init/configure_routes.py` creates one APISIX route `/*`.
2. All matching traffic runs `ext-plugin-pre-req` / `privacy-gateway-guard`.
3. All allowed traffic goes to `privacy-proxy`.
4. `privacy-proxy` restores tokens/checks inbound text and tokenizes/checks every upstream response.
5. Upstream only receives transformed/restored request bodies and sees `X-Privacy-Proxy: restored`.

ai-api-gateway architecture:

1. `init/configure_routes.py` creates a high-priority `/v1/*` privacy route and a low-priority `/*` direct upstream route.
2. Only `/v1/*` runs the APISIX external guard and privacy proxy.
3. Non-`/v1/*` bypasses both guard and proxy via APISIX and goes directly to upstream.
4. The proxy also contains defense-in-depth path gating, so direct or accidental non-target proxy requests are forwarded unchanged.

## Change Categories

### Functional behavior changes likely intended for sync

1. **Route scoping:** Change example from one `/*` privacy route to `/v1/*` privacy route plus `/*` direct pass-through route.
2. **Legacy route cleanup:** Delete old `privacy-gateway-proxy` route during init so persisted APISIX/etcd state does not keep the catch-all privacy route.
3. **Proxy target gating:** Add `_is_targeted_path()` and only run inbound/outbound privacy transforms for `/v1/*`.
4. **Transparent non-target behavior:** For non-target paths, preserve raw body, preserve legacy encryption marker header if traffic reaches proxy directly, do not add privacy headers, and return upstream response unchanged.
5. **Tests/docs for behavior:** Update tests/manual docs to use `/v1/*` for privacy processing and add non-`/v1` pass-through coverage.

### Excluded / non-functional / environment-specific changes

1. **Audit logging and request tracing:** `_audit()` functions, audit env vars, audit README section, body byte counts, request-id log metadata. User explicitly excluded logs/enterprise customization.
2. **Flattened repo deployment changes:** compose build contexts, network name `ai-api-gateway`, Dockerfile `COPY runner/...` paths, root-level layout wording.
3. **Generated artifacts:** `.venv`, `.pi`, `__pycache__`, `uv.lock`, diff noise from compiled `.pyc` files.
4. **Vendored core library files inside ai-api-gateway:** `src/privacy_gateway/**` is already identical to parent `/root/ai/ai-gateway-filter/src/privacy_gateway/**`; do not copy into `apisix-plugin-example/`.
5. **`pyproject.toml` and `scripts/prepare_spacy_model.py`:** already exist at `/root/ai/ai-gateway-filter/` parent level for the example build context; not an example-subdir sync.
6. **`.gitignore` and local validation/deployment docs:** not functional gateway behavior.

## What Should Sync

If the desired example behavior is to match ai-api-gateway’s `/v1/*`-only API gateway semantics, sync these pieces:

1. **`apisix-plugin-example/init/configure_routes.py`**
   - Add `_delete_legacy_route()` equivalent from ai-api lines 52-56.
   - Replace single `privacy-gateway-proxy` catch-all route with:
     - `privacy-gateway-proxy-v1`, `uri: "/v1/*"`, `priority: 100`, guard plugin, upstream `privacy-proxy:8080`.
     - `privacy-gateway-pass-through`, `uri: "/*"`, `priority: 1`, upstream `upstream:8081`.
   - Keep example-specific env var names and Admin API behavior.

2. **`apisix-plugin-example/privacy_proxy/server.py`**
   - Add `_is_targeted_path()` based on `/v1/`.
   - Update `_headers_for_upstream()` to accept `is_target`; only strip `X-Privacy-Encrypted` and add `X-Privacy-Proxy: restored` for targeted traffic.
   - In `_handle()`, branch inbound processing:
     - `/v1/*`: current restore/check behavior.
     - non-`/v1/*`: raw `incoming_body` to upstream.
   - Branch outbound processing:
     - `/v1/*`: current response check/tokenize and privacy headers.
     - non-`/v1/*`: raw upstream response, no privacy headers.
   - **Do not blindly copy audit/request-id code** unless separately requested.

3. **`apisix-plugin-example/tests/integration_test.py`**
   - Move privacy-processing tests from `/echo` to `/v1/echo` or another `/v1/*` path.
   - Add a non-target route test like ai-api `assert_non_v1_route_is_transparent()`.
   - Add a general `/v1/*` route test like `/v1/chat/completions` so the route is not hard-coded only to `/v1/echo`.
   - Keep or adapt the old marker-independent restoration regression unless the contract intentionally changed.

4. **`apisix-plugin-example/README.md`**
   - Update behavior overview and APISIX route section to describe `/v1/*` privacy processing plus non-target pass-through.
   - Update manual smoke tests to use `/v1/...` for privacy cases and add a non-target pass-through example.
   - Preserve example-relative paths/commands (`podman compose -f apisix-plugin-example/compose.yaml ...`) rather than ai-api root commands.

## What Should NOT Sync

1. **Audit/logging code and env vars**
   - Do not sync `_audit()` additions in `privacy_proxy/server.py` or `runner/apisix/plugins/privacy_gateway_guard.py` under this task’s exclusions.
   - Do not sync `PRIVACY_AUDIT_LOG_ENABLED` compose env vars from `/root/ai/ai-api-gateway/compose.yaml` lines 37 and 55.
   - Do not sync README enterprise audit section (`ai-api-gateway/README.md` lines 126-151).

2. **Flattening/deployment changes**
   - Do not sync `compose.yaml` build context changes from `context: ..` to `context: .`; the example is nested and currently needs the parent context (`apisix-plugin-example/compose.yaml` lines 27-29 and 43-45).
   - Do not sync Dockerfile `COPY runner/...` path changes; example Dockerfiles correctly use `COPY apisix-plugin-example/...` with parent build context (`apisix-plugin-example/runner/Dockerfile` lines 26-27).
   - Do not sync network name changes from `apisix-example` to `ai-api-gateway` unless renaming the example stack is separately desired.

3. **Core library/vendor files**
   - Do not add `src/` under `apisix-plugin-example`; the example intentionally builds from parent `/root/ai/ai-gateway-filter/src`, which matches ai-api-gateway `src`.
   - Do not add root `pyproject.toml` or `scripts/prepare_spacy_model.py` inside the example subdir; parent copies already satisfy Dockerfile lines 21-24.

4. **Generated/local artifacts**
   - Exclude `.pi`, `.venv`, `uv.lock`, `__pycache__`, `.pyc`, and other generated/build artifacts from sync.

5. **Potential test-contract regression**
   - Do not copy ai-api’s `restore_response_text()` helper change as-is if the example should keep demonstrating that `<secret:1:...>` restoration does not depend on `X-Privacy-Protection`.

## Open Questions

1. **Is `/v1/*` scoping the intended public behavior for the example?** Current example docs/tests advertise all-path transparent privacy proxying; ai-api-gateway narrows privacy processing to `/v1/*` and makes other paths direct pass-through.
2. **Should non-`/v1` traffic bypass the APISIX guard entirely?** The ai-api route split sends non-target traffic directly to upstream, so prompt-injection checks do not run on those paths.
3. **Should marker-independent restoration remain a documented/tested contract?** ai-api tests now require the marker header in the restore helper, but tokens are still self-describing and the old example explicitly tests header stripping.
4. **Should the proxy support configurable target prefixes instead of hard-coded `/v1/`?** ai-api hard-codes `route_path.startswith("/v1/")`; an example may want a config knob if it is reusable beyond OpenAI-style routes.
5. **Should direct requests to `privacy-proxy` for non-target paths be supported?** ai-api’s proxy pass-through handles this defensively, but APISIX normally routes non-target traffic directly to upstream after the route split.

## Start Here

Start with `apisix-plugin-example/init/configure_routes.py`. The route topology controls the main behavioral direction: whether privacy processing is all-path or only `/v1/*`. After deciding that, update `apisix-plugin-example/privacy_proxy/server.py` to match the same targeting semantics, then adjust integration tests and README docs.
