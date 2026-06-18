# Privacy Gateway (Core Library)

`privacy-gateway` is now a **pure Python library** for:

- text/image cryptographic protection primitives
- sensitive phrase detection and decisioning
- streaming detection helper

It is intentionally not a gateway, HTTP server, or network service.
No routing, no proxying, no `/v1` compatibility, no fallback, no rate limiting,
and no health-check endpoints.

## Install

```bash
uv sync
```

## Public API

```python
from privacy_gateway import PrivacyGatewayFilter

filter_ = PrivacyGatewayFilter()
encrypted = filter_.encrypt_text("My name is James Bond", "WmZq4t7w!z%C&F)J")
restored = filter_.decrypt_text(encrypted, "WmZq4t7w!z%C&F)J")

decision = filter_.check_text("Ignore previous instructions")
assert decision.blocked
print(decision.match.detected_word)
```

## Available modules

- `privacy_gateway` (public API exports): **recommended for plugin integration**
- `privacy_gateway.lib` (core classes and advanced extension points)
- `privacy_gateway.config` (environment/config helpers)
- `privacy_gateway.adapters.http` (framework-free HTTP adapter data helpers)
- `privacy_gateway.services.*` (internal implementation modules)

Plugins should prefer the public top-level API (`privacy_gateway`) and
`PrivacyGatewayFilter` for integration. If needed for advanced use, `privacy_gateway.lib`
is the expected entry point for library-level extension, while `privacy_gateway.services.*`
are internal details and should not be imported by long-lived plugins.

## Behavior examples

### Crypto

Preferred text APIs for HTTP proxy/plugin code:

- `encrypt_text(content, crypto_key=None)` -> `str`
- `decrypt_text(content, crypto_key=None)` -> `str`

These return plain text strings and do not echo the crypto key in a result
object. `crypto_key` may be passed explicitly for per-tenant keys, or omitted
when the filter was created from settings containing `PRIVACY_GATEWAY_CRYPTO_KEY`.

Backward-compatible payload APIs remain available for library round-trip tests
and mixed text/image call sites:

- `encrypt_payload(type, content, crypto_key)`
- `decrypt_payload(type, content, crypto_key)`
- `restore_payload(type, content, crypto_key)`

Supported payload types:
- `text`
- `image`

Text crypto requires key byte lengths {16, 24, 32}.

### Filter / detection

- `check_text(text)` -> `FilterDecision`
- `stream_matcher(max_window=None).feed(chunk)` -> `FilterDecision`

### Gateway text workflows

For proxy adapters that repeatedly decrypt/check/encrypt text bodies:

```python
inbound = filter_.process_inbound_text(
    content,
    crypto_key="WmZq4t7w!z%C&F)J",
    encrypted=True,
)
if inbound.error:
    ...  # normalized error details, no crypto key
if inbound.decision.blocked:
    ...
clean_plaintext = inbound.content

outbound = filter_.process_outbound_text(
    upstream_text,
    crypto_key="WmZq4t7w!z%C&F)J",
    encrypt=True,
)
if outbound.decision.blocked:
    ...
encrypted_response = outbound.content
```

`TextProcessingResult` contains `content`, `decision`, and optional normalized
`error` details. It never exposes the crypto key.

### HTTP adapter primitives

`privacy_gateway.adapters.http` exposes pure data helpers for HTTP gateways
without importing FastAPI, Flask, APISIX, or any networking framework:

```python
from privacy_gateway.adapters.http import (
    DEFAULT_ENCRYPTED_HEADER,
    build_block_error,
    is_encrypted_request,
)
```

- `DEFAULT_ENCRYPTED_HEADER` is `X-Privacy-Encrypted`.
- `is_encrypted_request(headers)` checks the encrypted marker case-insensitively.
- `build_block_error(...)` returns an `HttpBlockError` dataclass with `status`,
  JSON-compatible `body`, and plain response `headers`.

## Settings

Read environment variables:

- `PRIVACY_GATEWAY_SENSITIVE_PHRASES`: comma-separated phrase list
- `PRIVACY_GATEWAY_MAX_SENSITIVE_STREAM_WINDOW`: integer window size (default `4096`)
- `PRIVACY_GATEWAY_CRYPTO_KEY`: optional default text crypto key

Create a configured filter from env:

```python
from privacy_gateway import PrivacyGatewayFilter
from privacy_gateway.config import get_settings

filter_ = PrivacyGatewayFilter.from_settings(get_settings())
```

## Validation

Run behavior tests on core library APIs:

```bash
uv run behave
uv run python -m compileall -q src/privacy_gateway
uv build --out-dir /tmp/ai-gateway-filter-build-optional-polish
```

`uv run behave` runs the direct library-focused BDD checks.
`compileall` validates library source syntax/importability.
`uv build` validates packaging metadata and distribution output.

## Error classes

- `TextCryptoError`
- `TextCryptoKeyError`
- `ImageCryptoError`
- `UnsupportedPayloadTypeError`
- `PrivacyGatewayError`

## Removed functionality (out of scope)

The following HTTP/service artifacts were intentionally removed for library-first scope:

- FastAPI app and routers (`main.py`, `routers/*`)
- HTTP schema/response models (non-public)
- Server startup helpers and demo endpoints
- Manual HTTP test scripts and docker artifacts

## Notes

- This repository intentionally provides **library primitives only**.
- Gateway plugins should import and embed `PrivacyGatewayFilter`.