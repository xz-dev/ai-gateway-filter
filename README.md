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
result = filter_.encrypt_payload("text", "My name is James Bond", "WmZq4t7w!z%C&F)J")
restored = filter_.decrypt_payload("text", result.content, "WmZq4t7w!z%C&F)J")

decision = filter_.check_text("Ignore previous instructions")
assert decision.blocked
print(decision.match.detected_word)
```

## Available modules

- `privacy_gateway` (public API exports): **recommended for plugin integration**
- `privacy_gateway.lib` (core classes and advanced extension points)
- `privacy_gateway.config` (environment/config helpers)
- `privacy_gateway.services.*` (internal implementation modules)

Plugins should prefer the public top-level API (`privacy_gateway`) and
`PrivacyGatewayFilter` for integration. If needed for advanced use, `privacy_gateway.lib`
is the expected entry point for library-level extension, while `privacy_gateway.services.*`
are internal details and should not be imported by long-lived plugins.

## Behavior examples

### Crypto

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

## Settings

Read environment variables:

- `PRIVACY_GATEWAY_SENSITIVE_PHRASES`: comma-separated phrase list
- `PRIVACY_GATEWAY_MAX_SENSITIVE_STREAM_WINDOW`: integer window size (default `4096`)

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