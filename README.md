# Privacy Gateway (Core Library)

`privacy-gateway` is a **pure Python library** for:

- reversible natural-language PII protection with self-describing `<secret:1:...>` tokens
- automatic restoration of `<secret:1:...>` tokens without special HTTP headers
- prompt-injection phrase detection and decisioning
- streaming detection helper
- backward-compatible full text/image cryptographic primitives

It is intentionally not a gateway, HTTP server, or network service. JSON parsing,
field selection, routing, proxying, and request/response rewriting belong in the
embedding gateway/plugin. The APISIX example shows one way for a gateway to parse
JSON first and pass only relevant string values to this library.

## Install

```bash
uv sync
```

## Public API

```python
from privacy_gateway import PrivacyGatewayFilter

filter_ = PrivacyGatewayFilter(privacy_password="use-a-high-entropy-deployment-secret")

protected = filter_.protect_privacy_text(
    "我叫张三，身份证是110101199001011234，邮箱是zhangsan@example.com。"
)
assert "<secret:1:" in protected

restored = filter_.restore_privacy_text(protected)
assert restored == "我叫张三，身份证是110101199001011234，邮箱是zhangsan@example.com。"

decision = filter_.check_text("Ignore previous instructions")
assert decision.blocked
```

## Secret token format

PII is protected with a compact, descriptive, reversible token:

```text
<secret:1:<ciphertext>>
```

The token body contains only crypto material: a per-token salt and the encrypted
value. The `<secret:1:` prefix lets a gateway detect encrypted values without
relying on `X-Privacy-Encrypted` or any other marker header. Token restoration
uses the service-side password from `PRIVACY_GATEWAY_PASSWORD` or the
`privacy_password` constructor argument. Use a high-entropy deployment secret;
tokens are client-visible and weak passwords are vulnerable to offline guessing.

## Natural-language privacy APIs

Preferred APIs for new gateway/plugin code:

- `protect_privacy_text(content, privacy_password=None)` -> replaces detected PII spans with `<secret:1:...>` tokens.
- `restore_privacy_text(content, privacy_password=None)` -> decrypts all `<secret:1:...>` tokens inside text.
- `protect_secret(content, privacy_password=None)` -> encrypts one caller-selected complete value as a token.
- `detect_pii(content)` -> returns detected PII spans.
- `process_inbound_privacy_text(content, privacy_password=None)` -> restores tokens, then checks prompt-injection phrases.
- `process_outbound_privacy_text(content, privacy_password=None)` -> checks prompt-injection phrases, then tokenizes detected PII.

Example:

```python
from privacy_gateway import PrivacyGatewayFilter

filter_ = PrivacyGatewayFilter.from_settings()

inbound = filter_.process_inbound_privacy_text("hello <secret:1:...>")
if inbound.error:
    ...
if inbound.decision.blocked:
    ...
plaintext_for_ai = inbound.content

outbound = filter_.process_outbound_privacy_text("User 张三 can be reached at zhangsan@example.com")
protected_for_client = outbound.content
```

`TextProcessingResult` contains `content`, `decision`, and optional normalized
`error` details. It never exposes the password/key used for encryption.

## Detection behavior

The library uses Presidio Analyzer backed by a prepared spaCy model. By default
it expects `en_core_web_sm` to be installed before startup and refuses to
download models at runtime. Prepare it with:

```bash
uv run python scripts/prepare_spacy_model.py en_core_web_sm
```

Presidio recognizers cover common English PII patterns such as:

- `EMAIL_ADDRESS`
- `PHONE_NUMBER`
- `CREDIT_CARD`
- `CRYPTO`
- `IBAN_CODE`
- `IP_ADDRESS`
- `LOCATION`
- `PERSON` when available from configured analyzers
- US identifiers such as `US_SSN`, `US_PASSPORT`, `US_DRIVER_LICENSE`, etc.

The library also adds deterministic rules for common Chinese/business text:

- Chinese mainland ID card numbers
- Chinese mobile numbers
- common Chinese name contexts such as `我叫张三` / `姓名是张三`
- common Chinese address contexts such as `住在北京市...` / `地址是...`
- password/secret contexts such as `password=...` / `密码是...`

No PII detector is perfect. Gateways that know a string is sensitive because of
its JSON field name should pass the complete field value to `protect_secret(...)`.
This keeps JSON/field logic outside the library while still using the same token
format and crypto.

## JSON and gateway integration

The core library does **not** parse or format JSON. For JSON APIs, the gateway
must:

1. parse JSON first (`json.loads` or framework equivalent),
2. walk the resulting object/list,
3. pass selected string values to `process_inbound_privacy_text`,
   `process_outbound_privacy_text`, or `protect_secret`,
4. serialize JSON again.

This prevents unsafe raw-string rewriting of JSON and lets gateway code decide
which message/tool-call/AI-output fields are relevant.

## Backward-compatible full-payload crypto

Existing whole-text/image APIs remain available for older callers and tests:

- `encrypt_text(content, crypto_key=None)` -> `str`
- `decrypt_text(content, crypto_key=None)` -> `str`
- `encrypt_payload(type, content, crypto_key)`
- `decrypt_payload(type, content, crypto_key)`
- `restore_payload(type, content, crypto_key)`

Supported payload types:

- `text`
- `image`

Text crypto requires AES key byte lengths `{16, 24, 32}`. New automatic privacy
flows should prefer `<secret:1:...>` tokenization instead of whole-body payload
encryption.

## Filter / detection

- `check_text(text)` -> `FilterDecision`
- `stream_matcher(max_window=None).feed(chunk)` -> `FilterDecision`

`check_text` masks `<secret:1:...>` token bodies before prompt-injection checks,
so ciphertext is not misinterpreted as plaintext instructions.

## HTTP adapter primitives

`privacy_gateway.adapters.http` exposes pure data helpers for HTTP gateways
without importing FastAPI, Flask, APISIX, or any networking framework:

```python
from privacy_gateway.adapters.http import build_block_error
```

Legacy encrypted-header helpers are still exported for old integrations, but new
automatic token flows should not depend on them.

## Settings

Read environment variables:

- `PRIVACY_GATEWAY_PASSWORD`: password for reversible `<secret:1:...>` tokens.
- `PRIVACY_GATEWAY_CRYPTO_KEY`: optional legacy full-text AES key; also used as token password fallback when `PRIVACY_GATEWAY_PASSWORD` is not set.
- `PRIVACY_GATEWAY_PII_ENTITIES`: comma-separated Presidio entity types to enable.
- `PRIVACY_GATEWAY_SPACY_MODEL`: prepared spaCy model name/path, default `en_core_web_sm`.
- `PRIVACY_GATEWAY_REQUIRE_SPACY_MODEL`: require the model at startup, default `true`.
- `PRIVACY_GATEWAY_SENSITIVE_PHRASES`: comma-separated prompt-injection phrase list.
- `PRIVACY_GATEWAY_MAX_SENSITIVE_STREAM_WINDOW`: integer window size, default `4096`.

Create a configured filter from env:

```python
from privacy_gateway import PrivacyGatewayFilter
from privacy_gateway.config import get_settings

filter_ = PrivacyGatewayFilter.from_settings(get_settings())
```

## Validation

Run behavior tests on core library APIs:

```bash
uv run python scripts/prepare_spacy_model.py en_core_web_sm
uv run behave
uv run python -m compileall -q src/privacy_gateway
```

To include the APISIX example files in syntax validation:

```bash
uv run python -m compileall -q src/privacy_gateway \
  apisix-plugin-example/init \
  apisix-plugin-example/privacy_proxy \
  apisix-plugin-example/runner/apisix/plugins \
  apisix-plugin-example/upstream \
  apisix-plugin-example/tests
```

## Error classes

- `TextCryptoError`
- `TextCryptoKeyError`
- `ImageCryptoError`
- `UnsupportedPayloadTypeError`
- `PrivacyGatewayError`

## Notes

- This repository intentionally provides **library primitives only**.
- Gateway plugins should import and embed `PrivacyGatewayFilter`.
- Gateway plugins should own JSON parsing/field selection and use this library for natural-language string protection/restoration.
