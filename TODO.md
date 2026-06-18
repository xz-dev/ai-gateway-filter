# TODO

## Implementation status

Implemented in the core library and synchronized with `apisix-plugin-example`:

- [x] Key-hiding `encrypt_text` / `decrypt_text` APIs
- [x] `process_inbound_text` decrypt-and-check helper
- [x] `process_outbound_text` check-and-encrypt helper
- [x] Environment-backed `PrivacyGatewaySettings.crypto_key`
- [x] Framework-free `privacy_gateway.adapters.http` helpers
- [x] Automatic image-region protection with OCR-detected boxes, hash cache restoration, and low-resolution fallback

## Library API improvements discovered while wiring `apisix-plugin-example`

### 1. Add a proxy-oriented text crypto API that does not echo the key

- **Reason:** `PrivacyGatewayFilter.encrypt_payload(...)` and `decrypt_payload(...)` return `CryptoOperationResult(type, content, crypto_key)`. That is convenient for library round-trip tests, but proxy/plugin code should avoid carrying or accidentally logging the key in result objects.
- **Proposed API change:** Add key-hiding convenience methods for gateway/proxy integrations.
- **Desired API shape:**

  ```python
  encrypted: str = filter_.encrypt_text(content, crypto_key)
  plaintext: str = filter_.decrypt_text(encrypted, crypto_key)
  ```

  Keep `encrypt_payload` / `decrypt_payload` for backwards compatibility, but document the new text-specific methods as preferred for HTTP proxy code.

### 2. Add a combined decrypt-and-check helper for inbound gateway traffic

- **Reason:** The APISIX privacy proxy has to manually branch on encrypted/plaintext input, call `decrypt_payload`, normalize errors, and then call `check_text`. This boilerplate is easy to repeat incorrectly in every gateway adapter.
- **Proposed API change:** Add a helper that accepts text plus metadata indicating whether it is encrypted, then returns plaintext and a filter decision.
- **Desired API shape:**

  ```python
  result = filter_.process_inbound_text(
      content,
      crypto_key=crypto_key,
      encrypted=True,
  )
  if result.decision.blocked:
      ...
  clean_plaintext = result.content
  ```

  The result should include `content`, `decision`, and optional normalized error details without exposing `crypto_key`.

### 3. Add a combined check-and-encrypt helper for outbound gateway traffic

- **Reason:** Reverse-injection protection needs the same repeated sequence in proxy adapters: inspect upstream plaintext, block if matched, encrypt successful output, and set response metadata.
- **Proposed API change:** Add an outbound helper for response bodies.
- **Desired API shape:**

  ```python
  result = filter_.process_outbound_text(
      upstream_text,
      crypto_key=crypto_key,
      encrypt=True,
  )
  if result.decision.blocked:
      ...
  encrypted_response = result.content
  ```

  This would make reverse-injection protection a first-class library workflow rather than adapter boilerplate.

### 4. Add environment-backed crypto-key settings

- **Reason:** `PrivacyGatewaySettings` currently covers sensitive phrases and stream-window configuration, but not a crypto key. The example therefore has to read `PRIVACY_GATEWAY_CRYPTO_KEY` itself in every sidecar/plugin process.
- **Proposed API change:** Extend settings with an optional `crypto_key` read from environment.
- **Desired API shape:**

  ```python
  settings = get_settings()
  settings.crypto_key  # None or configured string
  filter_ = PrivacyGatewayFilter.from_settings(settings)
  ```

  Crypto methods should still accept an explicit key so applications can use per-tenant keys, but settings support would simplify single-key gateway deployments.

### 5. Provide stable HTTP adapter primitives without making the core library an HTTP server

- **Reason:** The project intentionally stays gateway-agnostic, but every gateway adapter still needs consistent HTTP error payloads, header names, encrypted-body markers, and block status mapping. Reimplementing these details in APISIX/Envoy/Nginx adapters can cause drift.
- **Proposed API change:** Add a small optional adapter module that exposes pure data helpers, not a server framework.
- **Desired API shape:**

  ```python
  from privacy_gateway.adapters.http import (
      DEFAULT_ENCRYPTED_HEADER,
      build_block_error,
      is_encrypted_request,
  )
  ```

  These helpers should return plain dictionaries/dataclasses and avoid importing FastAPI, Flask, APISIX, or any networking framework.

## Image privacy refactor decision

- **Decision:** The library should not expose a whole-image encryption workflow. Image privacy means detecting sensitive image/OCR regions and protecting only those rectangles.
- **Current behavior:** `protect_image(...)` and `encrypt_payload("image", ...)` run image-region detection, redact only detected boxes, and embed restoration metadata. `restore_image(...)` / `decrypt_payload("image", ...)` restore boxes by hash-cache hit or encrypted low-resolution fallback.
- **Cache contract:** Full-quality encrypted crops are keyed by SHA-256 hash in a process-local LRU cache with a max size of 1000. Cache miss falls back to the low-resolution encrypted crop stored in PNG metadata.
- **Failure policy:** Detection failures fail closed with `ImageCryptoError`; successful detection with no regions returns the original image unchanged.
- **Runtime requirement:** `presidio-image-redactor` is now a dependency, and deployments need the OCR runtime expected by that package (Tesseract in the example containers).
