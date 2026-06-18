# Privacy Gateway (Core Library)

This repository is a pure importable Python library for privacy filtering and
crypto primitives. It intentionally has no HTTP server, router, FastAPI, or
proxy/routing responsibilities. HTTP integration support is limited to pure data
adapter helpers, not a runnable server or framework binding.

## Scope

- text encryption/decryption and automatic sensitive image-region protection/restoration
- sensitive phrase detection and filtering decisions
- streaming detection helper
- optional environment-derived defaults
- framework-free HTTP adapter data helpers

## Notes

Use `privacy_gateway` (top-level package exports) as the recommended public integration entry for plugins.
`privacy_gateway.lib` exposes core classes and extension points for advanced use.
`privacy_gateway.services.*` are internal implementation modules and are not intended as a stable plugin integration surface.

## Public behavior

- `PrivacyGatewayFilter.encrypt_text`
- `PrivacyGatewayFilter.decrypt_text`
- `PrivacyGatewayFilter.protect_image`
- `PrivacyGatewayFilter.restore_image`
- `PrivacyGatewayFilter.encrypt_payload` (`image` payloads protect detected regions only; there is no whole-image encryption workflow)
- `PrivacyGatewayFilter.decrypt_payload`
- `PrivacyGatewayFilter.restore_payload`
- `PrivacyGatewayFilter.process_inbound_text`
- `PrivacyGatewayFilter.process_outbound_text`
- `PrivacyGatewayFilter.check_text`
- `PrivacyGatewayFilter.stream_matcher`
- `privacy_gateway.adapters.http.DEFAULT_ENCRYPTED_HEADER`
- `privacy_gateway.adapters.http.build_block_error`
- `privacy_gateway.adapters.http.is_encrypted_request`
