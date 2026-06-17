# Privacy Gateway (Core Library)

This repository is a pure importable Python library for privacy filtering and
crypto primitives. It intentionally has no HTTP server, router, FastAPI, or
proxy/routing/adapter responsibilities.

## Scope

- text/image encryption and decryption
- sensitive phrase detection and filtering decisions
- streaming detection helper
- optional environment-derived defaults

## Notes

Use `privacy_gateway` (top-level package exports) as the recommended public integration entry for plugins.
`privacy_gateway.lib` exposes core classes and extension points for advanced use.
`privacy_gateway.services.*` are internal implementation modules and are not intended as a stable plugin integration surface.

## Public behavior

- `PrivacyGatewayFilter.encrypt_payload`
- `PrivacyGatewayFilter.decrypt_payload`
- `PrivacyGatewayFilter.restore_payload`
- `PrivacyGatewayFilter.check_text`
- `PrivacyGatewayFilter.stream_matcher`
