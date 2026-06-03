# Error Contract Status Code Redesign Plan

## Context

The current API error contract returns `422 Unprocessable Entity` for both sensitive-word detections and crypto/input errors. The requested redesign is to reserve `422` for sensitive phrase detections only, and return `400 Bad Request` for crypto-related bad inputs/decryption failures:

| Case | Current | Target |
| --- | --- | --- |
| Invalid text key length | `422` | `400` |
| Wrong text decrypt key | `422` | `400` |
| Invalid image base64 on encrypt | `422` | `400` |
| Wrong image decrypt key | `422` | `400` |
| Sensitive phrase detected | `422` | `422` |

## Approach

Update the crypto router to translate `TextCryptoKeyError`, text decrypt failures, and `ImageCryptoError` into `400 Bad Request` while preserving the existing response body shapes (`{"detail": "..."}`). Leave sensitive-word endpoints unchanged so prompt-injection detections continue returning `422` with `{"detected_word": "...", "type": "Prompt Injection"}`.

Update the executable behavior specs and manual/API documentation so the documented contract matches the implementation.

## Files to modify

- `src/privacy_gateway/routers/crypto.py`
- `features/privacy_gateway.feature`
- `scripts/manual_test.sh`
- `README.md`

## Reuse

- Reuse `TextCryptoKeyError` from `src/privacy_gateway/services/presidio_crypto.py` to identify invalid AES key lengths.
- Reuse `ImageCryptoError` from `src/privacy_gateway/services/image_crypto.py` to identify image base64/decryption errors.
- Reuse the existing `HTTPException` handling style in `src/privacy_gateway/routers/crypto.py`; only the status code mapping changes.
- Reuse existing behave step definitions in `features/steps/privacy_gateway_steps.py`; the feature status expectations can change without adding new steps.
- Reuse existing shell assertions in `scripts/manual_test.sh`; update expected status codes only.

## Steps

- [x] Change crypto error `HTTPException` status codes in `src/privacy_gateway/routers/crypto.py` from `status.HTTP_422_UNPROCESSABLE_ENTITY` to `status.HTTP_400_BAD_REQUEST` for invalid text keys, text decrypt failures, image base64/encrypt errors, and image decrypt errors.
- [x] Keep sensitive-word response handling in `src/privacy_gateway/routers/sensitive_words.py` unchanged (`422`).
- [x] Update `features/privacy_gateway.feature` scenario names and expectations so the crypto error cases assert `400`, while sensitive-word scenarios still assert `422`.
- [x] Update `scripts/manual_test.sh` to assert `400` for crypto error cases and keep `422` for sensitive-word detection.
- [x] Update `README.md` examples and the Error contract table to document the new `400`/`422` split.

## Verification

- Run `uv run behave` and confirm all BDD scenarios pass.
- Run the manual HTTP script (`uv run privacy-gateway` in one terminal, then `scripts/manual_test.sh` in another) and confirm crypto bad inputs return `400` while sensitive phrase detections return `422`.
- Optionally inspect `/openapi.json`/docs to ensure the API still starts normally after the router changes.

## Decisions

- The crypto router's fallback `unsupported type` branch is also `400 Bad Request`, matching crypto API bad-input semantics.
- FastAPI/Pydantic request validation errors such as missing required fields or invalid enum values remain FastAPI's default `422`; this change only remaps crypto service errors handled by `src/privacy_gateway/routers/crypto.py`.
