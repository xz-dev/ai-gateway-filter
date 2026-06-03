# FastAPI Privacy Gateway Plan

## Context

The current directory appears to be effectively empty aside from `.git/` and `.pi/`. The requested project should be created here as a new FastAPI service initialized with `uv init`. Add `.pi/` to `.gitignore`.

Requested capabilities:

1. Transparent privacy protection wrapper for AI API responses/inputs.
2. Unified encryption/decryption endpoints using Presidio's encryption/anonymization tutorial pattern for text and symmetric encryption for image base64 payloads. Caller must provide `crypto_key`; service must not generate random key.
3. Request body carries the media kind as `type`: `{"type":"text", "content":"<text_string>", "crypto_key":"..."}` or `{"type":"image", "content":"<image_base64_string>", "crypto_key":"..."}`.
4. Stream and non-stream sensitive-word checks. The initial sensitive-word set only covers prompt-injection phrases, but the implementation should be generic so more sensitive-word categories can be added later.
5. Cucumber-style integration tests only; no unit tests.

## Approach

Create a new Python/FastAPI project with unified encryption/decryption routers/services and narrow sensitive-word APIs.

Encryption/decryption endpoints:

- `POST /encrypt`
- `POST /decrypt`

Sensitive-word endpoints:

- `POST /sensitive-words/text` for non-streaming checks. Request body: `{"text": "<text_string>"}`. Return `200` when no phrase matches; return `422` immediately when a phrase matches, with JSON body `{"detected_word": "<matched_phrase>", "type": "Prompt Injection"}`.
- `POST /sensitive-words/text/stream` for streaming checks. Request body: raw `text/plain` streaming/chunked text. Read chunks incrementally; return `422` as soon as accumulated/chunk text matches a sensitive phrase, with JSON body `{"detected_word": "<matched_phrase>", "type": "Prompt Injection"}`; return `200` only after the stream finishes clean.

Both `/encrypt` and `/decrypt` accept the same envelope shape and dispatch internally by `type`:

```json
{"type": "text", "content": "<text_string>", "crypto_key": "..."}
```

or:

```json
{"type": "image", "content": "<image_base64_string>", "crypto_key": "..."}
```

Use Presidio for text anonymization/encryption with caller-provided `crypto_key`. The service does not store or generate keys. Return the same envelope shape with encrypted/decrypted `content` and the provided `crypto_key` echoed back. Image encryption/decryption will use the same envelope with `type: "image"` and base64 `content`.

Use `behave` as the Cucumber-compatible Python BDD framework and write integration feature files that exercise FastAPI through HTTP.

## Files to modify

New project files to create, likely:

- `pyproject.toml`
- `README.md`
- `src/privacy_gateway/main.py`
- `src/privacy_gateway/config.py`
- `src/privacy_gateway/routers/crypto.py`
- `src/privacy_gateway/routers/safety.py`
- `src/privacy_gateway/services/presidio_crypto.py`
- `src/privacy_gateway/services/image_crypto.py`
- `src/privacy_gateway/schemas.py`
- `src/privacy_gateway/services/ban_words.py`
- `features/*.feature`
- `features/environment.py`
- `features/steps/*.py`

## Reuse

No local reusable implementation found yet; this appears to be a new project.

Implementation guidance:

- Use Presidio only for the encryption/decryption feature, not for sensitive-word filtering.
- Sensitive-word filtering scope is only AI-abuse prevention for now, specifically prompt-injection phrases. Do not add PII/DLP/credential-leak filtering endpoints or policies.
- Implement sensitive-word filtering locally in this project; do not vendor, import, or add a dependency on the Azure AI Security Gateway repository.
- Use the Azure AI Security Gateway prompt-injection policy only as a design example for simple case-insensitive phrase matching and immediate `422` blocking.
- Seed the initial sensitive-word list with prompt-injection phrases from that example, such as `ignore previous instructions`, `reveal your system prompt`, `bypass policy`, `disregard all prior guidance`, `repeat the exact instructions`, `hidden instructions`, and `developer debugging mode`.

## Steps

- [x] Run `uv init` to initialize the project.
- [x] Add `.pi/` to `.gitignore`.
- [x] Define exact API contract and payload formats from the user request.
- [x] Define FastAPI app structure and dependency list.
- [x] Implement unified `POST /encrypt` and `POST /decrypt` endpoints accepting `type`, `content`, and required caller-provided `crypto_key`.
- [x] Dispatch `type: "text"` to Presidio crypto operators.
- [x] Dispatch `type: "image"` to image/base64 encryption-decryption logic.
- [x] Implement generic sensitive-word matching for non-streaming text, seeded with prompt-injection phrases.
- [x] Implement streaming text guard that aborts immediately with `422` when a sensitive phrase is detected.
- [x] Add Cucumber/behave integration tests for all endpoint groups.
- [x] Add README with setup, run, and test commands.

## Verification

- Run FastAPI locally with uvicorn.
- Run Cucumber integration tests with `behave`.
- Verify unified `/encrypt` and `/decrypt` text round trip using same caller-provided `crypto_key` and `type: "text"`.
- Verify unified `/encrypt` and `/decrypt` image round trip using same caller-provided `crypto_key` and `type: "image"`.
- Verify non-stream text containing an initial prompt-injection sensitive phrase returns `422` with JSON `{"detected_word": "<matched_phrase>", "type": "Prompt Injection"}`.
- Verify stream text containing an initial prompt-injection sensitive phrase fails immediately with `422` with the same JSON shape.
- Verify allowed streaming/non-streaming text returns `200`.

## API Decisions

- Use unified `POST /encrypt` and `POST /decrypt` endpoints, not separate text/image routes.
- Request body is `{"type": "text", "content": "<text_string>", "crypto_key": "..."}` for text.
- Request body is `{"type": "image", "content": "<image_base64_string>", "crypto_key": "..."}` for image.
- Require `crypto_key` in every `/encrypt` and `/decrypt` request.
- Do not generate or persist crypto keys.
- Use JSON base64 payloads for image endpoints unless later changed.
- Add sensitive-word endpoints for streaming and non-streaming checks.
- For streaming safety, reject with `422` as soon as a sensitive phrase is detected before forwarding further chunks.
- Start and stop at built-in prompt-injection sensitive phrases for this interface; no extra DLP/credential/category API expansion.
