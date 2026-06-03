# Manual Podman Compose Test Script Plan

## Context

The project is a FastAPI Privacy Gateway with Docker/Podman Compose support in `docker-compose.yml`. The user wants a Bash script that simulates a human/manual tester by calling the public HTTP API after the service is started with Podman Compose, and wants the script to be run locally against the composed service.

Existing API behavior is documented in `README.md` and already covered by Behave scenarios in `features/privacy_gateway.feature`. The manual Bash script should mirror those end-to-end user flows through real HTTP requests rather than importing Python application code.

## Approach

Add a Bash manual test script that:

- Accepts `BASE_URL`, defaulting to `http://127.0.0.1:8000`.
- Waits for the gateway to become ready by polling `/openapi.json`.
- Uses `curl` for HTTP requests and `python3` for safe JSON payload generation/assertion.
- Exercises the same user-visible flows as the Cucumber feature file:
  - Text encrypt/decrypt round trip.
  - Invalid text key rejection on encrypt and decrypt.
  - Wrong text key cannot decrypt.
  - Image base64 encrypt/decrypt round trip.
  - Invalid image base64 rejection.
  - Wrong image key cannot decrypt.
  - Allowed and blocked non-stream sensitive-word text.
  - Allowed and blocked text/plain streaming endpoint requests.
- Fails fast with a readable error message showing the response body when a check fails.
- Prints PASS messages for each simulated manual test step.

Then run the stack locally with Podman Compose and execute the script against it.

Podman note discovered during exploration: `podman compose` exists, but the default external provider lookup first tries a missing Docker Desktop `docker-compose` binary in this environment. `podman-compose` is installed (`podman-compose version 1.5.0`). To satisfy the requested Podman Compose run reliably, invoke Podman Compose with the provider explicitly set, for example:

```bash
PODMAN_COMPOSE_PROVIDER=podman-compose podman compose up --build -d
```

or use `podman-compose up --build -d` if the provider override still fails.

## Files to modify

- `scripts/manual_test.sh` — new Bash script for manual API simulation.
- Optional documentation update if desired:
  - `README.md` — add a short section showing how to run the manual script after Podman Compose starts.

## Reuse

Existing contracts and expected responses to reuse:

- `README.md` — endpoint descriptions, payload examples, and Docker Compose commands.
- `docker-compose.yml` — service exposes the gateway at `127.0.0.1:8000`.
- `features/privacy_gateway.feature` — complete list of user-facing scenarios and expected HTTP/status/JSON behavior.
- `features/steps/privacy_gateway_steps.py` — assertion semantics for status codes, field equality, field absence, and error detail checks.

No new Python app logic is needed for this task; the script should test the existing running service only.

## Steps

- [ ] Create `scripts/manual_test.sh` with strict Bash mode (`set -Eeuo pipefail`).
- [ ] Add helper functions for logging, readiness polling, JSON request submission, text/plain stream submission, and JSON assertions.
- [ ] Implement crypto manual flows for text and image payloads.
- [ ] Implement negative crypto flows for invalid keys, invalid image base64, and wrong keys.
- [ ] Implement sensitive-word manual flows for non-streaming and streaming endpoints.
- [ ] Mark the script executable.
- [ ] Start the service locally with Podman Compose using the installed `podman-compose` provider.
- [ ] Run the manual test script against `http://127.0.0.1:8000`.
- [ ] If the run fails, inspect compose logs and adjust only the script/test expectations if the application behavior is already correct.
- [ ] Stop the compose stack after verification.

## Verification

Run these commands after implementation:

```bash
PODMAN_COMPOSE_PROVIDER=podman-compose podman compose up --build -d
./scripts/manual_test.sh
PODMAN_COMPOSE_PROVIDER=podman-compose podman compose down
```

Expected script result:

```text
PASS: gateway ready
PASS: GET /openapi.json
PASS: text round trip
PASS: invalid encrypt key
PASS: invalid decrypt key
PASS: wrong text key
PASS: image round trip
PASS: invalid image base64
PASS: wrong image key
PASS: allowed non-stream text
PASS: blocked non-stream text
PASS: allowed stream text
PASS: blocked stream text
All manual API tests passed against http://127.0.0.1:8000
```

Also verify compose logs if needed:

```bash
PODMAN_COMPOSE_PROVIDER=podman-compose podman compose logs privacy-gateway
```
