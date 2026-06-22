# AI Gateway Filter

This context describes the language used around the deployable AI proxy gateway and the privacy filtering library it embeds.

## Language

**AI Proxy Gateway**:
A deployable gateway that accepts OpenAI-compatible AI API requests, applies gateway-level policy, and forwards accepted requests to an AI provider endpoint while preserving client-facing OpenAI-compatible behavior.
_Avoid_: Demo project, mock-only gateway, manual proxy sidecar

**Transparent AI Proxy**:
An AI Proxy Gateway where privacy tokenization is hidden from the client-facing API contract: sensitive Semantic Content is tokenized before it reaches the AI Provider Endpoint, and known reversible tokens in provider responses are automatically restored before the response is returned to the client.
_Avoid_: Client-visible token gateway, manual restore workflow

**AI Provider Endpoint**:
A real OpenAI-compatible upstream service that fulfills AI API requests behind the gateway.
_Avoid_: Mock upstream, test-only backend

**Model Selection**:
The caller-owned choice of model carried by each AI API request. The gateway should not require a separate default model setting for normal proxying.
_Avoid_: Gateway model config, hard-coded test model

**Provider Authentication**:
The credentials or headers used to call the external AI Provider Endpoint. Provider Authentication belongs to APISIX `ai-proxy` route/config or client pass-through policy, not to the APISIX Privacy Plugin or Privacy Filter Library; the privacy plugin must not inspect or transform provider authorization headers.
_Avoid_: Treating Authorization headers as Semantic Content, privacy plugin-owned provider credentials

**Gateway Policy**:
Request/response rules enforced at the gateway boundary for AI API traffic, preferably through APISIX AI Gateway components when APISIX already provides the capability.
_Avoid_: Hand-written APISIX replacement logic

**Gateway Security Boundary**:
The AI Proxy Gateway is the trust boundary between the internal system and the external network/provider. Outbound semantic content follows `internal client -> injection check -> reversible tokenization -> provider`; outbound processing never restores or normalizes existing tokens because that is not its responsibility. Inbound semantic content follows `provider -> best-effort token restore/normalize -> injection check -> internal client`; inbound processing never performs PII tokenization, and newly generated plaintext PII from the provider is allowed as normal text because the internal environment is trusted. Injection checks run on the current semantic content at that stage; the gateway does not first mask token text as a separate injection-check preparation step.
_Avoid_: Best-effort optional filter, client-side-only privacy, provider-side-only safety, defining inbound/outbound from the provider's point of view, outbound restore/normalize, inbound PII tokenization, masking tokens before injection checks, masking inbound provider-generated PII

**Outbound External Traffic**:
Semantic Content flowing from the internal system through the gateway to an external AI provider or external network. This flow must not expose raw sensitive internal data; it checks the internal client's current semantic content for injection before protecting sensitive values with Reversible Privacy Tokenization, and it must not restore or normalize tokens. Existing `<secret:1:...>` tokens are treated as already-protected text and pass through unchanged rather than being decrypted, re-encrypted, tokenized internally, or masked before injection checks.
_Avoid_: Raw internal PII to provider, provider-facing plaintext secrets, outbound restore/normalize, double-tokenizing token bodies, token masking before injection checks

**Inbound Provider Traffic**:
Semantic Content flowing from an external AI provider or external network through the gateway into the internal system. This flow restores known reversible tokens when possible, then blocks or rejects injection on the restored/current semantic content; if a `<secret:1:...>` token cannot be decrypted, it is preserved unchanged rather than causing an error. Newly generated plaintext PII from the provider is not tokenized, masked, or blocked solely because it is PII.
_Avoid_: Treating provider responses as trusted, skipping token restore on returned tokens, failing inbound traffic solely because a token is undecryptable, masking tokens before injection checks, inbound PII tokenization, blocking provider text only because it contains new PII

**Outbound AI Request Body**:
The client-to-provider request for supported OpenAI-compatible agent-action endpoints is a complete JSON document, even when it asks for a streaming response with `stream: true`. The gateway reads and parses the whole outbound request before injection checking and reversible tokenization; HTTP chunked upload is treated as transport detail, not a semantic AI request stream.
_Avoid_: Streaming prompt body, partial JSON semantic processing, treating response SSE as request streaming

**Streaming Inbound Processing**:
The inbound provider response mode where the gateway restores tokens with a sliding-window token assembler while forwarding restored output incrementally to avoid UI stalls. The assembler must bound incomplete token-looking fragments; overlong unterminated token prefixes are emitted unchanged rather than buffered indefinitely, so untrusted provider output cannot suppress the stream or grow memory without bound. The gateway also buffers the complete AI answer for post-completion injection checking; if injection is detected after stream completion, the gateway cannot change the already-sent HTTP status and instead signals failure with a stream-level error/final error event and closes the stream. Non-streaming responses reuse the same internal restoration path for consistency, but can return a normal non-2xx HTTP error before any body is sent.
_Avoid_: Separate non-stream restore semantics, waiting for full response before any streaming UI output, token restore that requires a whole response body, unbounded buffering of incomplete token-looking text, changing HTTP status after a stream has started

**Streaming Semantic Delta**:
The SSE fields within streaming agent-action responses that carry Semantic Content and therefore need inbound restore plus full-answer injection buffering. For chat completions this includes `choices[*].delta.content` and `choices[*].delta.tool_calls[*].function.arguments`; for responses this includes text deltas such as `response.output_text.delta`, function-call argument deltas such as `response.function_call_arguments.delta`, and equivalent output/message content deltas. Non-semantic fields such as ids, timestamps, model, finish reasons, usage, event types, roles, and tool/function names are not transformed.
_Avoid_: Transforming SSE metadata, merging different tool-call argument streams, processing ids or function names as semantic content

**Unknown Semantic Structure**:
A structure on a supported Agent Action API Surface that may carry Semantic Content but is not recognized by the APISIX Privacy Plugin. Unknown Semantic Structure fails closed rather than passing through uninspected; clearly non-semantic metadata may pass through unchanged.
_Avoid_: Best-effort pass-through for possibly semantic fields, treating new provider fields as safe by default

**Gateway Error Contract**:
Failures returned before any response body is sent should use OpenAI-compatible error JSON. Injection or safety rejection should be treated as unprocessable semantic content, unknown semantic structures as bad or unprocessable requests, and internal tokenization/restore failures as internal errors; once an SSE stream has started, failures are signaled with stream-level error/final error events instead of changing HTTP status.
_Avoid_: Custom non-OpenAI error shapes, changing HTTP status after streaming starts, leaking secrets in error details

**Gateway Privacy Processing**:
PII recognition, provider-facing reversible privacy tokenization on outbound external traffic, internal-facing automatic restoration on inbound provider traffic, and safety identification performed as part of the APISIX AI Gateway request/response pipeline. The gateway should use APISIX AI Gateway components to parse AI requests and process AI responses rather than replacing that pipeline with a hand-written proxy.
_Avoid_: Sidecar-only privacy processing, manual request/response rewriting as the primary gateway, irreversible masking as the privacy contract, inbound PII masking inside the trusted internal environment

**Reversible Privacy Tokenization**:
A privacy transformation that replaces detected sensitive values with recoverable tokens, preserving a server-side ability to restore or map the original value when the approved flow requires it. This is the required privacy outcome; irreversible masking/redaction is not sufficient.
_Avoid_: Masking, redaction, anonymization

**Agent Action API Surface**:
The OpenAI-compatible agent/action endpoints that the APISIX Privacy Plugin supports: `/v1/chat/completions` and `/v1/responses`. Embeddings and image-generation endpoints are out of scope because they are not the agent-action interface this plugin is protecting.
_Avoid_: Arbitrary `/v1/*`, embeddings, image generation, files API

**Streaming Agent Response**:
An agent-action response delivered incrementally, such as OpenAI-compatible `stream: true` SSE output. Streaming must be supported without buffering the entire provider response before forwarding; privacy restore and injection checks must operate incrementally over semantic deltas/items while preserving the streaming contract.
_Avoid_: Non-streaming-only gateway, full-response buffering, silently disabling `stream: true`

**Semantic Content**:
The parts of an agent-action AI request or response that carry system/developer instructions, user content, tool/function-call arguments, prompt, assistant output, or inline image meaning and may be interpreted by a model or shown back to a user. Reversible Privacy Tokenization applies to Semantic Content crossing the external boundary, including system and developer message content, to reduce provider-side and network/MITM exposure; it does not apply to protocol/control fields such as model, stream, temperature, max tokens, route paths, headers, tool schemas, tool/function names, or `tools[].function.description`. Image Semantic Content is limited to inline/base64 or data URL images supplied inside an agent-action request; the gateway does not proactively download remote image URLs.
_Avoid_: Whole request body, protocol fields, gateway config, remote image fetching, embeddings endpoints, image-generation endpoints, tool/function schema processing, `tools[].function.description` processing, excluding system/developer message content from protection

**APISIX Privacy Plugin**:
The single APISIX integration glue that lives in `apisix-plugin-example/`, participates in the APISIX AI Gateway pipeline, locates Semantic Content, and calls the Privacy Filter Library for explicit direction-specific injection checking and secret guarding. It is a plugin/integration layer, not the core library and not a replacement for APISIX routing or AI proxying.
_Avoid_: Standalone proxy service, gateway core library, provider router, split plugins without a clear need

**Privacy Filter Library**:
The importable Python library that provides injection checking and secret guarding primitives for integrations. It may expose direction-aware semantic-content helpers for the Gateway Security Boundary, but it must not provide routing infrastructure, an HTTP server, or network proxy behavior.
_Avoid_: Privacy proxy, APISIX plugin implementation, route management, HTTP server, network proxy

## Example dialogue

Developer: “Should the example route to a fake local model?”
Domain expert: “No. The AI Provider Endpoint is real; the gateway must be usable as an AI Proxy Gateway, not only a mock demo.”

Developer: “Where do we configure the test model?”
Domain expert: “We do not configure Model Selection at the gateway level. OpenAI-compatible requests already carry the model in their body.”

Developer: “Should we copy the hand-written proxy behavior?”
Domain expert: “No. Gateway Policy should use APISIX AI Gateway components when APISIX provides the capability.”

Developer: “Will clients see `<secret:1:...>` tokens in normal responses?”
Domain expert: “No. This is a Transparent AI Proxy: tokenization protects traffic sent to the provider, then known tokens are automatically restored before returning to the client.”
