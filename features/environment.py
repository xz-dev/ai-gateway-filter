# Library-only behavior tests do not require HTTP fixtures.

from privacy_gateway import PrivacyGatewayFilter


def before_scenario(context, scenario):  # noqa: ARG001
    # Per-scenario mutable state keeps tests isolated and avoids cross-scenario leakage.
    context.gateway_with_phrases = PrivacyGatewayFilter()
    context.stream_matcher = context.gateway_with_phrases.stream_matcher()
    context.last_result = None
    context.last_error = None
    context.payload_type = None
    context.content = None
    context.crypto_key = None
    context.last_decision = None
    context.stream_blocked = False
    context.stream_match = None
    # Optional helpers used by streaming tests are also reset per scenario.
    context.api_exported_classes = {}
