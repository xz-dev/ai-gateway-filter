from __future__ import annotations

from behave import given, then, when

from privacy_gateway import (
    ImageCryptoError,
    PrivacyGatewayError,
    SensitiveMatch,
    TextCryptoError,
    TextCryptoKeyError,
    PrivacyGatewayFilter,
    UnsupportedPayloadTypeError,
)


gateway = PrivacyGatewayFilter()


def _set_error(context, exc: Exception) -> None:
    context.last_result = None
    context.last_error = exc


def _set_success(context, result) -> None:
    context.last_result = result
    context.last_error = None


def _check_text(context, text: str) -> None:
    """Evaluate `text` with either the default or configured custom filter."""

    target = getattr(context, "gateway_with_phrases", gateway)
    context.last_decision = target.check_text(text)


def _ensure_stream_matcher(context) -> None:
    context.stream_matcher = getattr(context, "stream_matcher", None) or getattr(context, "gateway_with_phrases", gateway).stream_matcher()
    context.stream_blocked = False
    context.stream_match = None


@given('a payload of type "{payload_type}", content "{content}", and key "{crypto_key}"')
def step_given_payload(context, payload_type, content, crypto_key):
    context.payload_type = payload_type
    context.content = content
    context.crypto_key = crypto_key


@when("I encrypt the payload")
def step_encrypt_payload(context):
    try:
        _set_success(
            context,
            gateway.encrypt_payload(context.payload_type, context.content, context.crypto_key),
        )
    except Exception as exc:  # noqa: BLE001
        _set_error(context, exc)


@when('I decrypt the payload with key "{crypto_key}"')
def step_decrypt_with_key(context, crypto_key):
    try:
        _set_success(
            context,
            gateway.decrypt_payload(context.last_result.type, context.last_result.content, crypto_key),
        )
    except Exception as exc:  # noqa: BLE001
        _set_error(context, exc)


@then('an error is raised with detail "{detail}"')
def step_operation_error(context, detail):
    assert context.last_error is not None, "expected an error"
    assert str(context.last_error) == detail


@then("the operation succeeds")
def step_operation_success(context):
    assert context.last_error is None, f"expected success, got {context.last_error!r}"
    assert context.last_result is not None


@then('the restored text is "{expected}"')
def step_restored_text(context, expected):
    assert context.last_error is None, f"expected restored payload, got {context.last_error!r}"
    assert context.last_result is not None
    assert context.last_result.content == expected


@when('I check text "{text}"')
def step_check_text(context, text):
    _check_text(context, text)


@then('text check result is "{result}"')
def step_check_result(context, result):
    assert context.last_decision is not None
    assert context.last_decision.blocked == (result == "blocked")


@then('the matched phrase is "{word}"')
def step_matched_phrase(context, word):
    assert context.last_decision is not None
    assert context.last_decision.match is not None
    assert context.last_decision.match.detected_word == word


@when("I stream text chunks")
def step_stream_chunks(context):
    _ensure_stream_matcher(context)

    for row in context.table:
        decision = context.stream_matcher.feed(row["chunk"])
        if decision.blocked:
            context.stream_blocked = True
            context.stream_match = decision.match
            break


@when('I stream large text chunk "{chunk}" with suffix "{suffix}"')
def step_stream_large_chunk(context, chunk, suffix):
    matcher = getattr(context, "stream_matcher", None) or context.gateway_with_phrases.stream_matcher()
    context.stream_blocked = False
    context.stream_match = None

    decision = matcher.feed(chunk + suffix * 200)
    if decision.blocked:
        context.stream_blocked = True
        context.stream_match = decision.match
    else:
        context.stream_blocked = False
        context.stream_match = None


@then('stream text check result is "{result}"')
def step_stream_result(context, result):
    assert context.stream_blocked == (result == "blocked")


@then('the stream matched phrase is "{word}"')
def step_stream_matched_phrase(context, word):
    assert context.stream_match is not None
    assert context.stream_match.detected_word == word


@when('I configure a filter with no sensitive phrases')
def step_configure_filter_no_sensitive(context):
    context.gateway_with_phrases = PrivacyGatewayFilter(sensitive_phrases=[])
    context.stream_matcher = context.gateway_with_phrases.stream_matcher()
    context.stream_blocked = False
    context.stream_match = None


@when('I configure a filter with only blank sensitive phrases')
def step_configure_filter_blank_sensitive(context):
    context.gateway_with_phrases = PrivacyGatewayFilter(sensitive_phrases=["   ", "\t", ""])
    context.stream_matcher = context.gateway_with_phrases.stream_matcher()
    context.stream_blocked = False
    context.stream_match = None


@when("I restore the payload with key \"{crypto_key}\"")
def step_restore_payload(context, crypto_key):
    try:
        _set_success(
            context,
            gateway.restore_payload(context.last_result.type, context.last_result.content, crypto_key),
        )
    except Exception as exc:  # noqa: BLE001
        _set_error(context, exc)


@when('a stream matcher is created with max_window {max_window:d}')
def step_stream_matcher_with_window(context, max_window):
    context.stream_matcher = context.gateway_with_phrases.stream_matcher(max_window=max_window)
    context.stream_blocked = False
    context.stream_match = None


@when("I inspect top-level API exports")
def step_inspect_top_level_api_exports(context):
    """Capture top-level API symbols for direct contract checks."""
    context.api_exported_classes = {
        "SensitiveMatch": SensitiveMatch,
        "TextCryptoError": TextCryptoError,
        "TextCryptoKeyError": TextCryptoKeyError,
        "ImageCryptoError": ImageCryptoError,
        "UnsupportedPayloadTypeError": UnsupportedPayloadTypeError,
        "PrivacyGatewayError": PrivacyGatewayError,
    }


@then('SensitiveMatch is importable from top-level privacy_gateway')
def step_top_level_sensitive_match(context):
    assert context.api_exported_classes["SensitiveMatch"] is not None


@then("public error classes inherit PrivacyGatewayError")
def step_error_hierarchy(context):
    assert issubclass(context.api_exported_classes["TextCryptoError"], PrivacyGatewayError)
    assert issubclass(context.api_exported_classes["TextCryptoKeyError"], PrivacyGatewayError)
    assert issubclass(context.api_exported_classes["ImageCryptoError"], PrivacyGatewayError)
    assert issubclass(context.api_exported_classes["UnsupportedPayloadTypeError"], PrivacyGatewayError)
