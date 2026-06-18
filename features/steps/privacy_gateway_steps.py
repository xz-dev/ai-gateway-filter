from __future__ import annotations

from behave import given, then, when
from dataclasses import dataclass
import base64
import io
import re

import privacy_gateway.config as config_module
from PIL import Image

from privacy_gateway import (
    ImageCryptoError,
    PrivacyGatewayError,
    SensitiveMatch,
    TextCryptoError,
    TextCryptoKeyError,
    PrivacyGatewayFilter,
    TextProcessingError,
    TextProcessingResult,
    UnsupportedPayloadTypeError,
)
from privacy_gateway.adapters.http import build_block_error, is_encrypted_request
from privacy_gateway.config import get_settings
from privacy_gateway.services.image_crypto import IMAGE_REGION_METADATA_KEY, ImageCryptoService, ImageRegion, _RegionCryptoCache


class StaticImageRegionDetector:
    def __init__(self, regions):
        self._regions = regions

    def detect(self, image):  # noqa: ARG002
        return list(self._regions)


class FailingImageRegionDetector:
    def detect(self, image):  # noqa: ARG002
        raise RuntimeError("detector unavailable")


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


@given('a sample image payload and key "{crypto_key}"')
def step_sample_image_payload(context, crypto_key):
    image = Image.new("RGB", (4, 4), "white")
    pixels = image.load()
    for x in range(1, 3):
        for y in range(1, 3):
            pixels[x, y] = (255, 0, 0)
    output = io.BytesIO()
    image.save(output, format="PNG")
    context.payload_type = "image"
    context.content = base64.b64encode(output.getvalue()).decode("ascii")
    context.crypto_key = crypto_key
    context.original_image = image.convert("RGBA")


def _target_filter(context) -> PrivacyGatewayFilter:
    return getattr(context, "gateway_with_phrases", gateway)


def _last_content(context) -> str:
    return context.last_result.content if hasattr(context.last_result, "content") else context.last_result


@when("I encrypt the payload")
def step_encrypt_payload(context):
    try:
        _set_success(
            context,
            _target_filter(context).encrypt_payload(context.payload_type, context.content, context.crypto_key),
        )
    except Exception as exc:  # noqa: BLE001
        _set_error(context, exc)


@when('I decrypt the payload with key "{crypto_key}"')
def step_decrypt_with_key(context, crypto_key):
    try:
        payload_type = context.last_result.type if hasattr(context.last_result, "type") else context.payload_type
        _set_success(
            context,
            _target_filter(context).decrypt_payload(payload_type, _last_content(context), crypto_key),
        )
    except Exception as exc:  # noqa: BLE001
        _set_error(context, exc)


@given('an image detector returns region {left:d},{top:d},{right:d},{bottom:d}')
def step_image_detector_returns_region(context, left, top, right, bottom):
    detector = StaticImageRegionDetector([ImageRegion(left, top, right, bottom)])
    context.gateway_with_phrases = PrivacyGatewayFilter(image_region_detector=detector)


@given("an image detector returns no regions")
def step_image_detector_returns_no_regions(context):
    context.gateway_with_phrases = PrivacyGatewayFilter(image_region_detector=StaticImageRegionDetector([]))


@given("an image detector fails")
def step_image_detector_fails(context):
    context.gateway_with_phrases = PrivacyGatewayFilter(image_region_detector=FailingImageRegionDetector())


@when("I encrypt the payload with an isolated image cache")
def step_encrypt_payload_isolated_image_cache(context):
    detector = context.gateway_with_phrases._image_crypto._get_detector()  # noqa: SLF001 - test detector preservation
    isolated = PrivacyGatewayFilter(image_region_detector=detector)
    isolated._image_crypto = ImageCryptoService(  # noqa: SLF001 - test cache isolation
        detector=detector,
        cache=_RegionCryptoCache(),
    )
    try:
        _set_success(context, isolated.encrypt_payload(context.payload_type, context.content, context.crypto_key).content)
    except Exception as exc:  # noqa: BLE001
        _set_error(context, exc)


@when("I decrypt the protected image with a fresh isolated cache")
def step_decrypt_image_regions_fresh_cache(context):
    fresh = PrivacyGatewayFilter(image_region_detector=StaticImageRegionDetector([]))
    fresh._image_crypto = ImageCryptoService(  # noqa: SLF001 - test cache isolation
        detector=StaticImageRegionDetector([]),
        cache=_RegionCryptoCache(),
    )
    try:
        _set_success(context, fresh.restore_image(context.last_result, context.crypto_key))
    except Exception as exc:  # noqa: BLE001
        _set_error(context, exc)


@then("the protected image differs from the original image")
def step_protected_image_differs(context):
    assert context.last_error is None, f"expected success, got {context.last_error!r}"
    protected = Image.open(io.BytesIO(base64.b64decode(_last_content(context)))).convert("RGBA")
    assert list(protected.getdata()) != list(context.original_image.getdata())


@then("the protected image contains partial image metadata")
def step_protected_image_metadata(context):
    protected = Image.open(io.BytesIO(base64.b64decode(_last_content(context))))
    assert IMAGE_REGION_METADATA_KEY in protected.info


@then("the restored image pixels match the original image")
def step_restored_image_pixels(context):
    assert context.last_error is None, f"expected success, got {context.last_error!r}"
    restored = Image.open(io.BytesIO(base64.b64decode(_last_content(context)))).convert("RGBA")
    assert list(restored.getdata()) == list(context.original_image.getdata())


@then("the restored image size matches the original image")
def step_restored_image_size(context):
    assert context.last_error is None, f"expected success, got {context.last_error!r}"
    restored = Image.open(io.BytesIO(base64.b64decode(_last_content(context)))).convert("RGBA")
    assert restored.size == context.original_image.size


@then("the protected image is unchanged")
def step_protected_image_unchanged(context):
    assert context.last_error is None, f"expected success, got {context.last_error!r}"
    assert _last_content(context) == context.content


@when("I fill the image region cache with 1001 entries")
def step_fill_image_region_cache(context):
    service = ImageCryptoService()
    for index in range(1001):
        service._cache.put(f"hash-{index}", f"encrypted-{index}".encode("ascii"))  # noqa: SLF001 - direct cache contract
    context.image_crypto_service = service


@then("image region cache size is 1000")
def step_image_region_cache_size(context):
    assert context.image_crypto_service.cache_size() == 1000


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


@when("I encrypt text directly")
def step_encrypt_text_directly(context):
    try:
        _set_success(context, gateway.encrypt_text(context.content, context.crypto_key))
    except Exception as exc:  # noqa: BLE001
        _set_error(context, exc)


@then("the direct text result has no crypto key")
def step_direct_text_result_no_crypto_key(context):
    assert context.last_error is None, f"expected success, got {context.last_error!r}"
    assert isinstance(context.last_result, str)
    assert context.last_result != context.crypto_key
    assert not hasattr(context.last_result, "crypto_key")


@when('I decrypt text directly with key "{crypto_key}"')
def step_decrypt_text_directly(context, crypto_key):
    try:
        _set_success(context, gateway.decrypt_text(context.last_result, crypto_key))
    except Exception as exc:  # noqa: BLE001
        _set_error(context, exc)


@then('the direct text result is "{expected}"')
def step_direct_text_result(context, expected):
    assert context.last_error is None, f"expected success, got {context.last_error!r}"
    assert context.last_result == expected


@when('I process inbound encrypted text with key "{crypto_key}"')
def step_process_inbound_last_result(context, crypto_key):
    context.text_processing_result = gateway.process_inbound_text(
        context.last_result,
        crypto_key=crypto_key,
        encrypted=True,
    )


@when('I process inbound encrypted text "{content}" with key "{crypto_key}"')
def step_process_inbound_text(context, content, crypto_key):
    context.text_processing_result = gateway.process_inbound_text(
        content,
        crypto_key=crypto_key,
        encrypted=True,
    )


@then('text processing content is "{expected}"')
def step_text_processing_content(context, expected):
    assert context.text_processing_result.content == expected


@then("text processing content is empty")
def step_text_processing_content_empty(context):
    assert context.text_processing_result.content == ""


@then('text processing decision is "{result}"')
def step_text_processing_decision(context, result):
    assert context.text_processing_result.decision.blocked == (result == "blocked")


@then("text processing has no error")
def step_text_processing_no_error(context):
    assert context.text_processing_result.error is None


@then('text processing error code is "{code}"')
def step_text_processing_error_code(context, code):
    assert context.text_processing_result.error is not None
    assert context.text_processing_result.error.code == code


@when('I process outbound text "{content}" with key "{crypto_key}" and encryption enabled')
def step_process_outbound_text(context, content, crypto_key):
    context.text_processing_result = gateway.process_outbound_text(
        content,
        crypto_key=crypto_key,
        encrypt=True,
    )


@then('text processing content decrypts to "{expected}" with key "{crypto_key}"')
def step_text_processing_decrypts_to(context, expected, crypto_key):
    assert gateway.decrypt_text(context.text_processing_result.content, crypto_key) == expected


@then('the text processing matched phrase is "{word}"')
def step_text_processing_matched_phrase(context, word):
    assert context.text_processing_result.decision.match is not None
    assert context.text_processing_result.decision.match.detected_word == word


@when('I load settings with crypto key "{crypto_key}"')
def step_load_settings_with_crypto_key(context, crypto_key):
    original = config_module.getenv

    def fake_getenv(name, default=None):
        if name == "PRIVACY_GATEWAY_CRYPTO_KEY":
            return crypto_key
        return original(name, default)

    config_module.getenv = fake_getenv
    try:
        context.settings = get_settings()
    finally:
        config_module.getenv = original


@then('settings crypto key is "{crypto_key}"')
def step_settings_crypto_key(context, crypto_key):
    assert context.settings.crypto_key == crypto_key


@then('a filter from settings can encrypt text "{content}" without an explicit key')
def step_filter_from_settings_encrypts_without_explicit_key(context, content):
    filter_ = PrivacyGatewayFilter.from_settings(context.settings)
    encrypted = filter_.encrypt_text(content)
    assert filter_.decrypt_text(encrypted) == content


@when("I create a filter from settings without a crypto key field")
def step_filter_from_settings_without_crypto_key_field(context):
    @dataclass(frozen=True)
    class LegacySettings:
        sensitive_phrases: list[str]
        max_sensitive_stream_window: int

        @property
        def prompt_injection_phrases(self):
            return self.sensitive_phrases

    context.gateway_with_phrases = PrivacyGatewayFilter.from_settings(
        LegacySettings(
            sensitive_phrases=["ignore previous instructions"],
            max_sensitive_stream_window=4096,
        )
    )


@then("explicit-key text encryption still works")
def step_explicit_key_text_encryption_still_works(context):
    encrypted = context.gateway_with_phrases.encrypt_text("legacy settings", "WmZq4t7w!z%C&F)J")
    assert context.gateway_with_phrases.decrypt_text(encrypted, "WmZq4t7w!z%C&F)J") == "legacy settings"


@when('I build an HTTP block error for matched text "{matched}"')
def step_build_http_block_error(context, matched):
    context.http_block_error = build_block_error(
        422,
        "forward injection detected",
        blocked_by="test-adapter",
        matched=matched,
    )


@then('the HTTP block error status is {status:d}')
def step_http_block_error_status(context, status):
    assert context.http_block_error.status == status


@then('the HTTP block error body includes matched text "{matched}"')
def step_http_block_error_matched(context, matched):
    assert context.http_block_error.body["matched"] == matched
    assert context.http_block_error.body["error"] == "privacy_gateway_blocked"


@then("encrypted request headers are detected case-insensitively")
def step_encrypted_headers_case_insensitive(context):
    assert is_encrypted_request({"x-privacy-encrypted": "1"})
    assert is_encrypted_request({"X-Privacy-Encrypted": "true"})
    assert not is_encrypted_request({"X-Privacy-Encrypted": "0"})


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
        "TextProcessingError": TextProcessingError,
        "TextProcessingResult": TextProcessingResult,
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


@when('I configure a privacy filter with password "{password}"')
def step_configure_privacy_filter(context, password):
    context.gateway_with_phrases = PrivacyGatewayFilter(privacy_password=password)
    context.privacy_password = password
    context.last_protected_text = None
    context.last_restored_text = None
    context.first_protected_text = None
    context.second_protected_text = None


@when('I set the privacy filter sensitive phrase to "{phrase}"')
def step_set_privacy_filter_sensitive_phrase(context, phrase):
    context.gateway_with_phrases = PrivacyGatewayFilter(
        privacy_password=context.privacy_password,
        sensitive_phrases=[phrase],
    )


@when("I configure a privacy filter without password")
def step_configure_privacy_filter_without_password(context):
    context.gateway_with_phrases = PrivacyGatewayFilter(privacy_password=None, crypto_key=None)
    context.privacy_password = None
    context.last_protected_text = None
    context.last_restored_text = None


def _privacy_filter(context) -> PrivacyGatewayFilter:
    return getattr(context, "gateway_with_phrases", gateway)


@when('I protect secret value "{value}"')
def step_protect_secret_value(context, value):
    context.last_protected_text = _privacy_filter(context).protect_secret(value)


@when('I attempt to protect secret value "{value}"')
def step_attempt_protect_secret_value(context, value):
    try:
        _set_success(context, _privacy_filter(context).protect_secret(value))
    except Exception as exc:  # noqa: BLE001 - behavior tests assert normalized public error text
        _set_error(context, exc)


@when('I protect secret value "{value}" twice')
def step_protect_secret_value_twice(context, value):
    context.first_protected_text = _privacy_filter(context).protect_secret(value)
    context.second_protected_text = _privacy_filter(context).protect_secret(value)
    context.last_protected_text = context.second_protected_text


@when('I protect privacy text "{text}"')
def step_protect_privacy_text(context, text):
    context.last_protected_text = _privacy_filter(context).protect_privacy_text(text)


@when("I protect the last protected privacy text again")
def step_protect_last_privacy_text_again(context):
    context.last_protected_text = _privacy_filter(context).protect_privacy_text(context.last_protected_text)


@when("I restore the last protected privacy text")
def step_restore_last_protected_privacy_text(context):
    context.last_restored_text = _privacy_filter(context).restore_privacy_text(context.last_protected_text)


@when('I restore privacy text "{text}"')
def step_restore_privacy_text(context, text):
    context.last_restored_text = _privacy_filter(context).restore_privacy_text(text)


@when('I process inbound privacy text "{text}"')
def step_process_inbound_privacy_text(context, text):
    if "{last_protected_text}" in text:
        assert context.last_protected_text is not None
        text = text.replace("{last_protected_text}", context.last_protected_text)
    context.text_processing_result = _privacy_filter(context).process_inbound_privacy_text(text)


@when('I process the last protected privacy text with password "{password}"')
def step_process_last_protected_privacy_text_with_password(context, password):
    context.text_processing_result = _privacy_filter(context).process_inbound_privacy_text(
        context.last_protected_text,
        privacy_password=password,
    )


@when("I tamper with the last protected privacy text")
def step_tamper_last_protected_privacy_text(context):
    token = context.last_protected_text
    assert token is not None and token.endswith(">")
    body_end = token.rfind(">")
    replacement = "A" if token[body_end - 1] != "A" else "B"
    context.last_protected_text = f"{token[: body_end - 1]}{replacement}{token[body_end:]}"


@when('I create a privacy filter requiring spaCy model "{model_name}"')
def step_create_filter_requiring_missing_spacy_model(context, model_name):
    try:
        _set_success(
            context,
            PrivacyGatewayFilter(
                privacy_password="gateway-password",
                spacy_model=model_name,
                require_spacy_model=True,
            ),
        )
    except Exception as exc:  # noqa: BLE001 - behavior tests assert public startup error text
        _set_error(context, exc)


@when('I process outbound privacy text "{text}"')
def step_process_outbound_privacy_text(context, text):
    context.text_processing_result = _privacy_filter(context).process_outbound_privacy_text(text)


@when("I check the last protected privacy text")
def step_check_last_protected_privacy_text(context):
    _check_text(context, context.last_protected_text)


@then("protected text contains a secret token")
def step_protected_text_contains_secret_token(context):
    assert context.last_protected_text is not None
    assert "<secret:1:" in context.last_protected_text
    assert context.last_protected_text.endswith(">")


@then("protected text matches the secret token salt ciphertext format")
def step_protected_text_matches_secret_token_format(context):
    pattern = re.compile(r"^<secret:1:[A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+>$")
    assert context.first_protected_text is not None
    assert context.second_protected_text is not None
    assert pattern.fullmatch(context.first_protected_text), context.first_protected_text
    assert pattern.fullmatch(context.second_protected_text), context.second_protected_text


@then("the two protected privacy texts differ")
def step_two_protected_privacy_texts_differ(context):
    assert context.first_protected_text is not None
    assert context.second_protected_text is not None
    assert context.first_protected_text != context.second_protected_text


@then("protected text contains at least {count:d} secret tokens")
def step_protected_text_contains_at_least_tokens(context, count):
    assert context.last_protected_text is not None
    assert context.last_protected_text.count("<secret:1:") >= count, context.last_protected_text


@then("protected text contains exactly {count:d} secret token")
def step_protected_text_contains_exactly_token(context, count):
    assert context.last_protected_text is not None
    assert context.last_protected_text.count("<secret:1:") == count, context.last_protected_text


@then('protected text does not contain "{text}"')
def step_protected_text_does_not_contain(context, text):
    assert context.last_protected_text is not None
    assert text not in context.last_protected_text, context.last_protected_text


@then('restored privacy text is "{expected}"')
def step_restored_privacy_text_is(context, expected):
    assert context.last_restored_text == expected


@then('both protected privacy texts restore to "{expected}"')
def step_both_protected_privacy_texts_restore_to(context, expected):
    assert _privacy_filter(context).restore_privacy_text(context.first_protected_text) == expected
    assert _privacy_filter(context).restore_privacy_text(context.second_protected_text) == expected
