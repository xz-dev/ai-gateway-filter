"""Python library entrypoint for privacy gateway primitives.

The package intentionally exposes only gateway-agnostic core primitives for:
- recognition/detection of sensitive phrases
- block decision handling
- text crypto primitives and automatic sensitive image-region protection
- reversible natural-language PII tokenization with ``<secret:1:...>`` tokens
"""

from privacy_gateway.lib import (  # noqa: F401
    CryptoOperationResult,
    FilterDecision,
    PrivacyGatewayError,
    PrivacyGatewayFilter,
    SensitiveMatch,
    SensitiveTextStreamDetector,
    PiiSpan,
    ImageCryptoError,
    TextCryptoError,
    TextCryptoKeyError,
    TextProcessingError,
    TextProcessingResult,
    UnsupportedPayloadTypeError,
)

from privacy_gateway.services.privacy_tokens import SecretTokenStreamRestorer

__all__ = [
    "CryptoOperationResult",
    "FilterDecision",
    "PrivacyGatewayError",
    "PrivacyGatewayFilter",
    "SensitiveMatch",
    "SensitiveTextStreamDetector",
    "PiiSpan",
    "TextCryptoError",
    "TextCryptoKeyError",
    "TextProcessingError",
    "TextProcessingResult",
    "ImageCryptoError",
    "UnsupportedPayloadTypeError",
    "SecretTokenStreamRestorer",
    "__version__",
]

__version__ = "0.1.0"
