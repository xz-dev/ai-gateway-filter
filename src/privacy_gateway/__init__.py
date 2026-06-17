"""Python library entrypoint for privacy gateway primitives.

The package intentionally exposes only gateway-agnostic core primitives for:
- recognition/detection of sensitive phrases
- block decision handling
- text/image crypto encrypt/decrypt primitives
"""

from privacy_gateway.lib import (  # noqa: F401
    CryptoOperationResult,
    FilterDecision,
    PrivacyGatewayError,
    PrivacyGatewayFilter,
    SensitiveMatch,
    SensitiveTextStreamDetector,
    TextCryptoError,
    TextCryptoKeyError,
    UnsupportedPayloadTypeError,
    ImageCryptoError,
)

__all__ = [
    "CryptoOperationResult",
    "FilterDecision",
    "PrivacyGatewayError",
    "PrivacyGatewayFilter",
    "SensitiveMatch",
    "SensitiveTextStreamDetector",
    "TextCryptoError",
    "TextCryptoKeyError",
    "ImageCryptoError",
    "UnsupportedPayloadTypeError",
    "__version__",
]

__version__ = "0.1.0"
