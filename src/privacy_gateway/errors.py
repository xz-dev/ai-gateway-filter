"""Core public error types for the privacy gateway library."""


class PrivacyGatewayError(ValueError):
    """Base error type for privacy-gateway core library errors."""


class UnsupportedPayloadTypeError(PrivacyGatewayError):
    """Raised when the payload type is not supported by the core library."""


class TextCryptoError(PrivacyGatewayError):
    """Raised when text crypto input is invalid."""


class TextCryptoKeyError(TextCryptoError):
    """Specific error when caller key length is invalid."""


class ImageCryptoError(PrivacyGatewayError):
    """Raised when image crypto input/decryption fails."""


__all__ = [
    "PrivacyGatewayError",
    "UnsupportedPayloadTypeError",
    "TextCryptoError",
    "TextCryptoKeyError",
    "ImageCryptoError",
]
