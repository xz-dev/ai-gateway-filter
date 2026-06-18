from __future__ import annotations

"""Core, gateway-agnostic library APIs for privacy filtering and crypto operations."""

from dataclasses import dataclass
from typing import Sequence

from privacy_gateway.config import (
    DEFAULT_PII_ENTITIES,
    DEFAULT_PROMPT_INJECTION_PHRASES,
    DEFAULT_SECRET_TOKEN_LABEL,
    DEFAULT_SECRET_TOKEN_VERSION,
    DEFAULT_SPACY_MODEL,
    DEFAULT_REQUIRE_SPACY_MODEL,
    PrivacyGatewaySettings,
    get_settings,
)
from privacy_gateway.errors import (
    ImageCryptoError,
    PrivacyGatewayError,
    TextCryptoError,
    TextCryptoKeyError,
    UnsupportedPayloadTypeError,
)
from privacy_gateway.services.image_crypto import ImageCryptoService
from privacy_gateway.services.pii_detection import PiiDetectionService, PiiSpan
from privacy_gateway.services.presidio_crypto import TextCryptoService
from privacy_gateway.services.privacy_text import TextPrivacyService
from privacy_gateway.services.privacy_tokens import SecretTokenService
from privacy_gateway.services.sensitive_words import SensitiveMatch, SensitiveWordService


_UNSUPPORTED_PAYLOAD_MESSAGE = "unsupported payload type"


def _sanitize_sensitive_phrases(raw_phrases: Sequence[str] | None) -> list[str] | None:
    """Normalize and drop blank phrases.

    Returns:
    - ``None`` when callers did not provide custom phrases, so defaults are preserved.
    - an explicit empty list when callers passed phrases but all entries were blank.
    """

    if raw_phrases is None:
        return None

    cleaned = [phrase.strip() for phrase in raw_phrases if isinstance(phrase, str)]
    return [phrase for phrase in cleaned if phrase]


@dataclass(frozen=True)
class CryptoOperationResult:
    """Result returned by core crypto operations."""

    type: str
    content: str
    crypto_key: str


@dataclass(frozen=True)
class FilterDecision:
    """Decision object for sensitive-content filtering."""

    blocked: bool
    match: SensitiveMatch | None = None

    @classmethod
    def allow(cls) -> "FilterDecision":
        return cls(blocked=False)

    @classmethod
    def block(cls, match: SensitiveMatch) -> "FilterDecision":
        return cls(blocked=True, match=match)


@dataclass(frozen=True)
class TextProcessingError:
    """Normalized text-processing error details for gateway integrations."""

    code: str
    message: str


@dataclass(frozen=True)
class TextProcessingResult:
    """Result returned by inbound/outbound text processing helpers.

    ``content`` contains the transformed text only for successful, non-blocked
    processing. ``error`` intentionally contains only normalized details and
    never stores the crypto key used for the operation.
    """

    content: str
    decision: FilterDecision
    error: TextProcessingError | None = None


class SensitiveTextStreamDetector:
    """Stateful streaming detector for text content."""

    def __init__(self, phrases: Sequence[str], max_window: int) -> None:
        self._service = SensitiveWordService(list(phrases))
        self._max_window = max(int(max_window), 1)
        self._buffer = ""

    def feed(self, chunk: str) -> FilterDecision:
        """Consume one chunk and return a blocking decision if it triggers a match."""

        if not chunk:
            return FilterDecision.allow()

        combined = f"{self._buffer}{chunk}"

        # Check full pre-truncation candidate so oversized chunks do not miss a match.
        match = self._service.find(combined)
        if match:
            return FilterDecision.block(match)

        if len(combined) > self._max_window:
            combined = combined[-self._max_window :]

        self._buffer = combined
        return FilterDecision.allow()


class PrivacyGatewayFilter:
    """Pure recognition/filter/crypto primitives for embedding in gateway plugins."""

    def __init__(
        self,
        *,
        sensitive_phrases: Sequence[str] | None = None,
        max_sensitive_stream_window: int = 4096,
        crypto_key: str | None = None,
        privacy_password: str | None = None,
        pii_entities: Sequence[str] | None = None,
        secret_token_label: str = DEFAULT_SECRET_TOKEN_LABEL,
        secret_token_version: str = DEFAULT_SECRET_TOKEN_VERSION,
        spacy_model: str = DEFAULT_SPACY_MODEL,
        require_spacy_model: bool = DEFAULT_REQUIRE_SPACY_MODEL,
    ) -> None:
        sanitized_phrases = _sanitize_sensitive_phrases(sensitive_phrases)
        self._sensitive_phrases = (
            list(DEFAULT_PROMPT_INJECTION_PHRASES)
            if sanitized_phrases is None
            else sanitized_phrases
        )
        self._max_sensitive_stream_window = max(int(max_sensitive_stream_window), 1)
        self._crypto_key = crypto_key
        self._privacy_password = privacy_password or crypto_key
        self._text_crypto = TextCryptoService()
        self._image_crypto = ImageCryptoService()
        self._sensitive = SensitiveWordService(self._sensitive_phrases)
        self._secret_tokens = SecretTokenService(
            crypto=self._text_crypto,
            label=secret_token_label,
            version=secret_token_version,
        )
        self._privacy_text = TextPrivacyService(
            token_service=self._secret_tokens,
            detector=PiiDetectionService(
                entities=pii_entities or DEFAULT_PII_ENTITIES,
                token_service=self._secret_tokens,
                spacy_model=spacy_model,
                require_spacy_model=require_spacy_model,
            ),
        )

    @classmethod
    def from_settings(cls, settings: PrivacyGatewaySettings | None = None) -> "PrivacyGatewayFilter":
        """Create a filter instance from environment-backed settings if available."""

        if settings is None:
            settings = get_settings()

        return cls(
            sensitive_phrases=settings.prompt_injection_phrases,
            max_sensitive_stream_window=settings.max_sensitive_stream_window,
            crypto_key=getattr(settings, "crypto_key", None),
            privacy_password=getattr(settings, "privacy_password", None),
            pii_entities=getattr(settings, "pii_entities", None),
            secret_token_label=getattr(settings, "secret_token_label", DEFAULT_SECRET_TOKEN_LABEL),
            secret_token_version=getattr(settings, "secret_token_version", DEFAULT_SECRET_TOKEN_VERSION),
            spacy_model=getattr(settings, "spacy_model", DEFAULT_SPACY_MODEL),
            require_spacy_model=getattr(settings, "require_spacy_model", False),
        )

    def _resolve_crypto_key(self, crypto_key: str | None) -> str:
        if crypto_key is not None:
            return crypto_key
        if self._crypto_key is not None:
            return self._crypto_key
        raise TextCryptoKeyError("crypto_key is required")

    def _resolve_privacy_password(self, privacy_password: str | None = None, crypto_key: str | None = None) -> str:
        if privacy_password is not None:
            return privacy_password
        if crypto_key is not None:
            return crypto_key
        if self._privacy_password is not None:
            return self._privacy_password
        raise TextCryptoKeyError("privacy password is required")

    def encrypt_text(self, content: str, crypto_key: str | None = None) -> str:
        """Encrypt text without returning or storing the crypto key in a result object."""

        return self._text_crypto.encrypt(content, self._resolve_crypto_key(crypto_key))

    def decrypt_text(self, content: str, crypto_key: str | None = None) -> str:
        """Decrypt text without returning or storing the crypto key in a result object."""

        return self._text_crypto.decrypt(content, self._resolve_crypto_key(crypto_key))

    def encrypt_payload(self, payload_type: str, content: str, crypto_key: str) -> CryptoOperationResult:
        """Encrypt text/image content and return an opaque payload result."""

        if payload_type == "text":
            content = self.encrypt_text(content, crypto_key)
        elif payload_type == "image":
            content = self._image_crypto.encrypt(content, crypto_key)
        else:
            raise UnsupportedPayloadTypeError(_UNSUPPORTED_PAYLOAD_MESSAGE)

        return CryptoOperationResult(type=payload_type, content=content, crypto_key=crypto_key)

    def decrypt_payload(self, payload_type: str, content: str, crypto_key: str) -> CryptoOperationResult:
        """Restore encrypted content and return an opaque payload result."""

        if payload_type == "text":
            content = self.decrypt_text(content, crypto_key)
        elif payload_type == "image":
            content = self._image_crypto.decrypt(content, crypto_key)
        else:
            raise UnsupportedPayloadTypeError(_UNSUPPORTED_PAYLOAD_MESSAGE)

        return CryptoOperationResult(type=payload_type, content=content, crypto_key=crypto_key)

    def restore_payload(self, payload_type: str, content: str, crypto_key: str) -> CryptoOperationResult:
        """Alias for ``decrypt_payload`` for restoration-first call sites."""

        return self.decrypt_payload(payload_type, content, crypto_key)

    def process_inbound_text(
        self,
        content: str,
        *,
        crypto_key: str | None = None,
        encrypted: bool = False,
    ) -> TextProcessingResult:
        """Decrypt encrypted inbound text when requested, then check it for blocking phrases.

        This legacy helper is kept for existing integrations. New integrations
        should prefer :meth:`process_inbound_privacy_text`, which detects and
        restores ``<secret:1:...>`` tokens without a special header.
        """

        try:
            plaintext = self.decrypt_text(content, crypto_key) if encrypted and content else content
        except TextCryptoError as exc:
            return TextProcessingResult(
                content="",
                decision=FilterDecision.allow(),
                error=TextProcessingError(code="text_decryption_failed", message=str(exc)),
            )

        decision = self.check_text(plaintext)
        return TextProcessingResult(content=plaintext if not decision.blocked else "", decision=decision)

    def process_outbound_text(
        self,
        content: str,
        *,
        crypto_key: str | None = None,
        encrypt: bool = True,
    ) -> TextProcessingResult:
        """Check upstream text for blocking phrases, then encrypt successful output when requested."""

        decision = self.check_text(content)
        if decision.blocked:
            return TextProcessingResult(content="", decision=decision)

        if not encrypt or not content:
            return TextProcessingResult(content=content, decision=decision)

        try:
            return TextProcessingResult(
                content=self.encrypt_text(content, crypto_key),
                decision=decision,
            )
        except TextCryptoError as exc:
            return TextProcessingResult(
                content="",
                decision=decision,
                error=TextProcessingError(code="text_encryption_failed", message=str(exc)),
            )

    def detect_pii(self, text: str) -> list[PiiSpan]:
        """Detect PII spans in natural-language text."""

        return self._privacy_text.detect(text)

    def protect_secret(self, content: str, *, privacy_password: str | None = None) -> str:
        """Encrypt one caller-selected value as a ``<secret:1:...>`` token."""

        return self._privacy_text.protect_secret(
            content,
            self._resolve_privacy_password(privacy_password=privacy_password),
        )

    def restore_privacy_text(self, content: str, *, privacy_password: str | None = None) -> str:
        """Restore all ``<secret:1:...>`` tokens in natural-language text."""

        return self._privacy_text.restore_text(
            content,
            self._resolve_privacy_password(privacy_password=privacy_password),
        )

    def protect_privacy_text(self, content: str, *, privacy_password: str | None = None) -> str:
        """Replace detected PII entities with reversible ``<secret:1:...>`` tokens."""

        return self._privacy_text.protect_text(
            content,
            self._resolve_privacy_password(privacy_password=privacy_password),
        )

    def process_inbound_privacy_text(
        self,
        content: str,
        *,
        privacy_password: str | None = None,
    ) -> TextProcessingResult:
        """Restore secret tokens automatically, then run prompt-injection checks."""

        try:
            plaintext = self.restore_privacy_text(content, privacy_password=privacy_password)
        except TextCryptoError as exc:
            return TextProcessingResult(
                content="",
                decision=FilterDecision.allow(),
                error=TextProcessingError(code="secret_token_decryption_failed", message=str(exc)),
            )

        decision = self.check_text(plaintext)
        return TextProcessingResult(content=plaintext if not decision.blocked else "", decision=decision)

    def process_outbound_privacy_text(
        self,
        content: str,
        *,
        privacy_password: str | None = None,
    ) -> TextProcessingResult:
        """Check plaintext output, then replace detected PII with secret tokens."""

        decision = self.check_text(content)
        if decision.blocked:
            return TextProcessingResult(content="", decision=decision)

        try:
            return TextProcessingResult(
                content=self.protect_privacy_text(content, privacy_password=privacy_password),
                decision=decision,
            )
        except TextCryptoError as exc:
            return TextProcessingResult(
                content="",
                decision=decision,
                error=TextProcessingError(code="secret_token_encryption_failed", message=str(exc)),
            )

    def check_text(self, text: str) -> FilterDecision:
        """Evaluate non-stream text and return a filter decision."""

        candidates = [text]
        masked = self._privacy_text.strip_tokens(text)
        if masked != text:
            candidates.append(masked)
        for candidate in candidates:
            match = self._sensitive.find(candidate)
            if match:
                return FilterDecision.block(match)
        return FilterDecision.allow()

    def stream_matcher(self, *, max_window: int | None = None) -> SensitiveTextStreamDetector:
        """Create a stateful streaming matcher for incremental chunk checks."""

        return SensitiveTextStreamDetector(
            phrases=self._sensitive_phrases,
            max_window=self._max_sensitive_stream_window if max_window is None else max_window,
        )

    def max_window(self) -> int:
        return self._max_sensitive_stream_window


__all__ = [
    "CryptoOperationResult",
    "FilterDecision",
    "PrivacyGatewayError",
    "PrivacyGatewayFilter",
    "SensitiveMatch",
    "SensitiveTextStreamDetector",
    "PiiSpan",
    "TextProcessingError",
    "TextProcessingResult",
    "UnsupportedPayloadTypeError",
    "TextCryptoError",
    "TextCryptoKeyError",
    "ImageCryptoError",
]
