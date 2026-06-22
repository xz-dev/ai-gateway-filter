from __future__ import annotations

"""Natural-language privacy protection and restoration helpers."""

from privacy_gateway.services.pii_detection import PiiDetectionService, PiiSpan
from privacy_gateway.services.privacy_tokens import SecretTokenService, SecretTokenStreamRestorer


class TextPrivacyService:
    """Protect PII entities in plain text using reversible secret tokens."""

    def __init__(
        self,
        *,
        detector: PiiDetectionService | None = None,
        token_service: SecretTokenService | None = None,
    ) -> None:
        self._token_service = token_service or SecretTokenService()
        self._detector = detector or PiiDetectionService(token_service=self._token_service)

    @property
    def token_service(self) -> SecretTokenService:
        return self._token_service

    def detect(self, text: str) -> list[PiiSpan]:
        return self._detector.detect(text)

    def protect_text(self, text: str, password: str) -> str:
        """Replace detected PII spans in natural-language text with tokens."""

        if not text:
            return text
        spans = [(span.start, span.end) for span in self.detect(text)]
        return self._token_service.replace_spans(text, spans, password)

    def protect_secret(self, value: str, password: str) -> str:
        """Protect one caller-selected value as a complete secret token."""

        return self._token_service.encrypt_secret(value, password)

    def restore_text(self, text: str, password: str) -> str:
        """Restore all secret tokens in text."""

        if not text:
            return text
        return self._token_service.restore_text(text, password)

    def restore_text_best_effort(self, text: str, password: str | None = None) -> str:
        """Restore all supported secret tokens, preserving undecryptable tokens unchanged."""

        if not text:
            return text
        return self._token_service.restore_text_best_effort(text, password)

    def stream_restorer(
        self,
        password: str | None = None,
        *,
        token_prefix: str | None = None,
        max_pending_token_chars: int | None = None,
    ) -> SecretTokenStreamRestorer:
        """Create an incremental secret-token restorer for streamed text."""

        kwargs = {}
        if max_pending_token_chars is not None:
            kwargs["max_pending_token_chars"] = max_pending_token_chars
        return SecretTokenStreamRestorer(
            token_service=self._token_service,
            password=password,
            token_prefix=token_prefix,
            **kwargs,
        )

    def strip_tokens(self, text: str, replacement: str = " <secret> ") -> str:
        """Mask token bodies before prompt-injection checks or logging."""

        return self._token_service.strip_tokens(text, replacement=replacement)


__all__ = ["TextPrivacyService"]
