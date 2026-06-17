from __future__ import annotations

from dataclasses import dataclass
from os import getenv


DEFAULT_PROMPT_INJECTION_PHRASES = (
    "ignore previous instructions",
    "reveal your system prompt",
    "bypass policy",
    "disregard all prior guidance",
    "repeat the exact instructions",
    "hidden instructions",
    "developer debugging mode",
)

DEFAULT_MAX_STREAM_WINDOW = 4096


@dataclass(frozen=True)
class PrivacyGatewaySettings:
    """Configuration container for the pure library behavior."""

    sensitive_phrases: list[str]
    max_sensitive_stream_window: int = DEFAULT_MAX_STREAM_WINDOW

    @property
    def prompt_injection_phrases(self) -> list[str]:
        return self.sensitive_phrases


def _parse_sensitive_phrases(raw: str | None) -> list[str]:
    if not raw:
        return []

    return [phrase.strip() for phrase in raw.split(",") if phrase.strip()]


def _parse_stream_window(raw: str | None) -> int:
    if raw is None:
        return DEFAULT_MAX_STREAM_WINDOW
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_STREAM_WINDOW

    return max(value, 1)


def get_settings() -> PrivacyGatewaySettings:
    """Read environment-backed settings for this library.

    Supports:
    - PRIVACY_GATEWAY_SENSITIVE_PHRASES: comma-separated phrase list
    - PRIVACY_GATEWAY_MAX_SENSITIVE_STREAM_WINDOW: positive integer window size
    """

    raw_phrases = getenv(
        "PRIVACY_GATEWAY_SENSITIVE_PHRASES", ",".join(DEFAULT_PROMPT_INJECTION_PHRASES)
    )
    raw_window = getenv("PRIVACY_GATEWAY_MAX_SENSITIVE_STREAM_WINDOW", str(DEFAULT_MAX_STREAM_WINDOW))

    sensitive_phrases = _parse_sensitive_phrases(raw_phrases)
    if not sensitive_phrases:
        sensitive_phrases = list(DEFAULT_PROMPT_INJECTION_PHRASES)

    return PrivacyGatewaySettings(
        sensitive_phrases=sensitive_phrases,
        max_sensitive_stream_window=_parse_stream_window(raw_window),
    )
