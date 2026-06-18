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
DEFAULT_SECRET_TOKEN_LABEL = "secret"
DEFAULT_SECRET_TOKEN_VERSION = "1"
DEFAULT_SPACY_MODEL = "en_core_web_sm"
DEFAULT_REQUIRE_SPACY_MODEL = True
DEFAULT_PII_ENTITIES = (
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "CRYPTO",
    "IBAN_CODE",
    "IP_ADDRESS",
    "LOCATION",
    "NRP",
    "URL",
    "US_BANK_NUMBER",
    "US_DRIVER_LICENSE",
    "US_ITIN",
    "US_PASSPORT",
    "US_SSN",
    "CN_ID_CARD",
    "CN_PHONE_NUMBER",
    "SECRET_VALUE",
)


@dataclass(frozen=True)
class PrivacyGatewaySettings:
    """Configuration container for the pure library behavior."""

    sensitive_phrases: list[str]
    max_sensitive_stream_window: int = DEFAULT_MAX_STREAM_WINDOW
    crypto_key: str | None = None
    privacy_password: str | None = None
    pii_entities: list[str] | None = None
    secret_token_label: str = DEFAULT_SECRET_TOKEN_LABEL
    secret_token_version: str = DEFAULT_SECRET_TOKEN_VERSION
    spacy_model: str = DEFAULT_SPACY_MODEL
    require_spacy_model: bool = DEFAULT_REQUIRE_SPACY_MODEL

    @property
    def prompt_injection_phrases(self) -> list[str]:
        return self.sensitive_phrases


def _parse_csv(raw: str | None) -> list[str]:
    if not raw:
        return []

    return [item.strip() for item in raw.split(",") if item.strip()]


def _parse_sensitive_phrases(raw: str | None) -> list[str]:
    return _parse_csv(raw)


def _parse_bool(raw: str | None, *, default: bool = False) -> bool:
    if raw is None:
        return default
    return raw.strip().casefold() in {"1", "true", "yes", "on"}


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
    - PRIVACY_GATEWAY_SENSITIVE_PHRASES: comma-separated prompt-injection phrase list
    - PRIVACY_GATEWAY_MAX_SENSITIVE_STREAM_WINDOW: positive integer window size
    - PRIVACY_GATEWAY_CRYPTO_KEY: optional legacy full-text AES key
    - PRIVACY_GATEWAY_PASSWORD: optional password for reversible ``<secret:1:...>`` tokens
    - PRIVACY_GATEWAY_PII_ENTITIES: comma-separated Presidio entity types to detect
    - PRIVACY_GATEWAY_SPACY_MODEL: prepared spaCy model name/path, default ``en_core_web_sm``
    - PRIVACY_GATEWAY_REQUIRE_SPACY_MODEL: fail startup if model is missing, default true
    """

    raw_phrases = getenv(
        "PRIVACY_GATEWAY_SENSITIVE_PHRASES", ",".join(DEFAULT_PROMPT_INJECTION_PHRASES)
    )
    raw_window = getenv("PRIVACY_GATEWAY_MAX_SENSITIVE_STREAM_WINDOW", str(DEFAULT_MAX_STREAM_WINDOW))
    raw_crypto_key = getenv("PRIVACY_GATEWAY_CRYPTO_KEY")
    raw_privacy_password = getenv("PRIVACY_GATEWAY_PASSWORD")
    raw_pii_entities = getenv("PRIVACY_GATEWAY_PII_ENTITIES")
    raw_spacy_model = getenv("PRIVACY_GATEWAY_SPACY_MODEL", DEFAULT_SPACY_MODEL)
    raw_require_spacy_model = getenv("PRIVACY_GATEWAY_REQUIRE_SPACY_MODEL")

    sensitive_phrases = _parse_sensitive_phrases(raw_phrases)
    if not sensitive_phrases:
        sensitive_phrases = list(DEFAULT_PROMPT_INJECTION_PHRASES)

    pii_entities = _parse_csv(raw_pii_entities)
    if not pii_entities:
        pii_entities = list(DEFAULT_PII_ENTITIES)

    return PrivacyGatewaySettings(
        sensitive_phrases=sensitive_phrases,
        max_sensitive_stream_window=_parse_stream_window(raw_window),
        crypto_key=raw_crypto_key if raw_crypto_key else None,
        privacy_password=(raw_privacy_password or raw_crypto_key or None),
        pii_entities=pii_entities,
        secret_token_label=DEFAULT_SECRET_TOKEN_LABEL,
        secret_token_version=DEFAULT_SECRET_TOKEN_VERSION,
        spacy_model=raw_spacy_model or DEFAULT_SPACY_MODEL,
        require_spacy_model=_parse_bool(raw_require_spacy_model, default=DEFAULT_REQUIRE_SPACY_MODEL),
    )
