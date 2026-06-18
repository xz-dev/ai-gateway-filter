from __future__ import annotations

"""Framework-free HTTP adapter primitives for privacy gateway integrations."""

from dataclasses import dataclass, field
from typing import Mapping

from privacy_gateway.lib import FilterDecision

DEFAULT_ENCRYPTED_HEADER = "X-Privacy-Encrypted"
DEFAULT_BLOCK_ERROR = "privacy_gateway_blocked"
DEFAULT_BLOCK_STATUS = 422
TRUE_HEADER_VALUES = frozenset({"1", "true", "yes", "on"})


@dataclass(frozen=True)
class HttpBlockError:
    """Plain HTTP block error payload plus status and headers."""

    status: int
    body: dict[str, object]
    headers: dict[str, str] = field(default_factory=dict)


def is_truthy_header(value: str | None) -> bool:
    """Return whether an HTTP header value should be interpreted as enabled."""

    return bool(value and value.strip().casefold() in TRUE_HEADER_VALUES)


def get_header(headers: Mapping[str, str] | None, name: str) -> str | None:
    """Fetch a header case-insensitively from a plain mapping."""

    if headers is None:
        return None

    wanted = name.casefold()
    for key, value in headers.items():
        if key.casefold() == wanted:
            return value
    return None


def is_encrypted_request(
    headers: Mapping[str, str] | None,
    *,
    header_name: str = DEFAULT_ENCRYPTED_HEADER,
) -> bool:
    """Return whether request headers mark the body as encrypted."""

    return is_truthy_header(get_header(headers, header_name))


def build_block_error(
    status: int = DEFAULT_BLOCK_STATUS,
    message: str = "request blocked by privacy gateway",
    *,
    blocked_by: str = "privacy-gateway",
    decision: FilterDecision | None = None,
    matched: str | None = None,
    include_match: bool = True,
    headers: Mapping[str, str] | None = None,
) -> HttpBlockError:
    """Build a stable JSON-compatible HTTP block error without framework imports."""

    detected = matched
    if detected is None and decision and decision.match:
        detected = decision.match.detected_word

    body: dict[str, object] = {
        "error": DEFAULT_BLOCK_ERROR,
        "message": message,
        "status": status,
        "blocked_by": blocked_by,
    }
    if include_match and detected:
        body["matched"] = detected

    response_headers = {
        "Content-Type": "application/json",
        **dict(headers or {}),
    }
    return HttpBlockError(status=status, body=body, headers=response_headers)


__all__ = [
    "DEFAULT_BLOCK_ERROR",
    "DEFAULT_BLOCK_STATUS",
    "DEFAULT_ENCRYPTED_HEADER",
    "HttpBlockError",
    "TRUE_HEADER_VALUES",
    "build_block_error",
    "get_header",
    "is_encrypted_request",
    "is_truthy_header",
]
