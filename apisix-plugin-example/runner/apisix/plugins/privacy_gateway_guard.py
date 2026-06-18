from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from apisix.runner.http.request import Request
from apisix.runner.http.response import Response
from apisix.runner.plugin.core import PluginBase
from privacy_gateway import PrivacyGatewayFilter
from privacy_gateway.adapters.http import build_block_error, get_header
from privacy_gateway.config import get_settings

_DEFAULT_FILTER = PrivacyGatewayFilter.from_settings(get_settings())
_DEFAULT_INSPECT_CONTENT_TYPES = (
    "text/plain",
    "application/json",
    "application/x-www-form-urlencoded",
)


def _json_body(payload: dict[str, object]) -> str:
    return json.dumps(payload, separators=(",", ":"))


@lru_cache(maxsize=32)
def _custom_filter(phrases: tuple[str, ...]) -> PrivacyGatewayFilter:
    return PrivacyGatewayFilter(sensitive_phrases=list(phrases))


def _filter_for(conf: dict[str, Any]) -> PrivacyGatewayFilter:
    phrases = conf.get("sensitive_phrases")
    if isinstance(phrases, list):
        normalized = tuple(str(phrase).strip() for phrase in phrases if str(phrase).strip())
        if normalized:
            return _custom_filter(normalized)
    return _DEFAULT_FILTER


def _parse_conf(conf: Any) -> dict[str, Any]:
    if isinstance(conf, dict):
        return conf
    if not conf:
        return {}
    if isinstance(conf, bytes):
        conf = conf.decode("utf-8", errors="replace")
    if isinstance(conf, str):
        try:
            parsed = json.loads(conf)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _should_inspect(headers: dict[str, str], conf: dict[str, Any]) -> bool:
    content_type = (get_header(headers, "content-type") or "").split(";", 1)[0].strip().casefold()
    if not content_type:
        # If the client sends a body without Content-Type, assume text for safety.
        return True

    configured = conf.get("inspect_content_types", _DEFAULT_INSPECT_CONTENT_TYPES)
    if not isinstance(configured, list | tuple):
        configured = _DEFAULT_INSPECT_CONTENT_TYPES
    allowed = {str(item).strip().casefold() for item in configured if str(item).strip()}
    return content_type in allowed


class PrivacyGatewayGuard(PluginBase):
    """Fast pre-request APISIX external plugin for plaintext injection blocking.

    The full token restore/protect flow is implemented in the privacy proxy
    sidecar. This plugin is intentionally small and cheap: it blocks obvious
    plaintext injection attempts before APISIX spends time proxying the request.
    It never trusts or skips based on an encrypted marker header; ``<secret:1:...>``
    token contents are masked by ``PrivacyGatewayFilter.check_text``.
    """

    def name(self) -> str:
        return "privacy-gateway-guard"

    def config(self, conf: Any) -> dict[str, Any]:
        parsed = _parse_conf(conf)
        parsed.setdefault("enabled", True)
        parsed.setdefault("block_status", 422)
        parsed.setdefault("block_message", "request blocked by privacy gateway guard")
        return parsed

    def filter(self, conf: dict[str, Any], request: Request, response: Response) -> None:
        if not conf.get("enabled", True):
            return

        headers = request.get_headers() or {}
        if not _should_inspect(headers, conf):
            return

        body = request.get_body()
        if not body:
            return

        decision = _filter_for(conf).check_text(body)
        if not decision.blocked:
            return

        status = int(conf.get("block_status", 422))
        message = str(conf.get("block_message", "request blocked by privacy gateway guard"))
        matched = decision.match.detected_word if decision.match else None
        error = build_block_error(
            status,
            message,
            blocked_by="apisix-python-runner:privacy-gateway-guard",
            matched=matched,
        )
        response.set_status_code(error.status)
        response.set_header("Content-Type", "application/json")
        response.set_header("X-Privacy-Guard", "blocked")
        response.set_body(_json_body(error.body))
