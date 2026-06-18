from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from privacy_gateway import FilterDecision, PrivacyGatewayFilter, TextProcessingError, TextProcessingResult
from privacy_gateway.adapters.http import DEFAULT_ENCRYPTED_HEADER, build_block_error
from privacy_gateway.config import get_settings

SETTINGS = get_settings()
FILTER = PrivacyGatewayFilter.from_settings(SETTINGS)
if not SETTINGS.privacy_password:
    raise RuntimeError("PRIVACY_GATEWAY_PASSWORD must be set to a high-entropy secret before startup")
PRIVACY_PASSWORD = SETTINGS.privacy_password
PRIVACY_PROTECTION_HEADER = "X-Privacy-Protection"
SENSITIVE_JSON_KEYS = {
    "name",
    "full_name",
    "real_name",
    "username",
    "user_name",
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "address",
    "id_card",
    "idcard",
    "identity_card",
    "phone",
    "mobile",
    "email",
    "姓名",
    "名字",
    "用户名",
    "密码",
    "口令",
    "密钥",
    "地址",
    "身份证",
    "身份证号",
    "手机号",
    "电话",
    "邮箱",
}
VALUE_LEVEL_JSON_KEYS = {
    "body",
    "message",
    "messages",
    "content",
    "text",
    "prompt",
    "completion",
    "response",
    "input",
    "output",
    "arguments",
    "tool_call",
    "tool_calls",
    "用户消息",
    "消息",
    "内容",
    "提示词",
    "回答",
}
UPSTREAM_HOST = os.environ.get("PRIVACY_PROXY_UPSTREAM_HOST", "upstream")
UPSTREAM_PORT = int(os.environ.get("PRIVACY_PROXY_UPSTREAM_PORT", "8081"))
LISTEN_HOST = os.environ.get("PRIVACY_PROXY_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("PRIVACY_PROXY_PORT", "8080"))
MAX_BODY_BYTES = int(os.environ.get("PRIVACY_PROXY_MAX_BODY_BYTES", str(1024 * 1024)))
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "host",
}


def _json_bytes(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _read_body(handler: BaseHTTPRequestHandler) -> bytes:
    raw_length = handler.headers.get("Content-Length")
    if not raw_length:
        return b""
    try:
        length = int(raw_length)
    except ValueError as exc:
        raise ValueError("invalid Content-Length") from exc
    if length > MAX_BODY_BYTES:
        raise ValueError(f"request body too large: {length} bytes > {MAX_BODY_BYTES} bytes")
    return handler.rfile.read(length)


def _decode_text(body: bytes) -> str:
    return body.decode("utf-8", errors="replace")


def _headers_for_upstream(handler: BaseHTTPRequestHandler, body: bytes) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in handler.headers.items():
        lowered = key.casefold()
        if lowered in HOP_BY_HOP_HEADERS:
            continue
        # Old whole-body encryption markers are ignored by the automatic token
        # flow and are not forwarded upstream.
        if lowered == DEFAULT_ENCRYPTED_HEADER.casefold():
            continue
        headers[key] = value
    headers["Host"] = f"{UPSTREAM_HOST}:{UPSTREAM_PORT}"
    headers["Content-Length"] = str(len(body))
    headers["X-Privacy-Proxy"] = "restored"
    return headers


def _copy_response_headers(source: Any) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in source.headers.items():
        lowered = key.casefold()
        if lowered in HOP_BY_HOP_HEADERS:
            continue
        if lowered in {"content-encoding", "content-md5", "etag"}:
            continue
        headers[key] = value
    return headers


def _transform_text_value(value: str, *, inbound: bool) -> TextProcessingResult:
    if inbound:
        return FILTER.process_inbound_privacy_text(value, privacy_password=PRIVACY_PASSWORD)
    return FILTER.process_outbound_privacy_text(value, privacy_password=PRIVACY_PASSWORD)


def _normalized_json_key(key: str | None) -> str:
    return "" if key is None else key.strip().casefold().replace("-", "_")


def _is_sensitive_json_key(key: str | None) -> bool:
    normalized = _normalized_json_key(key)
    return normalized in SENSITIVE_JSON_KEYS or (key or "").strip() in SENSITIVE_JSON_KEYS


def _is_value_level_json_key(key: str | None) -> bool:
    normalized = _normalized_json_key(key)
    return normalized in VALUE_LEVEL_JSON_KEYS or (key or "").strip() in VALUE_LEVEL_JSON_KEYS


def _allow_json_string_unchanged(value: str) -> TextProcessingResult:
    decision = FILTER.check_text(value)
    return TextProcessingResult(content="" if decision.blocked else value, decision=decision)


def _transform_json_string(value: str, *, key: str | None, inbound: bool) -> TextProcessingResult:
    sensitive_key = _is_sensitive_json_key(key)
    value_level_key = _is_value_level_json_key(key)

    if inbound:
        if sensitive_key or value_level_key:
            return _transform_text_value(value, inbound=True)
        return _allow_json_string_unchanged(value)

    # Gateway-owned JSON field rule: if a response field name is known to carry
    # a secret (e.g. password/name/address), protect the complete value. The core
    # library remains natural-language only and does not know JSON keys.
    if sensitive_key:
        decision = FILTER.check_text(value)
        if decision.blocked:
            return TextProcessingResult(content="", decision=decision)
        try:
            return TextProcessingResult(
                content=FILTER.protect_secret(value, privacy_password=PRIVACY_PASSWORD),
                decision=decision,
            )
        except Exception as exc:  # noqa: BLE001 - normalize gateway response protection failures
            return TextProcessingResult(
                content="",
                decision=decision,
                error=TextProcessingError(code="secret_token_encryption_failed", message=str(exc)),
            )

    if value_level_key:
        return _transform_text_value(value, inbound=False)
    return _allow_json_string_unchanged(value)


def _transform_json_value(value: Any, *, inbound: bool, key: str | None = None) -> tuple[Any, TextProcessingResult | None]:
    """Gateway-side JSON traversal: pass selected string values to the core lib."""

    if isinstance(value, str):
        result = _transform_json_string(value, key=key, inbound=inbound)
        if result.error or result.decision.blocked:
            return None, result
        return result.content, None
    if isinstance(value, list):
        transformed_items = []
        for item in value:
            transformed, result = _transform_json_value(item, inbound=inbound)
            if result is not None:
                return None, result
            transformed_items.append(transformed)
        return transformed_items, None
    if isinstance(value, dict):
        transformed_dict: dict[str, Any] = {}
        for item_key, item in value.items():
            transformed, result = _transform_json_value(item, inbound=inbound, key=str(item_key))
            if result is not None:
                return None, result
            transformed_dict[item_key] = transformed
        return transformed_dict, None
    return value, None


def _is_json_body(text: str) -> bool:
    if not text:
        return False
    try:
        json.loads(text)
    except json.JSONDecodeError:
        return False
    return True


def _transform_body(text: str, *, inbound: bool) -> TextProcessingResult:
    """Process JSON bodies in the gateway and plain text in the library.

    The core library intentionally stays natural-language only. This gateway
    parses JSON first, then invokes the library only for selected string values.
    """

    if not text:
        return TextProcessingResult(content=text, decision=FilterDecision.allow())

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return _transform_text_value(text, inbound=inbound)

    transformed, result = _transform_json_value(parsed, inbound=inbound)
    if result is not None:
        return result
    return TextProcessingResult(
        content=json.dumps(transformed, ensure_ascii=False, separators=(",", ":")),
        decision=FilterDecision.allow(),
    )


class PrivacyProxyHandler(BaseHTTPRequestHandler):
    server_version = "PrivacyProxy/0.1"

    def _send(self, status: int, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        merged = {"Content-Length": str(len(body))}
        if headers:
            merged.update(headers)
        for key, value in merged.items():
            self.send_header(key, value)
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _send_error_json(
        self,
        status: int,
        message: str,
        *,
        matched: str | None = None,
        include_match: bool = True,
    ) -> None:
        error = build_block_error(
            status,
            message,
            blocked_by="privacy-proxy",
            matched=matched,
            include_match=include_match,
            headers={"X-Privacy-Proxy": "blocked"},
        )
        self._send(error.status, _json_bytes(error.body), error.headers)

    def _handle(self) -> None:
        try:
            incoming_body = _read_body(self)
        except ValueError as exc:
            self._send_error_json(413, str(exc))
            return

        inbound = _transform_body(_decode_text(incoming_body), inbound=True)
        if inbound.error:
            self._send_error_json(400, f"request secret-token restore failed: {inbound.error.message}")
            return
        if inbound.decision.blocked:
            matched = inbound.decision.match.detected_word if inbound.decision.match else None
            self._send_error_json(422, "forward injection detected", matched=matched)
            return

        upstream_body = inbound.content.encode("utf-8")
        upstream_url = f"http://{UPSTREAM_HOST}:{UPSTREAM_PORT}{self.path}"
        upstream_headers = _headers_for_upstream(self, upstream_body)
        request = urllib.request.Request(
            upstream_url,
            data=upstream_body if self.command not in {"GET", "HEAD"} else None,
            method=self.command,
            headers=upstream_headers,
        )

        try:
            with urllib.request.urlopen(request, timeout=10) as upstream_response:
                upstream_status = upstream_response.status
                response_headers = _copy_response_headers(upstream_response)
                response_body = upstream_response.read()
        except urllib.error.HTTPError as exc:
            upstream_status = exc.code
            response_headers = _copy_response_headers(exc)
            response_body = exc.read()
        except Exception as exc:  # noqa: BLE001 - normalize upstream errors for proxy clients
            self._send_error_json(502, f"upstream request failed: {exc}")
            return

        response_text = _decode_text(response_body)
        response_was_json = _is_json_body(response_text)
        outbound = _transform_body(response_text, inbound=False)
        if outbound.decision.blocked:
            # Do not echo the upstream response or matched phrase back to the
            # client on reverse-injection failures; the upstream body is treated
            # as untrusted output.
            self._send_error_json(502, "reverse injection detected", include_match=False)
            return
        if outbound.error:
            self._send_error_json(500, f"response privacy protection failed: {outbound.error.message}")
            return

        response_headers["Content-Type"] = "application/json; charset=utf-8" if response_was_json else "text/plain; charset=utf-8"
        response_headers[PRIVACY_PROTECTION_HEADER] = "secret-tokenized"
        response_headers["X-Privacy-Proxy"] = "protected"
        self._send(upstream_status, outbound.content.encode("utf-8"), response_headers)

    def do_GET(self) -> None:  # noqa: N802
        self._handle()

    def do_POST(self) -> None:  # noqa: N802
        self._handle()

    def do_PUT(self) -> None:  # noqa: N802
        self._handle()

    def do_PATCH(self) -> None:  # noqa: N802
        self._handle()

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle()

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stdout.write("privacy-proxy: " + fmt % args + "\n")
        sys.stdout.flush()


def main() -> int:
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), PrivacyProxyHandler)
    print(f"privacy-proxy listening on {LISTEN_HOST}:{LISTEN_PORT}, upstream={UPSTREAM_HOST}:{UPSTREAM_PORT}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
