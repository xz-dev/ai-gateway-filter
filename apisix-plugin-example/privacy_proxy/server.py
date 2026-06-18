from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from privacy_gateway import PrivacyGatewayError, PrivacyGatewayFilter
from privacy_gateway.config import get_settings

FILTER = PrivacyGatewayFilter.from_settings(get_settings())
CRYPTO_KEY = os.environ.get("PRIVACY_GATEWAY_CRYPTO_KEY", "WmZq4t7w!z%C&F)J")
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
TRUE_VALUES = {"1", "true", "yes", "on"}


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _is_truthy(value: str | None) -> bool:
    return bool(value and value.strip().casefold() in TRUE_VALUES)


def _error_payload(status: int, message: str, *, matched: str | None = None) -> bytes:
    payload: dict[str, Any] = {
        "error": "privacy_gateway_blocked",
        "message": message,
        "status": status,
        "blocked_by": "privacy-proxy",
    }
    if matched:
        payload["matched"] = matched
    return _json_bytes(payload)


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
        if lowered == "x-privacy-encrypted":
            continue
        headers[key] = value
    headers["Host"] = f"{UPSTREAM_HOST}:{UPSTREAM_PORT}"
    headers["Content-Length"] = str(len(body))
    headers["X-Privacy-Proxy"] = "decrypted"
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

    def _send_error_json(self, status: int, message: str, *, matched: str | None = None) -> None:
        body = _error_payload(status, message, matched=matched)
        self._send(
            status,
            body,
            {
                "Content-Type": "application/json",
                "X-Privacy-Proxy": "blocked",
            },
        )

    def _handle(self) -> None:
        try:
            incoming_body = _read_body(self)
        except ValueError as exc:
            self._send_error_json(413, str(exc))
            return

        incoming_text = _decode_text(incoming_body)
        encrypted_request = _is_truthy(self.headers.get("X-Privacy-Encrypted"))
        if encrypted_request and incoming_text:
            try:
                incoming_text = FILTER.decrypt_payload("text", incoming_text, CRYPTO_KEY).content
            except PrivacyGatewayError as exc:
                self._send_error_json(400, f"request decryption failed: {exc}")
                return

        request_decision = FILTER.check_text(incoming_text)
        if request_decision.blocked:
            matched = request_decision.match.detected_word if request_decision.match else None
            self._send_error_json(422, "forward injection detected", matched=matched)
            return

        upstream_body = incoming_text.encode("utf-8")
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
        response_decision = FILTER.check_text(response_text)
        if response_decision.blocked:
            # Do not echo the upstream response or matched phrase back to the
            # client on reverse-injection failures; the upstream body is treated
            # as untrusted output.
            self._send_error_json(502, "reverse injection detected")
            return

        if response_text:
            try:
                encrypted_body = FILTER.encrypt_payload("text", response_text, CRYPTO_KEY).content.encode("utf-8")
            except PrivacyGatewayError as exc:
                self._send_error_json(500, f"response encryption failed: {exc}")
                return
        else:
            encrypted_body = b""

        response_headers["Content-Type"] = "text/plain; charset=utf-8"
        response_headers["X-Privacy-Encrypted"] = "1"
        response_headers["X-Privacy-Proxy"] = "encrypted"
        self._send(upstream_status, encrypted_body, response_headers)

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
