from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from privacy_gateway import PrivacyGatewayFilter
from privacy_gateway.adapters.http import DEFAULT_ENCRYPTED_HEADER, build_block_error, is_encrypted_request
from privacy_gateway.config import get_settings

SETTINGS = get_settings()
FILTER = PrivacyGatewayFilter.from_settings(SETTINGS)
CRYPTO_KEY = SETTINGS.crypto_key or "WmZq4t7w!z%C&F)J"
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
        if lowered == DEFAULT_ENCRYPTED_HEADER.casefold():
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

        inbound = FILTER.process_inbound_text(
            _decode_text(incoming_body),
            crypto_key=CRYPTO_KEY,
            encrypted=is_encrypted_request(self.headers),
        )
        if inbound.error:
            self._send_error_json(400, f"request decryption failed: {inbound.error.message}")
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

        outbound = FILTER.process_outbound_text(
            _decode_text(response_body),
            crypto_key=CRYPTO_KEY,
            encrypt=True,
        )
        if outbound.decision.blocked:
            # Do not echo the upstream response or matched phrase back to the
            # client on reverse-injection failures; the upstream body is treated
            # as untrusted output.
            self._send_error_json(502, "reverse injection detected", include_match=False)
            return
        if outbound.error:
            self._send_error_json(500, f"response encryption failed: {outbound.error.message}")
            return

        response_headers["Content-Type"] = "text/plain; charset=utf-8"
        response_headers[DEFAULT_ENCRYPTED_HEADER] = "1"
        response_headers["X-Privacy-Proxy"] = "encrypted"
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
