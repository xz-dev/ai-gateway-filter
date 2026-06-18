from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

ADMIN_URL = os.environ.get("APISIX_ADMIN_URL", "http://apisix:9180/apisix/admin").rstrip("/")
ADMIN_KEY = os.environ.get("APISIX_ADMIN_KEY", "privacy-gateway-admin-key")
PLUGIN_NAME = os.environ.get("PRIVACY_PLUGIN_NAME", "privacy-gateway-guard")


def _request(method: str, path: str, payload: dict | None = None) -> tuple[int, str]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{ADMIN_URL}{path}",
        data=data,
        method=method,
        headers={
            "X-API-KEY": ADMIN_KEY,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            body = response.read().decode("utf-8", errors="replace")
            return response.status, body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, body


def wait_for_admin_api(timeout_seconds: int = 90) -> None:
    deadline = time.time() + timeout_seconds
    last_error = ""
    while time.time() < deadline:
        try:
            status, body = _request("GET", "/routes")
            if status < 500:
                print(f"APISIX Admin API is ready: status={status}")
                return
            last_error = body
        except Exception as exc:  # noqa: BLE001 - startup retry loop
            last_error = repr(exc)
        time.sleep(1)
    raise TimeoutError(f"APISIX Admin API did not become ready: {last_error}")


def configure_route() -> None:
    plugin_conf = {
        "enabled": True,
        "block_status": 422,
        "inspect_content_types": [
            "text/plain",
            "application/json",
            "application/x-www-form-urlencoded",
        ],
        "skip_when_encrypted_header": "X-Privacy-Encrypted",
    }
    route = {
        "name": "privacy-gateway-proxy",
        "uri": "/*",
        "plugins": {
            "ext-plugin-pre-req": {
                "conf": [
                    {
                        "name": PLUGIN_NAME,
                        "value": json.dumps(plugin_conf, separators=(",", ":")),
                    }
                ],
                "allow_degradation": False,
            }
        },
        "upstream": {
            "type": "roundrobin",
            "nodes": {
                "privacy-proxy:8080": 1,
            },
        },
    }
    status, body = _request("PUT", "/routes/privacy-gateway-proxy", route)
    print(f"PUT route status={status}")
    print(body)
    if status >= 300:
        raise SystemExit(status)


def main() -> int:
    wait_for_admin_api()
    configure_route()
    print("APISIX route configured")
    return 0


if __name__ == "__main__":
    sys.exit(main())
