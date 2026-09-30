#!/usr/bin/env python3
"""Refresh an OAuth bearer token in a Splunk Observability Cloud webhook."""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen


LOGGER = logging.getLogger("webhook_token_refresh")
TIMEOUT_SECONDS = 20
ERROR_BODY_LOG_LIMIT = 4000
READ_ONLY_INTEGRATION_FIELDS = {
    "created",
    "createdByName",
    "creator",
    "id",
    "lastUpdated",
    "lastUpdatedBy",
    "lastUpdatedByName",
}
SENSITIVE_KEY_PARTS = (
    "authorization",
    "token",
    "secret",
    "password",
    "credential",
    "api_key",
    "apikey",
    "cookie",
)


class RefreshError(RuntimeError):
    """An operation failed without including secret values in its message."""


def _safe_url(url: str) -> str:
    """Return a URL without query parameters or fragments, which can contain secrets."""
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _safe_request_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        key: ("[REDACTED]" if any(part in key.lower() for part in SENSITIVE_KEY_PARTS) else value)
        for key, value in headers.items()
    }


def _safe_response_headers(headers: Any) -> dict[str, str]:
    useful_headers = {"accept", "allow", "content-length", "content-type", "date", "server", "vary"}
    return {key: value for key, value in headers.items() if key.lower() in useful_headers}


def _sensitive_values(headers: dict[str, str], body: bytes | None) -> list[str]:
    values = [
        value
        for key, value in headers.items()
        if any(part in key.lower() for part in SENSITIVE_KEY_PARTS) and value
    ]
    if not body:
        return values

    raw_body = body.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(raw_body)
    except json.JSONDecodeError:
        parsed = None

    def collect_json(item: Any) -> None:
        if isinstance(item, dict):
            is_authorization_header = str(item.get("headerKey", "")).lower() == "authorization"
            for key, value in item.items():
                key_is_sensitive = any(part in str(key).lower() for part in SENSITIVE_KEY_PARTS)
                if (key_is_sensitive or (is_authorization_header and key == "headerValue")) and isinstance(value, str):
                    values.append(value)
                else:
                    collect_json(value)
        elif isinstance(item, list):
            for value in item:
                collect_json(value)

    if parsed is not None:
        collect_json(parsed)
    else:
        for key, value in parse_qsl(raw_body, keep_blank_values=True):
            if any(part in key.lower() for part in SENSITIVE_KEY_PARTS) and value:
                values.append(value)

    return sorted(set(values), key=len, reverse=True)


def _safe_error_body(raw: bytes, headers: dict[str, str], request_body: bytes | None) -> str:
    text = raw[:ERROR_BODY_LOG_LIMIT].decode("utf-8", errors="replace")
    for secret in _sensitive_values(headers, request_body):
        text = text.replace(secret, "[REDACTED]")

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return text

    def redact_json(item: Any) -> Any:
        if isinstance(item, dict):
            return {
                key: ("[REDACTED]" if any(part in str(key).lower() for part in SENSITIVE_KEY_PARTS)
                      else redact_json(value))
                for key, value in item.items()
            }
        if isinstance(item, list):
            return [redact_json(value) for value in item]
        return item

    return json.dumps(redact_json(parsed), ensure_ascii=False)


def _safe_request_body(body: bytes | None) -> str:
    if not body:
        return "<empty>"
    text = body.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        form_fields = parse_qsl(text, keep_blank_values=True)
        if not form_fields:
            return text[:ERROR_BODY_LOG_LIMIT] + ("… [truncated]" if len(text) > ERROR_BODY_LOG_LIMIT else "")
        safe_fields = [
            (key, "[REDACTED]" if any(part in key.lower() for part in SENSITIVE_KEY_PARTS) else value)
            for key, value in form_fields
        ]
        text = urlencode(safe_fields, doseq=True)
        return text[:ERROR_BODY_LOG_LIMIT] + ("… [truncated]" if len(text) > ERROR_BODY_LOG_LIMIT else "")

    def redact_json(item: Any) -> Any:
        if isinstance(item, dict):
            is_authorization_header = str(item.get("headerKey", "")).lower() == "authorization"
            return {
                key: (
                    "[REDACTED]"
                    if any(part in str(key).lower() for part in SENSITIVE_KEY_PARTS)
                    or (is_authorization_header and key == "headerValue")
                    else redact_json(value)
                )
                for key, value in item.items()
            }
        if isinstance(item, list):
            return [redact_json(value) for value in item]
        return item

    text = json.dumps(redact_json(parsed), ensure_ascii=False)
    return text[:ERROR_BODY_LOG_LIMIT] + ("… [truncated]" if len(text) > ERROR_BODY_LOG_LIMIT else "")


def _request_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    operation: str,
    expect_json: bool = True,
) -> tuple[int, Any]:
    request = Request(url, data=body, headers=headers or {}, method=method)
    if LOGGER.isEnabledFor(logging.DEBUG):
        LOGGER.debug(
            "%s request: method=%s url=%s headers=%s body_bytes=%s payload=%s",
            operation,
            method,
            _safe_url(url),
            _safe_request_headers(headers or {}),
            len(body) if body else 0,
            _safe_request_body(body),
        )
    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read()
            LOGGER.debug(
                "%s response: status=%s headers=%s body_bytes=%s",
                operation,
                response.status,
                _safe_response_headers(response.headers),
                len(raw),
            )
            if not raw or not expect_json:
                return response.status, None
            try:
                return response.status, json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RefreshError(f"{operation} returned invalid JSON") from exc
    except HTTPError as exc:
        response_body = exc.read(ERROR_BODY_LOG_LIMIT + 1)
        if LOGGER.isEnabledFor(logging.DEBUG):
            body_preview = _safe_error_body(response_body, headers or {}, body)
            if len(response_body) > ERROR_BODY_LOG_LIMIT:
                body_preview += "… [truncated]"
            LOGGER.debug(
                "%s error response: status=%s reason=%s headers=%s body=%s",
                operation,
                exc.code,
                exc.reason,
                _safe_response_headers(exc.headers) if exc.headers else {},
                body_preview,
            )
        raise RefreshError(f"{operation} failed with HTTP {exc.code}") from None
    except (URLError, TimeoutError, OSError) as exc:
        raise RefreshError(f"{operation} failed due to a connection error") from None


def _env_secret(config: dict[str, Any], key: str, label: str) -> str:
    env_name = config.get(key)
    if not isinstance(env_name, str) or not env_name:
        raise RefreshError(f"Configuration must specify {key} with an environment variable name")
    value = os.environ.get(env_name)
    if not value:
        raise RefreshError(f"Required environment variable {env_name} is not set")
    return value


def fetch_oauth_token(config: dict[str, Any]) -> tuple[str, str]:
    oauth = config["oauth"]
    token_url = oauth["token_url"]
    client_id = oauth["client_id"]
    client_secret = _env_secret(oauth, "client_secret_env", "OAuth client secret")
    auth_method = oauth.get("client_auth_method", "client_secret_post")
    if auth_method not in {"client_secret_post", "client_secret_basic"}:
        raise RefreshError("oauth.client_auth_method must be client_secret_post or client_secret_basic")

    params: dict[str, Any] = {"grant_type": oauth.get("grant_type", "client_credentials")}
    if oauth.get("scope"):
        params["scope"] = oauth["scope"]
    params.update(oauth.get("extra_token_params", {}))

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if oauth.get("accept"):
        headers["Accept"] = oauth["accept"]
    if auth_method == "client_secret_post":
        params["client_id"] = client_id
        params["client_secret"] = client_secret
    else:
        credentials = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {credentials}"

    _, payload = _request_json(
        token_url,
        method="POST",
        headers=headers,
        body=urlencode(params, doseq=True).encode("utf-8"),
        operation="OAuth token request",
    )
    if not isinstance(payload, dict):
        raise RefreshError("OAuth token response must be a JSON object")
    access_token = payload.get("access_token")
    token_type = payload.get("token_type", "Bearer")
    if not isinstance(access_token, str) or not access_token:
        raise RefreshError("OAuth token response did not contain access_token")
    if not isinstance(token_type, str) or not token_type:
        raise RefreshError("OAuth token response contained an invalid token_type")
    return access_token, token_type


def update_webhook(config: dict[str, Any], access_token: str, token_type: str) -> None:
    splunk = config["splunk"]
    api_token = _env_secret(splunk, "api_token_env", "Splunk API token")
    api_base_url = splunk.get("api_base_url")
    if not api_base_url:
        realm = splunk["realm"]
        api_base_url = f"https://api.{realm}.observability.splunkcloud.com/v2"
    integration_id = splunk["integration_id"]
    integration_url = f"{api_base_url.rstrip('/')}/integration/{integration_id}"
    api_headers = {"X-SF-TOKEN": api_token, "Accept": "application/json"}

    _, integration = _request_json(
        integration_url,
        headers=api_headers,
        operation="Splunk integration read",
    )
    if not isinstance(integration, dict):
        raise RefreshError("Splunk integration response must be a JSON object")
    if integration.get("type", "").lower() != "webhook":
        raise RefreshError("The configured integration ID is not a Webhook integration")

    headers = integration.get("headers", {})
    auth_value = f"{token_type} {access_token}"
    if isinstance(headers, dict):
        # The Integrations API represents custom headers as a JSON object.
        updated_headers = {
            key: value
            for key, value in headers.items()
            if str(key).lower() != "authorization"
        }
        updated_headers["Authorization"] = auth_value
    elif isinstance(headers, list):
        # Accept the headerKey/headerValue list representation used by some SDKs.
        updated_headers = [
            item
            for item in headers
            if not isinstance(item, dict)
            or str(item.get("headerKey", "")).lower() != "authorization"
        ]
        updated_headers.append({"headerKey": "Authorization", "headerValue": auth_value})
    else:
        raise RefreshError("Webhook integration headers were not returned in a supported format")
    integration["headers"] = updated_headers

    # Preserve the fetched integration configuration while omitting server-owned metadata.
    for field in READ_ONLY_INTEGRATION_FIELDS:
        integration.pop(field, None)
    request_body = json.dumps(integration).encode("utf-8")
    put_headers = {
        **api_headers,
        "Content-Type": "application/json",
    }
    _request_json(
        integration_url,
        method="PUT",
        headers=put_headers,
        body=request_body,
        operation="Splunk integration update",
        expect_json=False,
    )


def publish_status(config: dict[str, Any], succeeded: bool) -> None:
    monitoring = config.get("monitoring", {})
    if not monitoring.get("enabled", True):
        return

    ingest_token = _env_secret(monitoring, "ingest_token_env", "Splunk ingest token")
    realm = monitoring.get("realm") or config["splunk"].get("realm")
    if not realm:
        raise RefreshError("Set monitoring.realm or splunk.realm")
    ingest_base_url = monitoring.get("ingest_base_url") or (
        f"https://ingest.{realm}.observability.splunkcloud.com"
    )
    metric_name = monitoring.get("metric_name", "splunk.webhook.oauth_token_refresh.success")
    dimensions = dict(monitoring.get("dimensions", {}))
    dimensions.setdefault("integration_id", config["splunk"]["integration_id"])
    data_point = {
        "gauge": [
            {
                "metric": metric_name,
                "dimensions": dimensions,
                "value": 1 if succeeded else 0,
                "timestamp": int(time.time() * 1000),
            }
        ]
    }
    _request_json(
        f"{ingest_base_url.rstrip('/')}/v2/datapoint",
        method="POST",
        headers={"X-SF-TOKEN": ingest_token, "Content-Type": "application/json"},
        body=json.dumps(data_point).encode("utf-8"),
        operation="Splunk refresh-status metric publish",
        expect_json=False,
    )


def load_config(path: Path) -> dict[str, Any]:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RefreshError(f"Could not read config file: {path}") from None
    except json.JSONDecodeError as exc:
        raise RefreshError(f"Config file is not valid JSON (line {exc.lineno})") from None
    if not isinstance(config, dict):
        raise RefreshError("Config file must contain a JSON object")
    for required in ("oauth", "splunk"):
        if not isinstance(config.get(required), dict):
            raise RefreshError(f"Config must contain a {required} object")
    return config


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        default="config.json",
        help="Path to JSON configuration file (default: ./config.json)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Log request/response diagnostics with sensitive values redacted",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    try:
        config = load_config(Path(args.config))
    except RefreshError as exc:
        LOGGER.error("Configuration error: %s", exc)
        return 1

    succeeded = False
    try:
        access_token, token_type = fetch_oauth_token(config)
        update_webhook(config, access_token, token_type)
        succeeded = True
        LOGGER.info("OAuth token refreshed and webhook integration updated")
    except (RefreshError, KeyError, TypeError, ValueError) as exc:
        LOGGER.error("Token refresh failed: %s", exc)

    try:
        publish_status(config, succeeded)
        LOGGER.info("Refresh status metric published with value %d", int(succeeded))
    except (RefreshError, KeyError, TypeError, ValueError) as exc:
        LOGGER.error("Could not publish refresh status metric: %s", exc)
        succeeded = False

    return 0 if succeeded else 1


if __name__ == "__main__":
    sys.exit(main())
