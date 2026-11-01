"""DeepSeek chat provider client.

The API key is read from server-side settings and never leaves this module: it is not
returned by any endpoint, not written to a log line, and not embedded in an error message.
"""
from __future__ import annotations

import json
import logging
import random
import time
from collections.abc import Iterator
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger("aegis.deepseek")

# Failure kinds the UI renders differently. Keep in sync with the frontend copy map.
NOT_CONFIGURED = "not_configured"
AUTH = "invalid_key"
QUOTA = "insufficient_credit"
RATE_LIMITED = "rate_limited"
MODEL_UNAVAILABLE = "model_unavailable"
TIMEOUT = "timeout"
UNREACHABLE = "unreachable"
SERVER = "provider_error"
REJECTED = "request_rejected"
TRUNCATED = "stream_truncated"
UNKNOWN = "provider_error"

_MESSAGES = {
    NOT_CONFIGURED: "No DeepSeek API key is configured on the server.",
    AUTH: "DeepSeek rejected the API key. Check DEEPSEEK_API_KEY.",
    QUOTA: "DeepSeek reported insufficient account credit for this request.",
    RATE_LIMITED: "DeepSeek is rate-limiting this account. Retry shortly.",
    MODEL_UNAVAILABLE: "The configured DeepSeek model is not available to this key.",
    TIMEOUT: "DeepSeek did not respond within the configured timeout.",
    UNREACHABLE: "Could not reach the DeepSeek API from the server.",
    SERVER: "DeepSeek returned a server-side error.",
    REJECTED: "DeepSeek rejected the request.",
    TRUNCATED: "The response stream ended before the reply was complete.",
    UNKNOWN: "DeepSeek returned an unexpected error.",
}


class DeepSeekError(RuntimeError):
    """A provider failure with a stable, display-safe `kind` and no credential content."""

    def __init__(self, kind: str, detail: str = "", *, status_code: int | None = None,
                 retryable: bool = False) -> None:
        self.kind = kind
        self.detail = detail[:400]
        self.status_code = status_code
        self.retryable = retryable
        super().__init__(f"{kind}: {detail[:200]}" if detail else kind)

    @property
    def message(self) -> str:
        base = _MESSAGES.get(self.kind, _MESSAGES[UNKNOWN])
        return f"{base} {self.detail}".strip() if self.detail else base


def _classify(status_code: int, body: str) -> DeepSeekError:
    lowered = body.lower()
    if status_code in (401, 403):
        return DeepSeekError(AUTH, body, status_code=status_code)
    if status_code == 402 or "insufficient balance" in lowered or "insufficient credit" in lowered:
        return DeepSeekError(QUOTA, body, status_code=status_code)
    if status_code == 429:
        retryable = "insufficient" not in lowered
        return DeepSeekError(RATE_LIMITED, body, status_code=status_code, retryable=retryable)
    if status_code == 404 or "model_not_found" in lowered or "modelunavailable" in lowered:
        return DeepSeekError(MODEL_UNAVAILABLE, body, status_code=status_code)
    if status_code >= 500:
        return DeepSeekError(SERVER, body, status_code=status_code, retryable=True)
    return DeepSeekError(REJECTED, body, status_code=status_code)


def _extract_error_detail(payload: Any) -> str:
    """Pull the provider's own message out, keeping it short and credential-free."""
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            return str(error.get("message") or error.get("code") or "")[:300]
        if error is not None:
            return str(error)[:300]
        return str(payload.get("message") or payload.get("detail") or "")[:300]
    return (payload or "")[:300]


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {settings.deepseek_api_key.strip()}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _url(path: str) -> str:
    return f"{settings.deepseek_base_url.rstrip('/')}/{path.lstrip('/')}"


def _timeout() -> httpx.Timeout:
    total = max(10, int(settings.deepseek_timeout_seconds))
    return httpx.Timeout(timeout=total, connect=min(15, total))


def require_key() -> None:
    if not settings.deepseek_configured:
        raise DeepSeekError(NOT_CONFIGURED)


def message_for(kind: str) -> str:
    """Display copy for a failure kind, for status payloads built without raising."""
    return _MESSAGES.get(kind or "", _MESSAGES[UNKNOWN])


def _payload(messages: list[dict], model: str, *, stream: bool, **overrides: Any) -> dict:
    body: dict[str, Any] = {
        "model": model or settings.deepseek_model,
        "messages": messages,
        "stream": stream,
        "temperature": overrides.pop("temperature", settings.deepseek_temperature),
        "max_tokens": overrides.pop("max_tokens", settings.deepseek_max_output_tokens),
    }
    body.update(overrides)
    return body


def _backoff(attempt: int) -> float:
    return min(6.0, (2 ** attempt) + random.uniform(0, 0.35))


def _guard(exc: Exception) -> DeepSeekError:
    if isinstance(exc, DeepSeekError):
        return exc
    if isinstance(exc, httpx.TimeoutException):
        return DeepSeekError(TIMEOUT, retryable=True)
    if isinstance(exc, httpx.HTTPError):
        return DeepSeekError(UNREACHABLE, str(exc.__class__.__name__), retryable=True)
    return DeepSeekError(UNKNOWN, str(exc)[:200])


def chat_stream(messages: list[dict], *, model: str = "", **overrides: Any) -> Iterator[str]:
    """Yield text deltas from a streaming completion.

    Retries happen only before the first token, so a half-delivered answer is never duplicated.
    """
    require_key()
    attempts = max(0, int(settings.deepseek_retries))
    body = _payload(messages, model, stream=True, **overrides)

    for attempt in range(attempts + 1):
        started = False
        finish_reason = None
        try:
            with httpx.Client(timeout=_timeout()) as client:
                with client.stream("POST", _url("chat/completions"), headers=_headers(), json=body) as response:
                    if response.status_code >= 400:
                        raw = response.read().decode("utf-8", "replace")
                        try:
                            detail = _extract_error_detail(json.loads(raw))
                        except json.JSONDecodeError:
                            detail = raw
                        raise _classify(response.status_code, detail)
                    for line in response.iter_lines():
                        if not line or not line.startswith("data:"):
                            continue
                        chunk = line[5:].strip()
                        if chunk == "[DONE]":
                            break
                        try:
                            event = json.loads(chunk)
                        except json.JSONDecodeError:
                            continue
                        for choice in event.get("choices") or []:
                            if choice.get("finish_reason"):
                                finish_reason = choice["finish_reason"]
                            delta = (choice.get("delta") or {}).get("content")
                            if delta:
                                started = True
                                yield delta
            if started and finish_reason == "length":
                raise DeepSeekError(TRUNCATED, "the answer hit the configured output-token limit")
            return
        except (DeepSeekError, httpx.HTTPError) as exc:
            error = _guard(exc)
            if started or not error.retryable or attempt >= attempts:
                raise error
            time.sleep(_backoff(attempt))


def complete(messages: list[dict], *, model: str = "", **overrides: Any) -> str:
    """Non-streaming completion used for the connection probe and title generation."""
    require_key()
    overrides.setdefault("max_tokens", 200)
    body = _payload(messages, model, stream=False, **overrides)
    attempts = max(0, int(settings.deepseek_retries))
    for attempt in range(attempts + 1):
        try:
            with httpx.Client(timeout=_timeout()) as client:
                response = client.post(_url("chat/completions"), headers=_headers(), json=body)
            if response.status_code >= 400:
                try:
                    detail = _extract_error_detail(response.json())
                except (ValueError, json.JSONDecodeError):
                    detail = response.text
                raise _classify(response.status_code, detail)
            choices = response.json().get("choices") or []
            if not choices:
                raise DeepSeekError(UNKNOWN, "the provider returned no choices")
            return str(choices[0].get("message", {}).get("content") or "")
        except (DeepSeekError, httpx.HTTPError) as exc:
            error = _guard(exc)
            if not error.retryable or attempt >= attempts:
                raise error
            time.sleep(_backoff(attempt))
    return ""


def probe() -> dict:
    """Make a real request and report exactly what happened. Never reports success by inference."""
    started = time.perf_counter()
    if not settings.deepseek_configured:
        return _probe_result("missing_key", False, NOT_CONFIGURED, started)
    try:
        reply = complete(
            [
                {"role": "system", "content": "Reply with the single word: ready"},
                {"role": "user", "content": "Connection check."},
            ],
            max_tokens=8,
        )
    except DeepSeekError as exc:
        return _probe_result("error", False, exc.kind, started, exc.message, exc.status_code)
    except Exception as exc:  # pragma: no cover - defensive: never surface a traceback to the browser
        logger.warning("DeepSeek probe failed unexpectedly")
        return _probe_result("error", False, UNKNOWN, started, str(exc)[:200])
    return _probe_result("ok", True, "", started, reply.strip()[:40])


def _probe_result(state: str, connected: bool, kind: str, started: float,
                  detail: str = "", status_code: int | None = None) -> dict:
    return {
        "state": state,
        "connected": connected,
        "kind": kind,
        "detail": detail,
        "status_code": status_code,
        "latency_ms": int((time.perf_counter() - started) * 1000),
        "tested_at": time.time(),
        "model": settings.deepseek_model,
        "host": settings.deepseek_host,
    }
