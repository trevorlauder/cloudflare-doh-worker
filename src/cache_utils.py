# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Cloudflare Cache API helpers for DNS response caching."""

import base64
import logging
import urllib.parse

from workers import Response

from dns_utils import Question

logger = logging.getLogger(__name__)


def _to_js_body(body: bytes | bytearray | str) -> object:
    """
    Convert bytes to a JS Uint8Array for use in a Workers Response.

    Parameters:
    body (bytes | bytearray | str): Response body.

    Returns:
    object: JS Uint8Array for bytes/bytearray, original value otherwise.
    """
    if isinstance(body, (bytes, bytearray)):
        from pyodide.ffi import to_js

        return to_js(body)

    return body


def _build_cache_key(
    endpoint: str,
    body_bytes: bytes | None,
    question: Question,
    extra_query: dict[str, str] | None = None,
) -> str | None:
    """
    Build a synthetic cache URL for a DNS request.

    Wire requests use ?dns=<base64url> with the transaction ID zeroed.
    JSON GET requests use ?name=&type= plus any extra_query params.

    Parameters:
    endpoint (str): Worker endpoint path.
    body_bytes (bytes | None): ECS-truncated DNS wire bytes, or None for JSON GET.
    question (Question): Parsed DNS question.
    extra_query (dict[str, str] | None): Extra JSON GET query parameters.

    Returns:
    str | None: Cache URL, or None if one cannot be built.
    """
    cache_key_base = "https://doh-cache.internal"

    if body_bytes is not None:
        canonical: bytes = (
            b"\x00\x00" + body_bytes[2:] if len(body_bytes) >= 2 else body_bytes
        )
        encoded: str = base64.urlsafe_b64encode(canonical).rstrip(b"=").decode("ascii")
        return f"{cache_key_base}{endpoint}?dns={encoded}"

    if question.name:
        params: dict[str, str] = {"name": question.name}
        if question.type:
            params["type"] = question.type
        if extra_query:
            params.update(extra_query)

        return f"{cache_key_base}{endpoint}?" + urllib.parse.urlencode(
            sorted(params.items()),
        )

    return None


async def _try_cache_get(
    cache_key: str,
    request_id: bytes | None = None,
    ecs_truncated: str = "",
) -> Response | None:
    """
    Look up a DNS response in the Cloudflare Cache API.

    Adjusts Cache-Control max-age by the Age header. Cache errors are
    non-fatal.

    Parameters:
    cache_key (str): Cache URL from _build_cache_key.
    request_id (bytes | None): First 2 bytes of the request's wire message,
        restored into the cached body. Only set for wire requests.
    ecs_truncated (str): This request's ECS truncation description. Keys are
        built from truncated bytes, so one entry is shared across requests that
        truncated differently and this can't come from the entry.

    Returns:
    Response | None: Cached response with a HIT header, or None on miss/error.
    """
    try:
        from js import caches

        cached = await caches.default.match(cache_key)

        if cached is None:
            return None

        body: bytes = (await cached.bytes()).to_bytes()

        content_type = str(
            cached.headers.get("content-type") or "application/dns-message",
        )

        if request_id is not None and len(request_id) >= 2 and len(body) >= 2:
            body = request_id[:2] + body[2:]

        passthrough_headers = (
            "CLOUDFLARE-DOH-WORKER-CONFIG-ALLOWED",
            "CLOUDFLARE-DOH-WORKER-CONFIG-BLOCKED",
            "CLOUDFLARE-DOH-WORKER-REBIND-PROTECTED",
        )

        response_headers: dict[str, str] = {
            "content-type": content_type,
            "CLOUDFLARE-DOH-WORKER-CACHE": "HIT",
        }

        if ecs_truncated:
            response_headers["CLOUDFLARE-DOH-WORKER-ECS-TRUNCATED"] = ecs_truncated

        for header in passthrough_headers:
            value: str | None = cached.headers.get(header)
            if value:
                response_headers[header] = str(value)

        try:
            cache_control: str = str(cached.headers.get("cache-control") or "")
            age: int = int(cached.headers.get("age") or 0)

            part: str | None = next(
                (
                    p.strip()
                    for p in cache_control.split(",")
                    if p.strip().startswith("max-age=")
                ),
                None,
            )
            if part:
                response_headers["Cache-Control"] = (
                    f"max-age={max(0, int(part[8:]) - age)}"
                )
        except (ValueError, AttributeError):
            pass

        return Response(
            _to_js_body(body),
            status=200,
            headers=response_headers,
        )
    except Exception:
        logger.debug("Cache get failed for %s", cache_key, exc_info=True)
        return None


def _schedule_cache_put(
    ctx: object,
    cache_key: str,
    body: bytes | str,
    content_type: str,
    min_ttl: int,
    extra_headers: dict[str, str] | None = None,
) -> None:
    """
    Schedule a DNS response write to the Cloudflare Cache API.

    Uses ctx.waitUntil so the write doesn't block the response. Cache-Control
    max-age is set to the DNS minimum TTL. Stable per-request headers (e.g.
    CONFIG-ALLOWED, ECS-TRUNCATED) can be passed via extra_headers and will be
    stored alongside the body so they are restored on cache hit. Errors are
    non-fatal.

    Parameters:
    ctx (object): Worker execution context.
    cache_key (str): Cache URL from _build_cache_key.
    body (bytes | str): DNS response body.
    content_type (str): Content-Type of the response.
    min_ttl (int): DNS response minimum TTL in seconds.
    extra_headers (dict[str, str] | None): Additional headers to store.

    Returns:
    None
    """
    try:
        from js import Object, caches
        from js import Response as JsResponse
        from pyodide.ffi import to_js

        js_body: object = _to_js_body(body)

        stored_headers: dict[str, str] = {
            "content-type": content_type,
            "Cache-Control": f"max-age={min_ttl}",
        }
        if extra_headers:
            stored_headers.update(extra_headers)

        init: object = to_js(
            {"status": 200, "headers": stored_headers},
            dict_converter=Object.fromEntries,
        )

        ctx.waitUntil(caches.default.put(cache_key, JsResponse.new(js_body, init)))
    except Exception:
        logger.debug("Cache put failed for %s", cache_key, exc_info=True)
