# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Cloudflare Worker entrypoint for the DNS-over-HTTPS proxy."""

import base64
from collections.abc import Callable
import hmac
import json
import logging
import math
import re
import time
from typing import NamedTuple
import urllib.parse

import dns.exception
import dns.name
import dns.rdatatype
from pyodide.ffi import to_js
from workers import Response, WorkerEntrypoint

from cache_utils import (
    _build_cache_key,
    _schedule_cache_put,
    _to_js_body,
    _try_cache_get,
)
import config
from config_types import EndpointConfig, Provider
from dns_utils import (
    MAX_DNS_BODY_SIZE,
    SUPPORTED_ACCEPT_HEADERS,
    DnsParseResult,
    ProviderResult,
    Question,
    _bloom_contains,
    compile_domain_set,
    domain_matches,
    get_response_min_ttl,
    make_blocked_response,
    parse_dns_wire_request,
    send_doh_requests_fanout,
)
from loki_utils import build_loki_fetch_promise


class _JsonFormatter(logging.Formatter):
    """Emit log records as single-line JSON for Workers Observability."""

    def format(self, record: logging.LogRecord) -> str:
        """
        Format a log record as single-line JSON.

        Parameters:
        record (logging.LogRecord): The log record to format.

        Returns:
        str: JSON string with level, logger, message, and optional exception.
        """
        entry: dict[str, object] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        if record.exc_info and record.exc_info[1] is not None:
            entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(entry, separators=(",", ":"))


_handler = logging.StreamHandler()
_handler.setFormatter(_JsonFormatter())
logging.root.addHandler(_handler)
logging.root.setLevel(logging.DEBUG if config.DEBUG else logging.WARNING)

logger = logging.getLogger(__name__)

_ALLOWED_COMPILED = compile_domain_set(config.ALLOWED_DOMAINS)
_BLOCKED_COMPILED = compile_domain_set(config.BLOCKED_DOMAINS)


class BlocklistCache(NamedTuple):
    """Immutable container for a loaded KV blocklist."""

    check: Callable[[str], bool]
    manifest_urls: tuple[str, ...]
    domain_count: int
    fp_rate: float
    bloom_size_bytes: int


_kv_blocklist_cache: BlocklistCache | None = None
_kv_blocklist_loading: bool = False
_EMPTY_BLOCKLIST: BlocklistCache = BlocklistCache(
    check=lambda _: False,
    manifest_urls=(),
    domain_count=0,
    fp_rate=0.0,
    bloom_size_bytes=0,
)


_CONFIG_TYPE_RULES: list[tuple[str, type | tuple]] = [
    ("DEBUG", bool),
    ("TIMEOUT_MS", int),
    ("LOKI_TIMEOUT_MS", int),
    ("RETRY_MAX_ATTEMPTS", int),
    ("REBIND_PROTECTION", bool),
    ("CACHE_DNS", bool),
    ("BLOCKLIST_ENABLED", bool),
    ("BLOCKLIST_LOADING_POLICY", str),
    ("BLOCKED_DOMAINS", list),
    ("ALLOWED_DOMAINS", list),
    ("BYPASS_PROVIDER", dict),
    ("ECS_TRUNCATION", dict),
    ("ENDPOINTS", dict),
    ("LOKI_URL", str),
    ("CONFIG_ENDPOINT", str),
    ("HEALTH_ENDPOINT", str),
]


def _validate_types() -> None:
    """Raise TypeError if any config value has the wrong type."""
    for name, expected_type in _CONFIG_TYPE_RULES:
        value: object = getattr(config, name, None)

        if value is not None and not isinstance(value, expected_type):
            raise TypeError(
                f"config.{name} must be {expected_type.__name__}, got {type(value).__name__}",
            )


_VALID_BLOCKLIST_LOADING_POLICIES: frozenset[str] = frozenset({"block", "bypass"})


def _validate_config() -> None:
    """Validate cross-field config constraints at import time."""
    policy: str = config.BLOCKLIST_LOADING_POLICY

    if policy not in _VALID_BLOCKLIST_LOADING_POLICIES:
        raise ValueError(
            f"config.BLOCKLIST_LOADING_POLICY must be one of "
            f"{sorted(_VALID_BLOCKLIST_LOADING_POLICIES)}, got {policy!r}",
        )

    if not config.ALLOWED_DOMAINS:
        return

    value: object = config.BYPASS_PROVIDER.get("url")

    if not isinstance(value, str) or not value:
        raise ValueError(
            "BYPASS_PROVIDER 'url' must be a non-empty string when ALLOWED_DOMAINS is set",
        )


_validate_types()
_validate_config()


async def _load_blocklist_from_kv(env: object) -> BlocklistCache | None:
    """
    Load the community block list from KV on cold start.

    Parameters:
    env (object): Worker environment with KV namespace bindings.

    Returns:
    BlocklistCache | None: Loaded blocklist data, or None if another request
        is already loading the blocklist.
    """
    global _kv_blocklist_cache, _kv_blocklist_loading

    if _kv_blocklist_cache is not None:
        return _kv_blocklist_cache

    if _kv_blocklist_loading:
        return None

    _kv_blocklist_loading = True

    try:
        binding: str = "BLOCKLIST"
        kv: object | None = getattr(env, binding, None)

        if kv is None:
            logger.warning(
                "KV binding %r not found on env, community block list disabled",
                binding,
            )

            _kv_blocklist_cache = _EMPTY_BLOCKLIST
            return _kv_blocklist_cache

        manifest_key: str = "blocklist:manifest"

        try:
            manifest_json: str | None = await kv.get(manifest_key)
        except Exception:
            logger.warning(
                "Failed to read KV block list manifest %r, community block list disabled",
                manifest_key,
                exc_info=True,
            )

            _kv_blocklist_cache = _EMPTY_BLOCKLIST
            return _kv_blocklist_cache

        if not manifest_json:
            logger.warning(
                "KV block list manifest %r is empty or not found, community block list disabled",
                manifest_key,
            )

            _kv_blocklist_cache = _EMPTY_BLOCKLIST
            return _kv_blocklist_cache

        try:
            manifest: list = json.loads(manifest_json)
        except Exception:
            logger.warning("Failed to parse blocklist manifest JSON", exc_info=True)
            _kv_blocklist_cache = _EMPTY_BLOCKLIST
            return _kv_blocklist_cache

        if not manifest:
            logger.warning("Blocklist manifest is empty, community block list disabled")
            _kv_blocklist_cache = _EMPTY_BLOCKLIST
            return _kv_blocklist_cache

        entry: dict = manifest[0]

        entry_source_urls: list = entry.get("source_urls", [])
        if entry_source_urls:
            manifest_urls: list[str] = list(entry_source_urls)
        else:
            legacy_url: str = entry.get("url", "")
            manifest_urls: list[str] = [legacy_url] if legacy_url else []

        bloom_m: int = int(entry.get("bloom_m", 0))
        bloom_k: int = int(entry.get("bloom_k", 0))
        exact_count: int = int(entry.get("exact_count", 0))
        suffixes_list: list = entry.get("suffixes", [])

        suffixes_tuple: tuple[str, ...] = tuple(sorted(suffixes_list))
        total_domain_count: int = exact_count + len(suffixes_list)

        if bloom_m and bloom_k:
            bloom_key: str = "blocklist:bloom"
            try:
                bloom_buf: object | None = await kv.get(
                    bloom_key,
                    to_js({"type": "arrayBuffer"}),
                )
            except Exception:
                logger.warning(
                    "Failed to read KV bloom filter %r, community block list disabled",
                    bloom_key,
                    exc_info=True,
                )
                _kv_blocklist_cache = _EMPTY_BLOCKLIST
                return _kv_blocklist_cache

            if bloom_buf is None:
                logger.warning(
                    "KV bloom filter %r is empty or not found, community block list disabled",
                    bloom_key,
                )
                _kv_blocklist_cache = _EMPTY_BLOCKLIST
                return _kv_blocklist_cache

            bit_array: bytearray = bytearray(bloom_buf.to_bytes())
            fp_rate: float = (
                (1.0 - math.exp(-bloom_k * exact_count / bloom_m)) ** bloom_k
                if exact_count > 0
                else 0.0
            )
        else:
            bit_array: bytearray = bytearray()
            fp_rate: float = 0.0

        def _check(name: str) -> bool:
            normalized: str = name.rstrip(".").lower()
            if any(normalized.endswith(suffix) for suffix in suffixes_tuple):
                return True
            if not bit_array:
                return False
            return _bloom_contains(bit_array, bloom_m, bloom_k, normalized)

        _kv_blocklist_cache = BlocklistCache(
            check=_check,
            manifest_urls=tuple(manifest_urls),
            domain_count=total_domain_count,
            fp_rate=fp_rate,
            bloom_size_bytes=len(bit_array),
        )

        logger.info(
            "Loaded KV block list: %d domains, %d wildcard suffixes, "
            "theoretical FP rate %.2e (2 KV reads)",
            total_domain_count,
            len(suffixes_tuple),
            fp_rate,
        )

        return _kv_blocklist_cache
    except Exception:
        logger.warning("Unexpected error loading KV blocklist", exc_info=True)
        _kv_blocklist_cache = _EMPTY_BLOCKLIST
        return _kv_blocklist_cache
    finally:
        _kv_blocklist_loading = False


def _with_provider_id(provider: Provider) -> dict:
    """
    Return a copy of provider with provider_id set to its URL.

    Parameters:
    provider (Provider): Provider config dict.

    Returns:
    dict: Provider dict with provider_id added.
    """
    return {**provider, "provider_id": provider["url"]}


_SECRET_RE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")


def _resolve_secrets(data: object, env: object) -> object:
    """
    Recursively replace ${SECRET_NAME} placeholders with values from env.

    Parameters:
    data (object): Data structure to resolve.
    env (object): Worker environment with secrets.

    Returns:
    object: Data with all placeholders replaced.
    """
    missing: list[str] = []

    def _resolve(value: object) -> object:
        """Recursively resolve placeholders in a value."""
        if isinstance(value, str):
            if "${" not in value:
                return value

            def _replacer(match: re.Match[str]) -> str:
                """
                Replace a ${SECRET_NAME} match with the resolved secret value.

                Parameters:
                match (re.Match[str]): Regex match object.

                Returns:
                str: Secret value, or original placeholder if not found.
                """
                try:
                    secret: object | None = getattr(env, match.group(1), None)
                except Exception:
                    secret = None
                if not secret:
                    missing.append(match.group(1))
                    return match.group(0)
                return str(secret)

            return _SECRET_RE.sub(_replacer, value)
        if isinstance(value, dict):
            return {k: _resolve(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_resolve(item) for item in value]
        return value

    resolved: object = _resolve(data)

    if missing:
        raise ValueError(f"Missing secret(s): {', '.join(sorted(set(missing)))}")

    return resolved


def _resolve_providers(providers: list[Provider], env: object) -> list[dict]:
    """
    Resolve secret placeholders in providers and update provider_id.

    Parameters:
    providers (list[Provider]): List of provider dicts.
    env (object): Worker environment with secrets.

    Returns:
    list[dict]: Resolved provider dicts.
    """
    resolved: list = _resolve_secrets(data=providers, env=env)

    for provider in resolved:
        provider["provider_id"] = provider["url"]

    return resolved


def _build_provider_lists() -> dict[str, list[dict]]:
    """
    Build per-endpoint provider lists from config.

    Returns:
    dict[str, list[dict]]: Endpoint paths mapped to provider lists.
    """
    result: dict[str, list[dict]] = {}
    cfg: EndpointConfig
    for path, cfg in config.ENDPOINTS.items():
        main: dict = _with_provider_id({**cfg["main_provider"], "main": True})

        additional: list[dict] = [
            _with_provider_id({**p, "main": False})
            for p in cfg.get("additional_providers", [])
        ]

        result[path] = [main, *additional]

    return result


_PROVIDER_LISTS = _build_provider_lists()

_BYPASS_PROVIDER_LIST = (
    [_with_provider_id({**config.BYPASS_PROVIDER, "main": True})]
    if config.ALLOWED_DOMAINS
    else []
)

_resolved_config_cache: "_ResolvedConfig | None" = None


class _ResolvedConfig(NamedTuple):
    """Runtime configuration with all ${SECRET} placeholders resolved."""

    health_endpoint: str | None
    config_endpoint: str | None
    loki_url: str
    provider_lists: dict[str, list[dict]]
    bypass_provider_list: list[dict]
    full_config: dict


def _resolve_config(env: object) -> _ResolvedConfig:
    """
    Resolve ${SECRET} placeholders in the config and cache the result.

    Parameters:
    env (object): Worker environment with secrets.

    Returns:
    _ResolvedConfig: Resolved runtime configuration.
    """
    global _resolved_config_cache

    if _resolved_config_cache is not None:
        return _resolved_config_cache

    health: str | None = (
        _resolve_secrets(data=config.HEALTH_ENDPOINT, env=env)
        if config.HEALTH_ENDPOINT
        else None
    )
    config_ep: str | None = (
        _resolve_secrets(data=config.CONFIG_ENDPOINT, env=env)
        if config.CONFIG_ENDPOINT
        else None
    )
    try:
        loki_url: str = (
            _resolve_secrets(data=config.LOKI_URL, env=env) if config.LOKI_URL else ""
        )
    except ValueError as e:
        logger.warning(
            "Loki logging disabled: failed to resolve LOKI_URL secret(s): %s",
            e,
        )

        loki_url: str = ""

    provider_lists: dict[str, list[dict]] = {
        _resolve_secrets(data=path, env=env): _resolve_providers(
            providers=providers,
            env=env,
        )
        for path, providers in _PROVIDER_LISTS.items()
    }

    full_config: dict = _resolve_secrets(
        data={name: getattr(config, name) for name, _ in _CONFIG_TYPE_RULES},
        env=env,
    )

    resolved: _ResolvedConfig = _ResolvedConfig(
        health_endpoint=health,
        config_endpoint=config_ep,
        loki_url=loki_url,
        provider_lists=provider_lists,
        bypass_provider_list=_resolve_providers(
            providers=_BYPASS_PROVIDER_LIST,
            env=env,
        ),
        full_config=full_config,
    )

    if loki_url or not config.LOKI_URL:
        _resolved_config_cache = resolved

    return resolved


class Default(WorkerEntrypoint):
    """Cloudflare Worker entrypoint for DNS-over-HTTPS requests."""

    async def fetch(self, request: object) -> Response:
        """
        Top-level request handler that catches all unhandled exceptions.

        Parameters:
        request (object): Incoming HTTP request.

        Returns:
        Response: HTTP response.
        """
        try:
            return await self._handle(request)
        except Exception:
            logger.exception("Unhandled exception in fetch")
            return Response("Internal server error", status=500)

    async def _handle(self, request: object) -> Response:
        """
        Route the request to the health, config, or DoH handler.

        Parameters:
        request (object): Incoming HTTP request.

        Returns:
        Response: HTTP response.
        """
        parsed_url: urllib.parse.ParseResult = urllib.parse.urlparse(str(request.url))
        pathname: str = parsed_url.path

        try:
            cfg: _ResolvedConfig = _resolve_config(self.env)
        except ValueError as e:
            logger.exception("Configuration error: %s", e)
            return Response("Internal server error", status=500)

        if cfg.health_endpoint and pathname == cfg.health_endpoint:
            return _handle_health()

        if cfg.config_endpoint and pathname == cfg.config_endpoint:
            return _handle_config(request=request, env=self.env, cfg=cfg)

        doh_providers: list[dict] | None = cfg.provider_lists.get(pathname)

        if doh_providers is None:
            return Response("", status=404)

        return await _handle_request(
            request=request,
            endpoint=pathname,
            doh_providers=doh_providers,
            cfg=cfg,
            env=self.env,
            ctx=self.ctx,
            parsed_url=parsed_url,
        )


def _handle_health() -> Response:
    """
    Return a 200 JSON health response.

    Returns:
    Response: {"status": "ok"} with no-cache headers.
    """
    body: str = json.dumps({"status": "ok"})
    return Response(
        body,
        status=200,
        headers={
            "content-type": "application/json",
            "Cache-Control": "no-store",
        },
    )


def _handle_config(request: object, env: object, cfg: _ResolvedConfig) -> Response:
    """
    Return the runtime config as JSON, gated by ADMIN_TOKEN bearer auth.

    Parameters:
    request (object): Incoming HTTP request.
    env (object): Worker environment with secrets.
    cfg (_ResolvedConfig): Resolved runtime configuration.

    Returns:
    Response: JSON config on success, 401/404 on auth failure.
    """
    token: object | None = getattr(env, "ADMIN_TOKEN", None)

    if not token:
        return Response("", status=404)

    auth_header: str = str(request.headers.get("authorization") or "")

    if not auth_header.startswith("Bearer "):
        return Response("Unauthorized", status=401)

    provided: str = auth_header[7:].strip()

    if not provided or not hmac.compare_digest(provided, str(token)):
        return Response("Unauthorized", status=401)

    kv_count: int | None = (
        _kv_blocklist_cache.domain_count if _kv_blocklist_cache is not None else None
    )
    kv_urls: list[str] | None = (
        list(_kv_blocklist_cache.manifest_urls)
        if _kv_blocklist_cache is not None
        else None
    )
    kv_fp_rate: float | None = (
        _kv_blocklist_cache.fp_rate if _kv_blocklist_cache is not None else None
    )
    kv_bloom_bytes: int | None = (
        _kv_blocklist_cache.bloom_size_bytes
        if _kv_blocklist_cache is not None
        else None
    )

    payload: dict[str, object] = {
        "config": cfg.full_config,
        "stats": {
            "endpoints": len(cfg.provider_lists),
            "allowed_domains": len(config.ALLOWED_DOMAINS),
            "blocked_domains": len(config.BLOCKED_DOMAINS),
            "kv_blocklist": kv_count,
            "kv_blocklist_urls": kv_urls,
            "kv_blocklist_fp_rate": kv_fp_rate,
            "kv_bloom_size_bytes": kv_bloom_bytes,
        },
    }

    return Response(
        json.dumps(payload, indent=2, default=_json_default),
        status=200,
        headers={
            "content-type": "application/json",
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
    )


def _json_default(value: object) -> list:
    """
    JSON serializer fallback for sets.

    Parameters:
    value (object): Value to serialize.

    Returns:
    list: Sorted list for set values.
    """
    if isinstance(value, set):
        return sorted(value)

    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


_HEADER_PREFIX = "CLOUDFLARE-DOH-WORKER"
_HEADER_RESPONSE_FROM = f"{_HEADER_PREFIX}-RESPONSE-FROM"
_HEADER_RESPONSE_CODES = f"{_HEADER_PREFIX}-RESPONSE-CODES"
_HEADER_POSSIBLY_BLOCKED = f"{_HEADER_PREFIX}-POSSIBLY-BLOCKED-PROVIDERS"
_HEADER_BLOCKED = f"{_HEADER_PREFIX}-BLOCKED-PROVIDERS"
_HEADER_TIMED_OUT = f"{_HEADER_PREFIX}-TIMED-OUT-PROVIDERS"
_HEADER_CONN_ERROR = f"{_HEADER_PREFIX}-CONNECTION-ERROR-PROVIDERS"
_HEADER_ALLOWED = f"{_HEADER_PREFIX}-CONFIG-ALLOWED"
_HEADER_CONFIG_BLOCKED = f"{_HEADER_PREFIX}-CONFIG-BLOCKED"
_HEADER_REBIND_PROTECTED = f"{_HEADER_PREFIX}-REBIND-PROTECTED"
_HEADER_ECS_TRUNCATED = f"{_HEADER_PREFIX}-ECS-TRUNCATED"
_HEADER_PROVIDERS_QUERIED = f"{_HEADER_PREFIX}-PROVIDERS-QUERIED"
_HEADER_PROVIDERS_FAILED = f"{_HEADER_PREFIX}-PROVIDERS-FAILED"
_HEADER_PROVIDERS_TIMED_OUT = f"{_HEADER_PREFIX}-PROVIDERS-TIMED-OUT"
_HEADER_PROVIDERS_CONN_ERROR = f"{_HEADER_PREFIX}-PROVIDERS-CONNECTION-ERROR"
_HEADER_PROVIDERS_FAILED_STATUS = f"{_HEADER_PREFIX}-PROVIDERS-FAILED-STATUS-CODE"
_HEADER_PROVIDERS_RETRIED = f"{_HEADER_PREFIX}-PROVIDERS-RETRIED"
_HEADER_RESPONSE_FROM_MAIN = f"{_HEADER_PREFIX}-RESPONSE-FROM-MAIN"


def _build_response_headers(
    content_type: str,
    response_from: str,
    *,
    response_codes: list[str] | None = None,
    possibly_blocked: list[str] | None = None,
    blocked: list[str] | None = None,
    timed_out: list[str] | None = None,
    connection_error: list[str] | None = None,
    config_allowed: bool = False,
    config_blocked: bool = False,
    rebind: bool = False,
    ecs_truncated: str = "",
    providers_queried: int = 0,
    providers_failed: int = 0,
    providers_timed_out: int = 0,
    providers_conn_error: int = 0,
    providers_failed_status: int = 0,
    providers_retried: int = 0,
    response_from_main: bool | None = None,
) -> dict:
    """
    Build response headers. Adds DEBUG diagnostics when DEBUG is enabled.

    Parameters:
    content_type (str): Content-Type header value.
    response_from (str): Winning provider ID.
    response_codes (list[str] | None): Per-provider status codes.
    possibly_blocked (list[str] | None): Providers that returned NXDOMAIN.
    blocked (list[str] | None): Providers that returned a blocked response.
    timed_out (list[str] | None): Providers that timed out.
    connection_error (list[str] | None): Providers with connection errors.
    config_allowed (bool): Domain matched the allowlist.
    config_blocked (bool): Domain matched the blocklist.
    rebind (bool): Rebind protection was triggered.
    ecs_truncated (str): ECS truncation description.
    providers_queried (int): Number of providers contacted.
    providers_failed (int): Number of providers that failed.
    providers_timed_out (int): Number of providers that timed out.
    providers_conn_error (int): Number of providers with connection errors.
    providers_failed_status (int): Number of providers that failed with 5xx.
    providers_retried (int): Number of providers that were retried.
    response_from_main (bool | None): Whether the winner was the main provider.

    Returns:
    dict: Response headers.
    """
    headers = {"content-type": content_type}

    if rebind:
        headers[_HEADER_REBIND_PROTECTED] = "1"

    if ecs_truncated:
        headers[_HEADER_ECS_TRUNCATED] = ecs_truncated

    if providers_queried:
        headers[_HEADER_PROVIDERS_QUERIED] = str(providers_queried)
    if providers_failed:
        headers[_HEADER_PROVIDERS_FAILED] = str(providers_failed)
    if providers_timed_out:
        headers[_HEADER_PROVIDERS_TIMED_OUT] = str(providers_timed_out)
    if providers_conn_error:
        headers[_HEADER_PROVIDERS_CONN_ERROR] = str(providers_conn_error)
    if providers_failed_status:
        headers[_HEADER_PROVIDERS_FAILED_STATUS] = str(providers_failed_status)
    if providers_retried:
        headers[_HEADER_PROVIDERS_RETRIED] = str(providers_retried)
    if response_from_main is not None:
        headers[_HEADER_RESPONSE_FROM_MAIN] = "1" if response_from_main else "0"

    if config_blocked:
        headers[_HEADER_CONFIG_BLOCKED] = "1"

    if config_allowed:
        headers[_HEADER_ALLOWED] = "1"

    if config.DEBUG:
        headers.update(
            {
                _HEADER_RESPONSE_FROM: response_from,
                _HEADER_RESPONSE_CODES: ", ".join(response_codes or []),
                _HEADER_POSSIBLY_BLOCKED: ", ".join(possibly_blocked or []),
                _HEADER_BLOCKED: ", ".join(blocked or []),
                _HEADER_TIMED_OUT: ", ".join(timed_out or []),
                _HEADER_CONN_ERROR: ", ".join(connection_error or []),
                _HEADER_ALLOWED: "1" if config_allowed else "",
                _HEADER_CONFIG_BLOCKED: "1" if config_blocked else "",
            },
        )

    return headers


def _negotiate_accept(raw: str) -> str:
    """
    Return the first supported media type from a raw Accept header.

    Parameters:
    raw (str): Raw Accept header value.

    Returns:
    str: Supported media type or empty string.
    """
    for part in raw.split(","):
        media_type: str = part.split(";", 1)[0].strip().lower()
        if media_type in SUPPORTED_ACCEPT_HEADERS:
            return media_type

    return ""


class _RejectError(Exception):
    """Raised to short-circuit request parsing with an error response."""

    def __init__(self, message: str, status: int = 406) -> None:
        """
        Parameters:
        message (str): Error message.
        status (int): HTTP status code.
        """
        self.response = Response(message, status=status)


async def _parse_dns_request(
    request: object,
    query_string: str,
    method: str,
    accept: str,
) -> DnsParseResult | Response:
    """
    Parse the DNS request. Returns a Response directly on error.

    Parameters:
    request (object): Incoming HTTP request.
    query_string (str): Query string.
    method (str): HTTP method.
    accept (str): Negotiated Accept header value.

    Returns:
    DnsParseResult | Response: Parsed result or error response.
    """
    try:
        if method == "GET":
            return _parse_get(query_string=query_string, accept=accept)

        if method == "POST":
            return await _parse_post(request=request, accept=accept)

        raise _RejectError(f"Method not allowed: {method}", status=405)
    except _RejectError as r:
        return r.response


def _parse_get(query_string: str, accept: str) -> DnsParseResult:
    """
    Parse a DNS question from GET query parameters.

    Parameters:
    query_string (str): Query string.
    accept (str): Negotiated Accept header value.

    Returns:
    DnsParseResult: Parsed DNS result.
    """
    if not accept:
        supported: str = ", ".join(sorted(SUPPORTED_ACCEPT_HEADERS))
        raise _RejectError(f"Unsupported Accept header\n\nUse one of: {supported}")

    params: dict[str, list[str]] = urllib.parse.parse_qs(
        query_string,
        keep_blank_values=True,
    )
    dns_param: str | None = params.get("dns", [None])[0]
    name_param: str | None = params.get("name", [None])[0]

    if dns_param:
        if accept != "application/dns-message":
            raise _RejectError("GET ?dns= requires Accept: application/dns-message")

        padded: str = dns_param + "=" * (-len(dns_param) % 4)

        try:
            data: bytes = base64.urlsafe_b64decode(padded)
            return parse_dns_wire_request(data)
        except Exception:
            raise _RejectError(
                "Failed to decode dns query parameter",
                status=400,
            ) from None

    if name_param:
        if accept != "application/dns-json":
            raise _RejectError("GET ?name= requires Accept: application/dns-json")

        type_param: str | None = params.get("type", [None])[0]
        try:
            dns.name.from_text(name_param)

            if type_param is not None:
                dns.rdatatype.from_text(type_param)
        except (
            dns.exception.DNSException,
            dns.name.LabelTooLong,
            dns.name.EmptyLabel,
            ValueError,
        ):
            raise _RejectError("Invalid DNS name or type", status=400) from None

        question: Question = Question(
            name=name_param,
            type=type_param if type_param else "",
        )

        return DnsParseResult(question, None, "", None)

    raise _RejectError(
        "GET requests must include one of name or dns as query parameters",
        status=400,
    )


async def _parse_post(request: object, accept: str) -> DnsParseResult:
    """
    Parse a DNS wire message from the POST body.

    Parameters:
    request (object): Incoming HTTP request.
    accept (str): Negotiated Accept header value.

    Returns:
    DnsParseResult: Parsed DNS result.
    """
    if accept != "application/dns-message":
        raise _RejectError("POST requires Accept: application/dns-message")

    try:
        raw_bytes: bytes = await request.bytes()
    except Exception as e:
        logger.debug("Failed to read request body: %s", e)
        raise _RejectError("Failed to read request body", status=400) from None

    if len(raw_bytes) > MAX_DNS_BODY_SIZE:
        logger.warning("POST body too large: %d bytes", len(raw_bytes))
        raise _RejectError("Request body too large", status=413)

    try:
        return parse_dns_wire_request(raw_bytes)
    except Exception as e:
        logger.debug("Failed to decode DNS packet: %s", e)
        raise _RejectError("Failed to decode DNS packet", status=400) from None


def _select_winner(results: list[ProviderResult]) -> ProviderResult | None:
    """
    Pick the best result: blocked > possibly_blocked > main > any.

    Parameters:
    results (list[ProviderResult]): All provider results.

    Returns:
    ProviderResult | None: Winning result, or None if all failed.
    """
    first_blocked: ProviderResult | None = None
    first_possibly_blocked: ProviderResult | None = None
    first_successful_main: ProviderResult | None = None
    first_successful: ProviderResult | None = None
    first_non_rebind_main: ProviderResult | None = None
    first_non_rebind: ProviderResult | None = None

    for result in results:
        if not result.failed:
            if first_successful is None:
                first_successful = result
            if result.main and first_successful_main is None:
                first_successful_main = result
            if not result.rebind:
                if first_non_rebind is None:
                    first_non_rebind = result
                if result.main and first_non_rebind_main is None:
                    first_non_rebind_main = result
            if result.blocked and first_blocked is None:
                first_blocked = result
            if result.possibly_blocked and first_possibly_blocked is None:
                first_possibly_blocked = result

    winner: ProviderResult | None = (
        first_blocked
        or first_possibly_blocked
        or first_successful_main
        or first_successful
    )

    if winner is None:
        return None

    if winner.rebind and config.REBIND_PROTECTION:
        replacement: ProviderResult | None = first_non_rebind_main or first_non_rebind
        if replacement:
            winner = replacement

    return winner


def _make_rebind_blocked_response(
    results: list[ProviderResult],
    question: Question,
    accept: str,
    request_wire: bytes | None,
    ecs_truncated: str,
    parsed_request: object = None,
) -> Response | None:
    """
    Return a synthetic NXDOMAIN if rebind protection fired on all results.

    Parameters:
    results (list[ProviderResult]): All provider results.
    question (Question): DNS question.
    accept (str): Negotiated Accept header value.
    request_wire (bytes | None): Original DNS wire bytes.
    ecs_truncated (str): ECS truncation description.
    parsed_request (object): Parsed DNS message, if available.

    Returns:
    Response | None: Synthetic NXDOMAIN, or None if rebind protection didn't fire.
    """
    if not (
        config.REBIND_PROTECTION
        and any(r.rebind for r in results)
        and all(r.failed or r.rebind for r in results)
    ):
        return None

    body, content_type = make_blocked_response(
        question=question,
        accept=accept,
        request_wire=request_wire,
        parsed_request=parsed_request,
    )

    return Response(
        _to_js_body(body),
        status=200,
        headers=_build_response_headers(
            content_type=content_type,
            response_from="rebind-protection",
            rebind=True,
            ecs_truncated=ecs_truncated,
        ),
    )


def _build_winner_response(
    winner: ProviderResult,
    results: list[ProviderResult],
    config_allowed: bool,
    ecs_truncated: str,
    endpoint: str,
) -> Response:
    """
    Build the final response from the winning provider result.

    Parameters:
    winner (ProviderResult): Winning provider result.
    results (list[ProviderResult]): All provider results.
    config_allowed (bool): Domain matched the allowlist.
    ecs_truncated (str): ECS truncation description.
    endpoint (str): Endpoint path.

    Returns:
    Response: Final HTTP response.
    """
    response_codes: list[str] = []
    blocked_ids: list[str] = []
    possibly_blocked_ids: list[str] = []
    timed_out_ids: list[str] = []
    connection_error_ids: list[str] = []
    failed_count: int = 0
    retried_count: int = 0
    failed_status_count: int = 0

    for result in results:
        pid: str = result.provider_id
        response_codes.append(f"{pid}:{result.response_status}")
        if result.blocked:
            blocked_ids.append(pid)
        if result.possibly_blocked:
            possibly_blocked_ids.append(pid)
        if result.timed_out:
            timed_out_ids.append(pid)
        if result.connection_error:
            connection_error_ids.append(pid)
        if result.retry_count > 0:
            retried_count += 1
        if result.failed:
            failed_count += 1
            if not result.timed_out and not result.connection_error:
                failed_status_count += 1

    rebind_triggered: bool = any(result.rebind for result in results)

    response_headers: dict[str, str] = _build_response_headers(
        content_type=winner.response_content_type,
        response_from=winner.provider_id,
        response_codes=response_codes,
        possibly_blocked=possibly_blocked_ids,
        blocked=blocked_ids,
        timed_out=timed_out_ids,
        connection_error=connection_error_ids,
        config_allowed=config_allowed,
        rebind=rebind_triggered,
        ecs_truncated=ecs_truncated,
        providers_queried=len(results),
        providers_failed=failed_count,
        providers_timed_out=len(timed_out_ids),
        providers_conn_error=len(connection_error_ids),
        providers_failed_status=failed_status_count,
        providers_retried=retried_count,
        response_from_main=winner.main,
    )

    min_ttl: int | None = get_response_min_ttl(winner)

    if min_ttl is not None:
        response_headers["Cache-Control"] = f"max-age={min_ttl}"

    if config.DEBUG:
        logger.debug("endpoint: '%s'", endpoint)
        for key, value in response_headers.items():
            if key != "content-type":
                logger.debug("%s: '%s'", key, value)

    return Response(
        _to_js_body(winner.response_body),
        status=winner.response_status,
        headers=response_headers,
    )


async def _handle_request(
    request: object,
    endpoint: str,
    doh_providers: list[dict],
    cfg: _ResolvedConfig,
    env: object,
    ctx: object,
    parsed_url: urllib.parse.ParseResult,
) -> Response:
    """
    Core DoH handler: parse request, fan out to providers, return best result.

    Parameters:
    request (object): Incoming HTTP request.
    endpoint (str): Matched endpoint path.
    doh_providers (list[dict]): Providers for this endpoint.
    cfg (_ResolvedConfig): Resolved runtime config.
    env (object): Worker environment with secrets.
    ctx (object): Worker execution context.
    parsed_url (urllib.parse.ParseResult): Parsed request URL.

    Returns:
    Response: Final HTTP response.
    """
    request_timestamp_ms: int = int(time.time() * 1000)
    client_ip: str = str(request.headers.get("cf-connecting-ip") or "unknown")
    query: str = f"?{parsed_url.query}" if parsed_url.query else ""
    method: str = str(request.method).upper()
    raw_accept: str = str(request.headers.get("accept") or "")
    accept: str = _negotiate_accept(raw_accept)

    loki_url: str = cfg.loki_url
    loki_enabled: bool = bool(
        loki_url
        and getattr(env, "LOKI_USERNAME", None)
        and getattr(env, "LOKI_PASSWORD", None),
    )

    parsed: DnsParseResult | Response = await _parse_dns_request(
        request=request,
        query_string=parsed_url.query,
        method=method,
        accept=accept,
    )
    if isinstance(parsed, Response):
        return parsed

    question: Question = parsed.question
    body_bytes: bytes | None = parsed.body_bytes
    ecs_truncated: str = parsed.ecs_description
    request_wire: bytes | None = parsed.request_wire
    parsed_request: object = parsed.parsed_request

    if method == "GET" and body_bytes is None and question.name:
        _json_params: dict[str, str] = {"name": question.name}
        if question.type:
            _json_params["type"] = question.type
        query = "?" + urllib.parse.urlencode(_json_params)

    name: str = question.name
    config_allowed: bool = bool(
        name and domain_matches(name=name, compiled=_ALLOWED_COMPILED),
    )

    cache_key: str | None = None
    if config.CACHE_DNS:
        cache_key = _build_cache_key(
            endpoint=endpoint,
            body_bytes=body_bytes,
            question=question,
        )

    error: bool = False
    results: list[ProviderResult] = []
    response_from: str = "error"

    if config_allowed:
        doh_providers = cfg.bypass_provider_list

    config_blocked = bool(
        name
        and not config_allowed
        and domain_matches(name=name, compiled=_BLOCKED_COMPILED),
    )

    blocklist_bypassed: bool = False
    blocklist_loading_503: bool = False
    if not name or config_allowed or config_blocked or not config.BLOCKLIST_ENABLED:
        kv_blocklist: BlocklistCache = _EMPTY_BLOCKLIST
    else:
        kv_blocklist = await _load_blocklist_from_kv(env)

        if kv_blocklist is None:
            if config.BLOCKLIST_LOADING_POLICY == "bypass":
                logger.info("Blocklist still loading, bypassing check.")
                kv_blocklist = _EMPTY_BLOCKLIST
                blocklist_bypassed = True
            else:
                logger.warning("Blocklist still loading, returning 503.")
                blocklist_loading_503 = True
                kv_blocklist = _EMPTY_BLOCKLIST

    config_blocked = config_blocked or bool(
        name and not config_allowed and kv_blocklist.check(name),
    )

    results: list[ProviderResult] = []
    response_from: str = "error"
    error: bool = False
    final_response: Response | None = None

    if blocklist_loading_503:
        final_response = Response(
            "Service Unavailable",
            status=503,
            headers={"Retry-After": "1"},
        )
    elif config_blocked:
        response_from = "config"

        body, content_type = make_blocked_response(
            question=question,
            accept=accept,
            request_wire=request_wire,
            parsed_request=parsed_request,
        )
        final_response = Response(
            _to_js_body(body),
            status=200,
            headers=_build_response_headers(
                content_type=content_type,
                response_from="config",
                config_blocked=True,
                ecs_truncated=ecs_truncated,
            ),
        )
    else:
        if cache_key:
            cached_response: Response | None = await _try_cache_get(cache_key)
            if cached_response is not None:
                response_from = "cache"
                final_response = cached_response

        if final_response is None:
            safety_timeout_ms: int = config.TIMEOUT_MS + 2000

            try:
                results = await send_doh_requests_fanout(
                    doh_providers=doh_providers,
                    method=method,
                    accept=accept,
                    body_bytes=body_bytes,
                    query=query,
                    safety_timeout_ms=safety_timeout_ms,
                )
            except Exception:
                logger.exception("send_doh_requests_fanout failed")

                error = True

                final_response = Response(
                    "Service Unavailable",
                    status=503,
                    headers={"Retry-After": "1"},
                )
            else:
                try:
                    rebind_response: Response | None = _make_rebind_blocked_response(
                        results=results,
                        question=question,
                        accept=accept,
                        request_wire=request_wire,
                        ecs_truncated=ecs_truncated,
                        parsed_request=parsed_request,
                    )

                    if rebind_response is not None:
                        response_from = "rebind-protection"
                        error = True
                        final_response = rebind_response
                    elif winner := _select_winner(results):
                        response_from = winner.provider_id
                        final_response = _build_winner_response(
                            winner=winner,
                            results=results,
                            config_allowed=config_allowed,
                            ecs_truncated=ecs_truncated,
                            endpoint=endpoint,
                        )

                        min_ttl: int | None = get_response_min_ttl(winner)
                        if cache_key and min_ttl and min_ttl > 0:
                            stable_headers: dict[str, str] = {}
                            if config_allowed:
                                stable_headers[_HEADER_ALLOWED] = "1"
                            if ecs_truncated:
                                stable_headers[_HEADER_ECS_TRUNCATED] = ecs_truncated
                            _schedule_cache_put(
                                ctx=ctx,
                                cache_key=cache_key,
                                body=winner.response_body,
                                content_type=winner.response_content_type,
                                min_ttl=min_ttl,
                                extra_headers=stable_headers or None,
                            )
                    else:
                        error = True

                        final_response = Response(
                            "All providers responded with an error",
                            status=500,
                        )
                except Exception:
                    logger.exception("Failed to process provider results")
                    error = True
                    final_response = Response("Internal server error", status=500)

    if loki_enabled:
        elapsed_ms: int = int(time.time() * 1000) - request_timestamp_ms
        promise: object | None = build_loki_fetch_promise(
            request_timestamp_ms=request_timestamp_ms,
            elapsed_ms=elapsed_ms,
            endpoint=endpoint,
            question=question,
            response_from=response_from
            if not blocklist_loading_503
            else "blocklist-loading",
            results=results,
            env=env,
            loki_url=loki_url,
            client_ip=client_ip,
            config_blocked=config_blocked,
            config_allowed=config_allowed,
            error=error or blocklist_loading_503,
            kv_loading=blocklist_bypassed or blocklist_loading_503,
            blocklist_domain_count=_kv_blocklist_cache.domain_count
            if _kv_blocklist_cache is not None
            else 0,
        )
        if promise is not None:
            ctx.waitUntil(promise)

    return final_response
