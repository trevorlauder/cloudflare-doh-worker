# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Cloudflare Worker entrypoint for the DNS-over-HTTPS proxy."""

import asyncio
import base64
import hmac
import json
import logging
import re
import time
from typing import NamedTuple
import urllib.parse

import dns.exception
import dns.name
import dns.rdatatype
from workers import Response, WorkerEntrypoint

import config
from dns_utils import (
    MAX_DNS_BODY_SIZE,
    SUPPORTED_ACCEPT_HEADERS,
    DnsParseResult,
    ProviderResult,
    Question,
    compile_domain_set,
    domain_matches,
    get_response_min_ttl,
    make_blocked_response,
    parse_dns_wire_request,
    send_doh_requests_fanout,
)
from loki_utils import build_loki_fetch_promise


class _JsonFormatter(logging.Formatter):
    """
    Emit log records as single-line JSON for Workers Observability.

    Inherits from logging.Formatter.
    """

    def format(self, record: logging.LogRecord) -> str:
        """
        Format a log record as a single-line JSON string.

        Parameters:
        record (logging.LogRecord): The log record to format.

        Returns:
        str: JSON with level, logger, message, and an optional exception field.
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


_CONFIG_TYPE_RULES: list[tuple[str, type | tuple]] = [
    ("DEBUG", bool),
    ("TIMEOUT_MS", int),
    ("LOKI_TIMEOUT_MS", int),
    ("RETRY_MAX_ATTEMPTS", int),
    ("REBIND_PROTECTION", bool),
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
    """
    Raise TypeError if any config value has the wrong type.

    Returns:
    None
    """
    for name, expected_type in _CONFIG_TYPE_RULES:
        value = getattr(config, name, None)

        if value is not None and not isinstance(value, expected_type):
            raise TypeError(
                f"config.{name} must be {expected_type.__name__}, got {type(value).__name__}",
            )


def _validate_config() -> None:
    """
    Validate cross-field config constraints at import time.

    Returns:
    None
    """
    if not config.ALLOWED_DOMAINS:
        return

    value = config.BYPASS_PROVIDER.get("url")

    if not isinstance(value, str) or not value:
        raise ValueError(
            "BYPASS_PROVIDER 'url' must be a non-empty string when ALLOWED_DOMAINS is set",
        )


_validate_types()
_validate_config()


def _with_provider_id(provider: dict) -> dict:
    """
    Return a copy of provider with a pre-computed provider_id key.

    Parameters:
    provider (dict): Provider config dict.

    Returns:
    dict: Provider dict with provider_id.
    """
    return {**provider, "provider_id": provider["url"]}


_SECRET_RE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")


def _resolve_secrets(data: object, env: object) -> object:
    """
    Recursively substitute ${SECRET_NAME} placeholders in strings, dicts, and lists.

    Parameters:
    data (object): Data to resolve placeholders in.
    env (object): Environment with secrets.

    Returns:
    object: Resolved object.
    """
    missing: list[str] = []

    def _resolve(value: object) -> object:
        """
        Recursively resolve placeholders in a value.

        Parameters:
        value (object): Value to resolve.

        Returns:
        object: Resolved value.
        """
        if isinstance(value, str):
            if "${" not in value:
                return value

            def _replacer(match: re.Match[str]) -> str:
                """
                Replace a single ${SECRET_NAME} match with the secret value.

                Parameters:
                match (re.Match[str]): Regex match object.

                Returns:
                str: Resolved secret value or original placeholder.
                """
                try:
                    secret = getattr(env, match.group(1), None)
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

    resolved = _resolve(data)

    if missing:
        raise ValueError(f"Missing secret(s): {', '.join(sorted(set(missing)))}")

    return resolved


def _resolve_providers(providers: list[dict], env: object) -> list[dict]:
    """
    Resolve secret placeholders in providers and recompute provider_id.

    Parameters:
    providers (list[dict]): List of provider dicts.
    env (object): Environment with secrets.

    Returns:
    list[dict]: List of resolved provider dicts.
    """
    resolved = _resolve_secrets(data=providers, env=env)

    for provider in resolved:
        provider["provider_id"] = provider["url"]

    return resolved


def _build_provider_lists() -> dict[str, list[dict]]:
    """
    Build per-endpoint provider lists from config at import time.

    Returns:
    dict[str, list[dict]]: Mapping of endpoint paths to provider lists.
    """
    result: dict[str, list[dict]] = {}
    for path, cfg in config.ENDPOINTS.items():
        main = _with_provider_id({**cfg["main_provider"], "main": True})

        additional = [
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
    """
    Runtime configuration with all ${SECRET} placeholders resolved.

    Attributes:
    health_endpoint (str | None): Health endpoint path.
    config_endpoint (str | None): Config endpoint path.
    loki_url (str): Loki URL.
    provider_lists (dict[str, list[dict]]): Endpoint provider lists.
    bypass_provider_list (list[dict]): Bypass provider list.
    """

    health_endpoint: str | None
    config_endpoint: str | None
    loki_url: str
    provider_lists: dict[str, list[dict]]
    bypass_provider_list: list[dict]


def _resolve_config(env: object) -> _ResolvedConfig:
    """
    Resolve all ${SECRET} placeholders in the config.

    Parameters:
    env (object): Environment with secrets.

    Returns:
    _ResolvedConfig: Resolved runtime configuration.
    """
    global _resolved_config_cache

    if _resolved_config_cache is not None:
        return _resolved_config_cache

    health = (
        _resolve_secrets(data=config.HEALTH_ENDPOINT, env=env)
        if config.HEALTH_ENDPOINT
        else None
    )
    config_ep = (
        _resolve_secrets(data=config.CONFIG_ENDPOINT, env=env)
        if config.CONFIG_ENDPOINT
        else None
    )
    try:
        loki_url = (
            _resolve_secrets(data=config.LOKI_URL, env=env) if config.LOKI_URL else ""
        )
    except ValueError as e:
        logger.warning(
            "Loki logging disabled: failed to resolve LOKI_URL secret(s): %s",
            e,
        )

        loki_url = ""

    provider_lists = {
        _resolve_secrets(data=path, env=env): _resolve_providers(
            providers=providers,
            env=env,
        )
        for path, providers in _PROVIDER_LISTS.items()
    }

    resolved = _ResolvedConfig(
        health_endpoint=health,
        config_endpoint=config_ep,
        loki_url=loki_url,
        provider_lists=provider_lists,
        bypass_provider_list=_resolve_providers(
            providers=_BYPASS_PROVIDER_LIST,
            env=env,
        ),
    )

    if loki_url or not config.LOKI_URL:
        _resolved_config_cache = resolved

    return resolved


class Default(WorkerEntrypoint):
    """
    Cloudflare Worker entrypoint handling DNS-over-HTTPS requests.

    Inherits from WorkerEntrypoint.
    """

    async def fetch(self, request: object) -> Response:
        """
        Top-level request handler with global exception guard.

        Parameters:
        request (object): Incoming HTTP request.

        Returns:
        Response: HTTP response object.
        """
        try:
            return await self._handle(request)
        except Exception:
            logger.exception("Unhandled exception in fetch")
            return Response("Internal server error", status=500)

    async def _handle(self, request: object) -> Response:
        """
        Route the request to health, config, or DoH handler.

        Parameters:
        request (object): Incoming HTTP request.

        Returns:
        Response: HTTP response object.
        """
        parsed_url = urllib.parse.urlparse(str(request.url))
        pathname = parsed_url.path

        try:
            cfg = _resolve_config(self.env)
        except ValueError as e:
            logger.exception("Configuration error: %s", e)
            return Response("Internal server error", status=500)

        if cfg.health_endpoint and pathname == cfg.health_endpoint:
            return _handle_health(cfg)

        if cfg.config_endpoint and pathname == cfg.config_endpoint:
            return _handle_config(request=request, env=self.env)

        doh_providers = cfg.provider_lists.get(pathname)

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


def _handle_health(cfg: _ResolvedConfig) -> Response:
    """
    Return a lightweight JSON health response.

    Parameters:
    cfg (_ResolvedConfig): The resolved runtime configuration.

    Returns:
    Response: HTTP response with status 200 and a JSON body containing status and endpoint count.
    """
    body = json.dumps(
        {
            "status": "ok",
            "endpoints": len(cfg.provider_lists),
        },
    )
    return Response(
        body,
        status=200,
        headers={
            "content-type": "application/json",
            "Cache-Control": "no-store",
        },
    )


_CONFIG_ALLOWLIST = frozenset(
    {
        "CONFIG_ENDPOINT",
        "DEBUG",
        "HEALTH_ENDPOINT",
        "TIMEOUT_MS",
        "ECS_TRUNCATION",
        "REBIND_PROTECTION",
        "BLOCKED_DOMAINS",
        "ALLOWED_DOMAINS",
        "BYPASS_PROVIDER",
        "LOKI_URL",
        "LOKI_TIMEOUT_MS",
        "RETRY_MAX_ATTEMPTS",
        "ENDPOINTS",
    },
)


def _handle_config(request: object, env: object) -> Response:
    """
    Return current runtime configuration as JSON, gated by ADMIN_TOKEN secret.

    Parameters:
    request (object): Incoming HTTP request.
    env (object): Environment with secrets.

    Returns:
    Response: HTTP response with JSON config or error.
    """
    token = getattr(env, "ADMIN_TOKEN", None)

    if not token:
        return Response("", status=404)

    auth_header = str(request.headers.get("authorization") or "")

    if not auth_header.startswith("Bearer "):
        return Response("Unauthorized", status=401)

    provided = auth_header[7:].strip()

    if not provided or not hmac.compare_digest(provided, str(token)):
        return Response("Unauthorized", status=401)

    payload = {k: getattr(config, k) for k in _CONFIG_ALLOWLIST if hasattr(config, k)}

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
    JSON serializer fallback for set objects.

    Parameters:
    value (object): Value to serialize.

    Returns:
    list: Sorted list if value is set.
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
    Build response headers with optional DEBUG diagnostics.

    Parameters:
    content_type (str): Content-Type header value.
    response_from (str): Provider ID.
    response_codes (list[str] | None): Per-provider status codes.
    possibly_blocked (list[str] | None): Possibly blocked providers.
    blocked (list[str] | None): Blocked providers.
    timed_out (list[str] | None): Timed out providers.
    connection_error (list[str] | None): Providers with connection errors.
    config_allowed (bool): Is config allowed.
    config_blocked (bool): Is config blocked.
    rebind (bool): Rebind protection triggered.
    ecs_truncated (str): ECS truncation description.
    providers_queried (int): Number of providers queried.
    providers_failed (int): Number of providers failed.
    providers_timed_out (int): Number of providers timed out.
    providers_conn_error (int): Number of providers with connection errors.
    providers_failed_status (int): Number of providers failed with status code.
    providers_retried (int): Number of providers retried.
    response_from_main (bool | None): Response from main provider.

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


def _to_js_body(body: bytes | bytearray | str) -> object:
    """
    Convert Python bytes to a JS Uint8Array for Cloudflare Workers Response.

    Parameters:
    body (bytes | bytearray | str): Response body.

    Returns:
    object: JS Uint8Array or original body.
    """
    if isinstance(body, (bytes, bytearray)):
        from pyodide.ffi import to_js

        return to_js(body)

    return body


def _negotiate_accept(raw: str) -> str:
    """
    Return the first supported media type from a raw Accept header.

    Parameters:
    raw (str): Raw Accept header value.

    Returns:
    str: Supported media type or empty string.
    """
    for part in raw.split(","):
        media_type = part.split(";", 1)[0].strip().lower()
        if media_type in SUPPORTED_ACCEPT_HEADERS:
            return media_type

    return ""


class _RejectError(Exception):
    """
    Raised to short-circuit _parse_dns_request with an error Response.

    Inherits from Exception.
    """

    def __init__(self, message: str, status: int = 406) -> None:
        """
        Initialize _RejectError.

        Parameters:
        message (str): Error message.
        status (int): HTTP status code (default 406).

        Returns:
        None
        """
        self.response = Response(message, status=status)


async def _parse_dns_request(
    request: object,
    query_string: str,
    method: str,
    accept: str,
) -> DnsParseResult | Response:
    """
    Parse DNS question and wire bytes; returns DnsParseResult or a Response on error.

    Parameters:
    request (object): Incoming HTTP request.
    query_string (str): Query string.
    method (str): HTTP method.
    accept (str): Accept header value.

    Returns:
    DnsParseResult | Response: Parsed DNS result or error response.
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
    accept (str): Accept header value.

    Returns:
    DnsParseResult: Parsed DNS result.
    """
    if not accept:
        supported = ", ".join(sorted(SUPPORTED_ACCEPT_HEADERS))
        raise _RejectError(f"Unsupported Accept header\n\nUse one of: {supported}")

    params = urllib.parse.parse_qs(query_string, keep_blank_values=True)
    dns_param = params.get("dns", [None])[0]
    name_param = params.get("name", [None])[0]

    if dns_param:
        if accept != "application/dns-message":
            raise _RejectError("GET ?dns= requires Accept: application/dns-message")

        padded = dns_param + "=" * (-len(dns_param) % 4)

        try:
            data = base64.urlsafe_b64decode(padded)
            return parse_dns_wire_request(data)
        except Exception:
            raise _RejectError(
                "Failed to decode dns query parameter",
                status=400,
            ) from None

    if name_param:
        if accept != "application/dns-json":
            raise _RejectError("GET ?name= requires Accept: application/dns-json")

        type_param = params.get("type", [None])[0]
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

        question = Question(
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
    Parse a DNS wire message from a POST request body.

    Parameters:
    request (object): Incoming HTTP request.
    accept (str): Accept header value.

    Returns:
    DnsParseResult: Parsed DNS result.
    """
    if accept != "application/dns-message":
        raise _RejectError("POST requires Accept: application/dns-message")

    try:
        raw_bytes = await request.bytes()
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
    Pick the best upstream result: blocked > possibly_blocked > main > any.

    Parameters:
    results (list[ProviderResult]): List of provider results.

    Returns:
    ProviderResult | None: Winning provider result or None.
    """
    first_blocked = None
    first_possibly_blocked = None
    first_successful_main = None
    first_successful = None
    first_non_rebind_main = None
    first_non_rebind = None

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

    winner = (
        first_blocked
        or first_possibly_blocked
        or first_successful_main
        or first_successful
    )

    if winner is None:
        return None

    if winner.rebind and config.REBIND_PROTECTION:
        replacement = first_non_rebind_main or first_non_rebind
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
    Build a synthetic NXDOMAIN when all successful responses have private IPs.

    Parameters:
    results (list[ProviderResult]): List of provider results.
    question (Question): DNS question tuple.
    accept (str): Accept header value.
    request_wire (bytes | None): Original DNS wire message.
    ecs_truncated (str): ECS truncation description.
    parsed_request (object): Parsed DNS message (optional).

    Returns:
    Response | None: Synthetic NXDOMAIN response or None.
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
    Build the final HTTP Response from the winning provider result.

    Parameters:
    winner (ProviderResult): Winning provider result.
    results (list[ProviderResult]): List of provider results.
    config_allowed (bool): Is config allowed.
    ecs_truncated (str): ECS truncation description.
    endpoint (str): Endpoint path.

    Returns:
    Response: Final HTTP response.
    """
    response_codes = []
    blocked_ids = []
    possibly_blocked_ids = []
    timed_out_ids = []
    connection_error_ids = []
    failed_count = 0
    retried_count = 0
    failed_status_count = 0

    for result in results:
        pid = result.provider_id
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

    rebind_triggered = any(result.rebind for result in results)

    response_headers = _build_response_headers(
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

    min_ttl = get_response_min_ttl(winner)

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
    Core DoH handler: parse, fan-out to providers, select winner, respond.

    Parameters:
    request (object): Incoming HTTP request.
    endpoint (str): Endpoint path.
    doh_providers (list[dict]): List of provider dicts.
    cfg (_ResolvedConfig): Resolved config.
    env (object): Environment with secrets.
    ctx (object): Worker context.
    parsed_url (urllib.parse.ParseResult): Parsed URL.

    Returns:
    Response: Final HTTP response.
    """
    request_timestamp_ms = int(time.time() * 1000)
    client_ip = str(request.headers.get("cf-connecting-ip") or "unknown")
    query = f"?{parsed_url.query}" if parsed_url.query else ""
    method = str(request.method).upper()
    raw_accept = str(request.headers.get("accept") or "")
    accept = _negotiate_accept(raw_accept)

    loki_url = cfg.loki_url
    loki_enabled = bool(
        loki_url
        and getattr(env, "LOKI_USERNAME", None)
        and getattr(env, "LOKI_PASSWORD", None),
    )

    parsed = await _parse_dns_request(
        request=request,
        query_string=parsed_url.query,
        method=method,
        accept=accept,
    )
    if isinstance(parsed, Response):
        return parsed

    question = parsed.question
    body_bytes = parsed.body_bytes
    ecs_truncated = parsed.ecs_description
    request_wire = parsed.request_wire
    parsed_request = parsed.parsed_request

    if method == "GET" and body_bytes is None and question.name:
        _json_params: dict[str, str] = {"name": question.name}
        if question.type:
            _json_params["type"] = question.type
        query = "?" + urllib.parse.urlencode(_json_params)

    name = question.name
    config_allowed = bool(
        name and domain_matches(name=name, compiled=_ALLOWED_COMPILED),
    )

    config_blocked = False
    error = False
    results = []
    response_from = "error"

    if config_allowed:
        doh_providers = cfg.bypass_provider_list

    if name and domain_matches(name=name, compiled=_BLOCKED_COMPILED):
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

        config_blocked = True
        response_from = "config"
    else:
        safety_seconds = config.TIMEOUT_MS / 1000 + 2

        try:
            results = await asyncio.wait_for(
                send_doh_requests_fanout(
                    doh_providers=doh_providers,
                    method=method,
                    accept=accept,
                    body_bytes=body_bytes,
                    query=query,
                ),
                timeout=safety_seconds,
            )
        except TimeoutError:
            logger.warning(
                "send_doh_requests_fanout safety timeout (%.0fs)",
                safety_seconds,
            )

            return Response(
                "Service Unavailable",
                status=503,
                headers={"Retry-After": "1"},
            )

        try:
            rebind_response = _make_rebind_blocked_response(
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
        promise = build_loki_fetch_promise(
            request_timestamp_ms=request_timestamp_ms,
            endpoint=endpoint,
            question=question,
            response_from=response_from,
            results=results,
            env=env,
            loki_url=loki_url,
            client_ip=client_ip,
            config_blocked=config_blocked,
            config_allowed=config_allowed,
            error=error,
        )

        if promise is not None:
            ctx.waitUntil(promise)

    return final_response
