# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

import base64
import hmac
import json
import logging
import re
import time
from typing import NamedTuple

from js import URL
from pyodide.ffi import to_js
from workers import Response, WorkerEntrypoint

import config
from dns_utils import (
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

logging.basicConfig(
  level=logging.DEBUG if config.DEBUG else logging.WARNING,
  format="%(name)s %(levelname)s %(message)s",
)

logger = logging.getLogger(__name__)

_ALLOWED_COMPILED = compile_domain_set(config.ALLOWED_DOMAINS)
_BLOCKED_COMPILED = compile_domain_set(config.BLOCKED_DOMAINS)


def _validate_config():
  """Validate configuration at module load time."""

  if not config.ALLOWED_DOMAINS:
    return
  if not isinstance(config.BYPASS_PROVIDER, dict):
    raise ValueError("BYPASS_PROVIDER must be a dict when ALLOWED_DOMAINS is set")
  for key in ("host", "path"):
    value = config.BYPASS_PROVIDER.get(key)
    if not isinstance(value, str) or not value:
      raise ValueError(
        f"BYPASS_PROVIDER '{key}' must be a non-empty string when ALLOWED_DOMAINS is set"
      )


_validate_config()


def _with_provider_id(provider: dict) -> dict:
  """Return a copy of *provider* with a pre-computed provider_id key."""

  return {**provider, "provider_id": f"{provider['host']}{provider['path']}"}


_SECRET_RE = re.compile(r"\{([A-Z][A-Z0-9_]*)\}")


def _resolve_secrets(obj, env):
  """Recursively substitute {SECRET_NAME} placeholders in strings, dicts, and lists."""

  missing: list[str] = []

  def _resolve(value):
    if isinstance(value, str):
      if "{" not in value:
        return value

      def _replacer(m):
        try:
          secret = getattr(env, m.group(1), None)
        except Exception:
          secret = None
        if not secret:
          missing.append(m.group(1))
          return m.group(0)
        return str(secret)

      return _SECRET_RE.sub(_replacer, value)
    if isinstance(value, dict):
      return {k: _resolve(v) for k, v in value.items()}
    if isinstance(value, list):
      return [_resolve(item) for item in value]
    return value

  resolved = _resolve(obj)

  if missing:
    raise ValueError(f"Missing secret(s): {', '.join(sorted(set(missing)))}")

  return resolved


def _resolve_providers(providers: list[dict], env) -> list[dict]:
  """Resolve secret placeholders in providers and recompute provider_id."""

  resolved = _resolve_secrets(providers, env)
  for provider in resolved:
    provider["provider_id"] = f"{provider['host']}{provider['path']}"

  return resolved


def _build_provider_lists() -> dict[str, list[dict]]:
  """Build the per-endpoint provider lists from ENDPOINTS config."""

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
  """Runtime configuration with all {SECRET} placeholders resolved."""

  health_endpoint: str | None
  config_endpoint: str | None
  loki_url: str
  provider_lists: dict[str, list[dict]]
  bypass_provider_list: list[dict]


def _resolve_config(env) -> _ResolvedConfig:
  """Resolve all {SECRET} placeholders in the config."""

  global _resolved_config_cache

  if _resolved_config_cache is not None:
    return _resolved_config_cache

  health = (
    _resolve_secrets(config.HEALTH_ENDPOINT, env) if config.HEALTH_ENDPOINT else None
  )
  config_ep = (
    _resolve_secrets(config.CONFIG_ENDPOINT, env) if config.CONFIG_ENDPOINT else None
  )
  try:
    loki_url = _resolve_secrets(config.LOKI_URL, env) if config.LOKI_URL else ""
  except ValueError:
    loki_url = ""

  provider_lists = {
    _resolve_secrets(path, env): _resolve_providers(providers, env)
    for path, providers in _PROVIDER_LISTS.items()
  }

  resolved = _ResolvedConfig(
    health_endpoint=health,
    config_endpoint=config_ep,
    loki_url=loki_url,
    provider_lists=provider_lists,
    bypass_provider_list=_resolve_providers(_BYPASS_PROVIDER_LIST, env),
  )

  _resolved_config_cache = resolved

  return resolved


class Default(WorkerEntrypoint):
  async def fetch(self, request):
    url = URL.new(request.url)
    pathname = str(url.pathname)

    try:
      cfg = _resolve_config(self.env)
    except ValueError as e:
      logger.exception("Configuration error: %s", e)
      return Response("Internal server error", status=500)

    if cfg.health_endpoint and pathname == cfg.health_endpoint:
      return Response("ok", status=200)

    if cfg.config_endpoint and pathname == cfg.config_endpoint:
      return _handle_config(request, self.env)

    doh_providers = cfg.provider_lists.get(pathname)

    if doh_providers is None:
      return Response("", status=404)

    return await _handle_request(
      request, pathname, doh_providers, cfg, self.env, self.ctx, url
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
    "ENDPOINTS",
  }
)


def _handle_config(request, env) -> Response:
  """Return current runtime configuration as JSON, gated by ADMIN_TOKEN secret."""

  token = getattr(env, "ADMIN_TOKEN", None)

  if not token:
    return Response("", status=404)

  auth_header = str(request.headers.get("authorization") or "")

  provided = ""

  if auth_header.startswith("Bearer "):
    provided = auth_header[7:].strip()

  if not hmac.compare_digest(provided, str(token)):
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


def _json_default(obj):
  if isinstance(obj, set):
    return sorted(obj)

  raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


_HEADER_PREFIX = "CLOUDFLARE-DOH-WORKER"
_HEADER_RESPONSE_FROM = f"{_HEADER_PREFIX}-RESPONSE-FROM"
_HEADER_RESPONSE_CODES = f"{_HEADER_PREFIX}-RESPONSE-CODES"
_HEADER_POSSIBLY_BLOCKED = f"{_HEADER_PREFIX}-POSSIBLY-BLOCKED-PROVIDERS"
_HEADER_BLOCKED = f"{_HEADER_PREFIX}-BLOCKED-PROVIDERS"
_HEADER_TIMED_OUT = f"{_HEADER_PREFIX}-TIMED-OUT-PROVIDERS"
_HEADER_ALLOWED = f"{_HEADER_PREFIX}-CONFIG-ALLOWED"
_HEADER_CONFIG_BLOCKED = f"{_HEADER_PREFIX}-CONFIG-BLOCKED"
_HEADER_REBIND_PROTECTED = f"{_HEADER_PREFIX}-REBIND-PROTECTED"
_HEADER_ECS_TRUNCATED = f"{_HEADER_PREFIX}-ECS-TRUNCATED"


def _build_response_headers(
  content_type: str,
  response_from: str,
  *,
  response_codes: list[str] | None = None,
  possibly_blocked: list[str] | None = None,
  blocked: list[str] | None = None,
  timed_out: list[str] | None = None,
  config_allowed: bool = False,
  config_blocked: bool = False,
  rebind: bool = False,
  ecs_truncated: str = "",
) -> dict:
  """Build response headers with optional DEBUG diagnostics."""

  headers = {"content-type": content_type}

  if rebind:
    headers[_HEADER_REBIND_PROTECTED] = "1"

  if ecs_truncated:
    headers[_HEADER_ECS_TRUNCATED] = ecs_truncated

  if config.DEBUG:
    headers.update(
      {
        _HEADER_RESPONSE_FROM: response_from,
        _HEADER_RESPONSE_CODES: ", ".join(response_codes or []),
        _HEADER_POSSIBLY_BLOCKED: ", ".join(possibly_blocked or []),
        _HEADER_BLOCKED: ", ".join(blocked or []),
        _HEADER_TIMED_OUT: ", ".join(timed_out or []),
        _HEADER_ALLOWED: "1" if config_allowed else "",
        _HEADER_CONFIG_BLOCKED: "1" if config_blocked else "",
      }
    )

  return headers


def _to_js_body(body):
  """Convert Python bytes to a JS Uint8Array for Cloudflare Workers Response."""

  if isinstance(body, (bytes, bytearray)):
    return to_js(body)

  return body


def _negotiate_accept(raw: str) -> str:
  """Return the first supported media type from a raw Accept header."""

  for part in raw.split(","):
    media_type = part.split(";", 1)[0].strip().lower()
    if media_type in SUPPORTED_ACCEPT_HEADERS:
      return media_type

  return ""


class _RejectError(Exception):
  """Raised to short-circuit _parse_dns_request with an error Response."""

  def __init__(self, message: str, status: int = 406):
    self.response = Response(message, status=status)


async def _parse_dns_request(
  request,
  js_url,
  method: str,
  accept: str,
) -> DnsParseResult | Response:
  """Parse DNS question and body bytes from the incoming request.

  Returns a DnsParseResult on success, or a Response on error.
  """

  try:
    if method == "GET":
      return _parse_get(js_url, accept)

    if method == "POST":
      return await _parse_post(request, accept)

    raise _RejectError(f"Method not allowed: {method}", status=405)
  except _RejectError as r:
    return r.response


def _parse_get(js_url, accept: str) -> DnsParseResult:
  """Handle GET requests (wire ?dns= or JSON ?name=)."""

  if not accept:
    supported = ", ".join(sorted(SUPPORTED_ACCEPT_HEADERS))
    raise _RejectError(f"Unsupported Accept header\n\nUse one of: {supported}")

  sp = js_url.searchParams
  dns_param = sp.get("dns")
  name_param = sp.get("name")

  if dns_param:
    if accept != "application/dns-message":
      raise _RejectError("GET ?dns= requires Accept: application/dns-message")

    raw = str(dns_param)
    padded = raw + "=" * (-len(raw) % 4)

    try:
      data = base64.urlsafe_b64decode(padded)
      return parse_dns_wire_request(data)
    except Exception:
      raise _RejectError("Failed to decode dns query parameter", status=400) from None

  if name_param:
    if accept != "application/dns-json":
      raise _RejectError("GET ?name= requires Accept: application/dns-json")

    type_param = sp.get("type")
    question = Question(
      name=str(name_param),
      type=str(type_param) if type_param else "",
    )
    return DnsParseResult(question, None, "", None)

  raise _RejectError(
    "GET requests must include one of name or dns as query parameters", status=400
  )


async def _parse_post(request, accept: str) -> DnsParseResult:
  """Handle POST requests (wire body)."""

  if accept != "application/dns-message":
    raise _RejectError("POST requires Accept: application/dns-message")

  try:
    raw_bytes = await request.bytes()
    return parse_dns_wire_request(raw_bytes)
  except Exception as e:
    logger.debug("Failed to decode DNS packet: %s", e)
    raise _RejectError("Failed to decode DNS packet", status=400) from None


def _select_winner(results: list[ProviderResult]) -> ProviderResult | None:
  """Pick the best result from provider responses."""

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
    first_blocked or first_possibly_blocked or first_successful_main or first_successful
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
) -> Response | None:
  """Build a synthetic NXDOMAIN when all successful responses have private IPs."""

  if not (
    config.REBIND_PROTECTION
    and any(r.rebind for r in results)
    and all(r.failed or r.rebind for r in results)
  ):
    return None

  body, content_type = make_blocked_response(question, accept, request_wire)

  return Response(
    _to_js_body(body),
    status=200,
    headers=_build_response_headers(
      content_type,
      "rebind-protection",
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
  """Build the final Response from the winning provider result."""

  response_codes = []
  blocked_ids = []
  possibly_blocked_ids = []
  timed_out_ids = []

  for result in results:
    pid = result.provider_id
    response_codes.append(f"{pid}:{result.response_status}")
    if result.blocked:
      blocked_ids.append(pid)
    if result.possibly_blocked:
      possibly_blocked_ids.append(pid)
    if result.timed_out:
      timed_out_ids.append(pid)

  rebind_triggered = any(result.rebind for result in results)

  response_headers = _build_response_headers(
    winner.response_content_type,
    winner.provider_id,
    response_codes=response_codes,
    possibly_blocked=possibly_blocked_ids,
    blocked=blocked_ids,
    timed_out=timed_out_ids,
    config_allowed=config_allowed,
    rebind=rebind_triggered,
    ecs_truncated=ecs_truncated,
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
  request,
  endpoint: str,
  doh_providers: list[dict],
  cfg: _ResolvedConfig,
  env,
  ctx,
  js_url,
) -> Response:
  request_timestamp_ms = int(time.time() * 1000)
  client_ip = str(request.headers.get("cf-connecting-ip") or "unknown")
  query = str(js_url.search)
  method = str(request.method).upper()
  raw_accept = str(request.headers.get("accept") or "")
  accept = _negotiate_accept(raw_accept)

  loki_url = cfg.loki_url
  loki_enabled = bool(
    loki_url
    and getattr(env, "LOKI_USERNAME", None)
    and getattr(env, "LOKI_PASSWORD", None)
  )

  parsed = await _parse_dns_request(request, js_url, method, accept)
  if isinstance(parsed, Response):
    return parsed

  question = parsed.question
  body_bytes = parsed.body_bytes
  ecs_truncated = parsed.ecs_description
  request_wire = parsed.request_wire

  name = question.name
  config_allowed = bool(name and domain_matches(name, _ALLOWED_COMPILED))

  config_blocked = False
  error = False
  results = []
  response_from = "error"

  if config_allowed:
    doh_providers = cfg.bypass_provider_list

  if name and domain_matches(name, _BLOCKED_COMPILED):
    body, content_type = make_blocked_response(question, accept, request_wire)

    final_response = Response(
      _to_js_body(body),
      status=200,
      headers=_build_response_headers(
        content_type, "config", config_blocked=True, ecs_truncated=ecs_truncated
      ),
    )

    config_blocked = True
    response_from = "config"
  else:
    results = await send_doh_requests_fanout(
      doh_providers, method, accept, body_bytes, query
    )

    rebind_response = _make_rebind_blocked_response(
      results, question, accept, request_wire, ecs_truncated
    )

    if rebind_response is not None:
      response_from = "rebind-protection"
      error = True
      final_response = rebind_response
    elif winner := _select_winner(results):
      response_from = winner.provider_id
      final_response = _build_winner_response(
        winner, results, config_allowed, ecs_truncated, endpoint
      )
    else:
      error = True
      final_response = Response("All providers responded with an error", status=500)

  if loki_enabled:
    promise = build_loki_fetch_promise(
      request_timestamp_ms,
      endpoint,
      question,
      response_from,
      results,
      env,
      loki_url,
      client_ip=client_ip,
      config_blocked=config_blocked,
      config_allowed=config_allowed,
      error=error,
    )

    if promise is not None:
      ctx.waitUntil(promise)

  return final_response
