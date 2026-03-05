# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

import base64
import ipaddress
import json
import logging
from dataclasses import dataclass
from typing import NamedTuple

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype

import config

logger = logging.getLogger(__name__)


SUPPORTED_ACCEPT_HEADERS = frozenset(
  {"application/dns-json", "application/dns-message"}
)

DNS_JSON_HOSTS = frozenset(
  {
    "cloudflare-dns.com",
    "security.cloudflare-dns.com",
    "family.cloudflare-dns.com",
    "dns.google",
  }
)


def _build_servfail_wire() -> bytes:
  msg = dns.message.Message(id=0)
  msg.flags = dns.flags.QR | dns.flags.RD | dns.flags.RA
  msg.set_rcode(dns.rcode.SERVFAIL)
  return msg.to_wire()


_SERVFAIL_WIRE = _build_servfail_wire()


_PRIVATE_NETWORKS = (
  ipaddress.ip_network("10.0.0.0/8"),
  ipaddress.ip_network("172.16.0.0/12"),
  ipaddress.ip_network("192.168.0.0/16"),
  ipaddress.ip_network("100.64.0.0/10"),
  ipaddress.ip_network("127.0.0.0/8"),
  ipaddress.ip_network("169.254.0.0/16"),
  ipaddress.ip_network("::1/128"),
  ipaddress.ip_network("fc00::/7"),
  ipaddress.ip_network("fe80::/10"),
)


def _is_private_ip(addr: str) -> bool:
  """Return True if *addr* falls within a private/reserved IP range."""

  try:
    ip = ipaddress.ip_address(addr)
    return any(ip in net for net in _PRIVATE_NETWORKS)
  except ValueError:
    return False


def has_private_answers(addresses: list[str]) -> bool:
  """Return True if any address string is a private/internal IP."""

  return any(_is_private_ip(addr) for addr in addresses)


def truncate_ecs(
  data: bytes, *, msg: dns.message.Message | None = None
) -> tuple[bytes, str]:
  """Truncate ECS prefix lengths in a DNS wire message."""

  if not (config.ECS_TRUNCATION and config.ECS_TRUNCATION.get("enabled")):
    return data, ""

  if len(data) >= 12 and int.from_bytes(data[10:12], "big") == 0:
    return data, ""

  if msg is None:
    try:
      msg = dns.message.from_wire(data)
    except Exception:
      return data, ""

  if msg.edns < 0:
    return data, ""

  ipv4_prefix = config.ECS_TRUNCATION.get("ipv4_prefix", 24)
  ipv6_prefix = config.ECS_TRUNCATION.get("ipv6_prefix", 64)

  new_options = []
  descriptions = []
  changed = False

  for opt in msg.options:
    if isinstance(opt, dns.edns.ECSOption):
      target = ipv4_prefix if opt.family == 1 else ipv6_prefix

      if opt.srclen > target:
        truncated_opt = dns.edns.ECSOption(opt.address, srclen=target, scopelen=0)
        new_options.append(truncated_opt)
        descriptions.append(
          f"{opt.address}/{opt.srclen} -> {truncated_opt.address}/{target}"
        )
        changed = True
      else:
        new_options.append(opt)
    else:
      new_options.append(opt)

  if not changed:
    return data, ""

  msg.use_edns(
    edns=msg.edns,
    ednsflags=msg.ednsflags,
    payload=msg.payload,
    options=new_options,
    pad=msg.pad,
  )

  return msg.to_wire(), ", ".join(descriptions)


class Question(NamedTuple):
  """DNS question with name and type."""

  name: str
  type: str


class DnsParseResult(NamedTuple):
  """Result of parsing a DNS request from wire or query parameters."""

  question: Question
  body_bytes: bytes | None
  ecs_description: str
  request_wire: bytes | None
  parsed_request: dns.message.Message | None = None


@dataclass
class ProviderResult:
  """Result of querying an upstream DoH provider."""

  host: str
  path: str
  provider_id: str
  response_status: int
  response_content_type: str
  response_body: bytes | str
  main: bool
  failed: bool
  blocked: bool = False
  possibly_blocked: bool = False
  rebind: bool = False
  timed_out: bool = False
  retry_count: int = 0
  min_ttl: int | None = None


class _ProviderFetchRequest(NamedTuple):
  """Pre-built fetch request for an upstream provider."""

  url: str
  options: dict
  main: bool


def _extract_question(packet: dns.message.Message) -> Question:
  """Extract the first question from a parsed DNS message."""

  question = packet.question[0]
  return Question(
    name=str(question.name).rstrip("."),
    type=dns.rdatatype.to_text(question.rdtype),
  )


def parse_dns_wire_request(data: bytes) -> DnsParseResult:
  """Decode, ECS-truncate, and parse a DNS wire message in one step."""

  packet = dns.message.from_wire(data)
  question = _extract_question(packet)
  truncated, ecs_desc = truncate_ecs(data, msg=packet)
  return DnsParseResult(question, truncated, ecs_desc, data, packet)


def compile_domain_set(domains: list) -> tuple[frozenset, tuple]:
  """Split a domain set into (exact_set, suffix_tuple) for fast matching."""

  exact = set()
  suffixes = []
  for domain in domains:
    if domain.startswith("*."):
      suffixes.append("." + domain[2:])
    else:
      exact.add(domain)
  return frozenset(exact), tuple(suffixes)


def domain_matches(name: str, compiled: tuple[frozenset, tuple]) -> bool:
  """Check if a domain matches a pre-compiled (exact, suffixes) pair."""

  exact, suffixes = compiled
  name = name.rstrip(".").lower()
  if name in exact:
    return True

  return any(name.endswith(suffix) for suffix in suffixes)


def make_blocked_response(
  question: Question,
  accept: str,
  request_wire: bytes | None = None,
  parsed_request: dns.message.Message | None = None,
) -> tuple:
  """Build a synthetic NXDOMAIN DNS response for a blocked domain."""

  try:
    rdtype = dns.rdatatype.from_text(question.type or "A")
  except (dns.exception.SyntaxError, ValueError):
    rdtype = dns.rdatatype.A

  try:
    qname = dns.name.from_text(question.name or ".")
  except (
    dns.exception.SyntaxError,
    dns.name.LabelTooLong,
    dns.name.EmptyLabel,
    ValueError,
  ):
    qname = dns.name.from_text(".")

  if "dns-json" in accept:
    body = json.dumps(
      {
        "Status": 3,
        "Question": [{"name": question.name or ".", "type": int(rdtype)}],
        "Answer": [],
      }
    )

    return body, "application/dns-json"

  if parsed_request is not None:
    req = parsed_request
  elif request_wire is not None:
    try:
      req = dns.message.from_wire(request_wire)
    except Exception:
      req = dns.message.make_query(qname, rdtype)
  else:
    req = dns.message.make_query(qname, rdtype)

  try:
    resp = dns.message.make_response(req)
    resp.set_rcode(dns.rcode.NXDOMAIN)
    return resp.to_wire(), "application/dns-message"
  except Exception:
    logger.exception("Failed to build blocked DNS wire response")
    if request_wire and len(request_wire) >= 2:
      return request_wire[:2] + _SERVFAIL_WIRE[2:], "application/dns-message"
    return _SERVFAIL_WIRE, "application/dns-message"


_BLOCKED_ADDRS = frozenset({"0.0.0.0", "::"})  # noqa: S104


def _classify_answers(
  result: ProviderResult, status: int, addresses: list[str]
) -> None:
  """Set blocked/possibly_blocked/rebind directly on *result*."""

  blocked = any(addr in _BLOCKED_ADDRS for addr in addresses)
  result.blocked = blocked
  result.possibly_blocked = status == dns.rcode.NXDOMAIN
  if config.REBIND_PROTECTION and not blocked:
    result.rebind = has_private_answers(addresses)


MAX_DNS_BODY_SIZE = 65535

_RETRY_STATUS_CODES = frozenset(range(500, 600))


def _build_provider_fetch_request(
  provider: dict,
  method: str,
  accept: str,
  abort_signal,
  body_bytes: bytes | None = None,
  query: str = "",
) -> _ProviderFetchRequest:
  target_url = f"https://{provider['host']}{provider['path']}"

  if method == "GET" and body_bytes is not None:
    encoded = base64.urlsafe_b64encode(body_bytes).rstrip(b"=").decode("ascii")
    target_url += "?dns=" + encoded
  elif query:
    target_url += query

  main = provider.get("main", False)

  headers = {}

  if accept:
    headers["accept"] = accept

  if method == "POST":
    headers["content-type"] = "application/dns-message"

  headers.update(provider.get("headers", {}))

  fetch_options: dict = {
    "method": method,
    "headers": headers,
    "signal": abort_signal,
  }

  if body_bytes is not None and method == "POST":
    fetch_options["body"] = body_bytes

  return _ProviderFetchRequest(target_url, fetch_options, main)


def _get_provider_id(provider: dict) -> str:
  """Return the provider_id from config, falling back to host+path."""

  return provider.get("provider_id") or f"{provider['host']}{provider['path']}"


def _failed_result(provider: dict, main: bool, exc) -> ProviderResult:
  exc_str = f"{type(exc).__name__} {exc}".lower()
  timed_out = "timeout" in exc_str or "abort" in exc_str

  return ProviderResult(
    host=provider["host"],
    path=provider["path"],
    provider_id=_get_provider_id(provider),
    response_status=504 if timed_out else 502,
    response_content_type="application/dns-message",
    response_body=b"",
    main=main,
    failed=True,
    timed_out=timed_out,
  )


def _build_provider_result(
  resp_body: bytes | str,
  content_type: str,
  ok: bool,
  status: int,
  provider: dict,
  main: bool,
) -> ProviderResult:
  """Build a ProviderResult from pre-read response data (no async)."""

  is_json = "dns-json" in content_type or "application/json" in content_type

  result = ProviderResult(
    host=provider["host"],
    path=provider["path"],
    provider_id=_get_provider_id(provider),
    response_status=status,
    response_content_type=content_type,
    response_body=resp_body,
    main=main,
    failed=not ok,
  )

  if not ok:
    return result

  if is_json:
    try:
      resp_json = json.loads(resp_body)
      answers = resp_json.get("Answer", [])
      addresses = [a.get("data", "") for a in answers if a.get("data")]
      _classify_answers(result, resp_json.get("Status", 0), addresses)
      ttls = [a["TTL"] for a in answers if "TTL" in a]
      result.min_ttl = min(ttls) if ttls else None
    except Exception:
      logger.debug(
        "Failed to parse JSON DNS response from %s", provider["host"], exc_info=True
      )
  elif "dns-message" in content_type:
    try:
      packet = dns.message.from_wire(resp_body)

      addresses = [
        str(rr)
        for rrset in packet.answer
        for rr in rrset
        if rr.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA)
      ]
      _classify_answers(result, int(packet.rcode()), addresses)
      ttls = [rrset.ttl for rrset in packet.answer]
      result.min_ttl = min(ttls) if ttls else None
    except Exception:
      logger.debug(
        "Failed to parse binary DNS response from %s", provider["host"], exc_info=True
      )

  return result


def get_response_min_ttl(result: ProviderResult) -> int | None:
  """Return the minimum TTL from a provider's DNS response, or None."""

  return result.min_ttl


class _FanoutContext(NamedTuple):
  """JS/FFI references threaded through the fanout helpers."""

  fetch: object
  to_js: object
  Object: object
  Uint8Array: object


class _FanoutFetchEntry(NamedTuple):
  """A queued upstream fetch promise."""

  promise: object
  global_idx: int
  attempt: int


class _FanoutBodyEntry(NamedTuple):
  """A queued body-read promise for an already-settled fetch."""

  promise: object
  global_idx: int
  attempt: int
  content_type: str
  ok: bool
  response_status: int


def _fanout_fetch_entry(
  ctx: "_FanoutContext",
  provider: dict,
  method: str,
  accept: str,
  abort_signal,
  body_bytes: bytes | None,
  query: str,
  global_idx: int,
  attempt: int,
) -> _FanoutFetchEntry:
  """Build a _FanoutFetchEntry for the given provider."""

  target_url, fetch_options, _ = _build_provider_fetch_request(
    provider, method, accept, abort_signal, body_bytes, query
  )
  return _FanoutFetchEntry(
    promise=ctx.fetch(
      target_url, ctx.to_js(fetch_options, dict_converter=ctx.Object.fromEntries)
    ),
    global_idx=global_idx,
    attempt=attempt,
  )


def _process_fanout_round(
  round_settled,
  pending: list,
  provider_meta: list[tuple],
  results: list,
  method: str,
  accept: str,
  abort_signal,
  body_bytes: bytes | None,
  query: str,
  ctx: "_FanoutContext",
) -> list:
  """Process one allSettled round and return the next pending list."""

  next_pending: list = []

  for item, entry in zip(round_settled, pending, strict=True):
    provider, main = provider_meta[entry.global_idx]
    host = provider.get("host", "")

    if str(getattr(item, "status", "")) != "fulfilled":
      reason = getattr(item, "reason", "rejected")
      logger.error(
        "send_doh_requests %s for %s: %s", type(entry).__name__, host, reason
      )
      result = _failed_result(provider, main, reason)
      result.retry_count = entry.attempt
      results[entry.global_idx] = result
      continue

    if isinstance(entry, _FanoutFetchEntry):
      resp = item.value
      status = int(resp.status)
      content_type = str(resp.headers.get("content-type") or "application/dns-message")
      ok = bool(resp.ok)

      if status in _RETRY_STATUS_CODES and entry.attempt < config.RETRY_MAX_ATTEMPTS:
        logger.warning(
          "Retrying %s (attempt %d/%d, status %d)",
          host,
          entry.attempt + 1,
          config.RETRY_MAX_ATTEMPTS,
          status,
        )
        next_pending.append(
          _fanout_fetch_entry(
            ctx,
            provider,
            method,
            accept,
            abort_signal,
            body_bytes,
            query,
            entry.global_idx,
            entry.attempt + 1,
          )
        )
      else:
        if status in _RETRY_STATUS_CODES:
          logger.error(
            "All %d retries exhausted for %s (status %d)",
            config.RETRY_MAX_ATTEMPTS,
            host,
            status,
          )
        next_pending.append(
          _FanoutBodyEntry(
            promise=resp.text() if "json" in content_type else resp.arrayBuffer(),
            global_idx=entry.global_idx,
            attempt=entry.attempt,
            content_type=content_type,
            ok=ok,
            response_status=status,
          )
        )

    else:
      raw = item.value
      resp_body = (
        str(raw)
        if "json" in entry.content_type
        else bytes(ctx.Uint8Array.new(raw).to_py())
      )
      try:
        result = _build_provider_result(
          resp_body, entry.content_type, entry.ok, entry.response_status, provider, main
        )
      except Exception as exc:
        logger.error(
          "send_doh_requests failed for %s: %s: %s", host, type(exc).__name__, exc
        )
        result = _failed_result(provider, main, exc)
      result.retry_count = entry.attempt
      results[entry.global_idx] = result

  return next_pending


async def send_doh_requests_fanout(
  doh_providers: list,
  method: str,
  accept: str,
  body_bytes: bytes | None = None,
  query: str = "",
) -> list:
  """Query providers with JS Promise fan-out to avoid Python task re-entrancy."""

  from js import AbortSignal, Object, Promise, Uint8Array
  from js import fetch as js_fetch
  from pyodide.ffi import to_js

  if not doh_providers:
    return []

  abort_signal = AbortSignal.timeout(config.TIMEOUT_MS)
  is_json_query = accept == "application/dns-json" and body_bytes is None
  ctx = _FanoutContext(js_fetch, to_js, Object, Uint8Array)

  provider_meta: list[tuple] = []
  pending: list = []

  for provider in doh_providers:
    if is_json_query and provider.get("host", "") not in DNS_JSON_HOSTS:
      continue

    idx = len(provider_meta)
    main = provider.get("main", False)
    provider_meta.append((provider, main))
    pending.append(
      _fanout_fetch_entry(
        ctx, provider, method, accept, abort_signal, body_bytes, query, idx, 0
      )
    )

  results: list = [None] * len(provider_meta)

  while pending:
    round_settled = await Promise.allSettled(
      to_js([entry.promise for entry in pending])
    )

    pending = _process_fanout_round(
      round_settled,
      pending,
      provider_meta,
      results,
      method,
      accept,
      abort_signal,
      body_bytes,
      query,
      ctx,
    )

  return [r for r in results if r is not None]
