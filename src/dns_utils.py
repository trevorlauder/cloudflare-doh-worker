# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""DNS wire-format helpers, ECS truncation, and upstream provider fan-out."""

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
    {"application/dns-json", "application/dns-message"},
)


def _build_servfail_wire() -> bytes:
    """Build a pre-computed SERVFAIL wire response for error fallback."""
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
    """Return True if *addr* belongs to a private or reserved network."""
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def has_private_answers(addresses: list[str]) -> bool:
    """Return True if any address in the list is a private IP."""
    return any(_is_private_ip(addr) for addr in addresses)


def truncate_ecs(
    data: bytes,
    *,
    msg: dns.message.Message | None = None,
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
                truncated_opt = dns.edns.ECSOption(
                    opt.address,
                    srclen=target,
                    scopelen=0,
                )
                new_options.append(truncated_opt)
                descriptions.append(
                    f"{opt.address}/{opt.srclen} -> {truncated_opt.address}/{target}",
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

    url: str
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
    connection_error: bool = False
    retry_count: int = 0
    min_ttl: int | None = None


class _ProviderFetchRequest(NamedTuple):
    """Pre-built fetch request for an upstream provider."""

    url: str
    options: dict


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
            },
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

_RETRY_STATUS_CODES = frozenset({408, 429, 500, 502, 503, 504})


def _classify_answers(
    result: ProviderResult,
    status: int,
    addresses: list[str],
) -> None:
    """Set blocked/possibly_blocked/rebind directly on *result*."""
    blocked = any(addr in _BLOCKED_ADDRS for addr in addresses)
    result.blocked = blocked
    result.possibly_blocked = status == dns.rcode.NXDOMAIN
    if config.REBIND_PROTECTION and not blocked:
        result.rebind = has_private_answers(addresses)


MAX_DNS_BODY_SIZE = 65535


def _build_provider_fetch_request(
    provider: dict,
    method: str,
    accept: str,
    abort_signal: object,
    body_bytes: bytes | None = None,
    query: str = "",
) -> _ProviderFetchRequest:
    """Build a URL, headers, and fetch options for an upstream DoH provider."""
    target_url = provider["url"]

    if method == "GET" and body_bytes is not None:
        encoded = base64.urlsafe_b64encode(body_bytes).rstrip(b"=").decode("ascii")
        target_url += "?dns=" + encoded
    elif method == "GET" and query:
        target_url += query

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

    return _ProviderFetchRequest(target_url, fetch_options)


def _get_provider_id(provider: dict) -> str:
    """Return the provider_id from config, falling back to url."""
    return provider.get("provider_id") or provider["url"]


def _failed_result(provider: dict, main: bool, exc: object) -> ProviderResult:
    """Build a ProviderResult representing a failed upstream fetch."""
    exc_str = f"{type(exc).__name__} {exc}".lower()
    timed_out = "timeout" in exc_str or "abort" in exc_str

    return ProviderResult(
        url=provider["url"],
        provider_id=_get_provider_id(provider),
        response_status=504 if timed_out else 502,
        response_content_type="application/dns-message",
        response_body=b"",
        main=main,
        failed=True,
        timed_out=timed_out,
        connection_error=not timed_out,
    )


def _build_provider_result(
    resp_body: bytes | str,
    ok: bool,
    status: int,
    provider: dict,
    main: bool,
    accept: str,
) -> ProviderResult:
    """Build a ProviderResult from pre-read response data (no async)."""
    is_json = accept == "application/dns-json"

    result = ProviderResult(
        url=provider["url"],
        provider_id=_get_provider_id(provider),
        response_status=status,
        response_content_type=accept,
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
                "Failed to parse JSON DNS response from %s",
                provider["url"],
                exc_info=True,
            )
    else:
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
                "Failed to parse binary DNS response from %s",
                provider["url"],
                exc_info=True,
            )

    return result


def get_response_min_ttl(result: ProviderResult) -> int | None:
    """Return the minimum TTL from the provider result, or None."""
    return result.min_ttl


@dataclass
class _PendingFetch:
    """Work item carrying provider context through the two-gather loop."""

    provider: dict
    main: bool
    request: _ProviderFetchRequest
    response: object = None


def _partition_fetch_responses(
    pending: list[_PendingFetch],
    responses: list,
) -> tuple[list[_PendingFetch], list[ProviderResult]]:
    """Split fetch gather results into succeeded items and failed results.

    Parameters:
    pending (list[_PendingFetch]): Work items from the current retry round.
    responses (list): Gather results, positionally aligned with pending.

    Returns:
    tuple[list[_PendingFetch], list[ProviderResult]]: Succeeded items with
        their response attached, and ProviderResult failures.
    """
    succeeded: list[_PendingFetch] = []
    failed: list[ProviderResult] = []

    for item, resp in zip(pending, responses, strict=True):
        if isinstance(resp, BaseException):
            logger.error(
                "send_doh_requests fetch rejected for %s: %s",
                item.provider.get("url", ""),
                resp,
            )

            failed.append(_failed_result(item.provider, item.main, resp))
        else:
            item.response = resp
            succeeded.append(item)

    return succeeded, failed


def _process_bodies(
    succeeded: list[_PendingFetch],
    bodies: list,
    is_json: bool,
    accept: str,
    attempt: int,
    uint8array_cls: type,
) -> tuple[list[_PendingFetch], list[ProviderResult]]:
    """Decode response bodies and decide which providers to retry.

    Parameters:
    succeeded (list[_PendingFetch]): Items whose fetch succeeded.
    bodies (list): Body-read gather results, aligned with succeeded.
    is_json (bool): True when accept type is application/dns-json.
    accept (str): Accept header value passed to _build_provider_result.
    attempt (int): Current retry attempt (0-based).
    uint8array_cls (type): JS Uint8Array class for ArrayBuffer conversion.

    Returns:
    tuple[list[_PendingFetch], list[ProviderResult]]: Items to re-fetch
        and finalised ProviderResult objects.
    """
    retryable: list[_PendingFetch] = []
    done: list[ProviderResult] = []

    for item, body in zip(succeeded, bodies, strict=True):
        if isinstance(body, BaseException):
            logger.error(
                "send_doh_requests body read failed for %s: %s",
                item.provider.get("url", ""),
                body,
            )

            done.append(_failed_result(item.provider, item.main, body))
            continue

        status = item.response.status

        if status in _RETRY_STATUS_CODES and attempt < config.RETRY_MAX_ATTEMPTS:
            retryable.append(item)
            continue

        try:
            resp_body = (
                str(body) if is_json else bytes(uint8array_cls.new(body).to_py())
            )

            result = _build_provider_result(
                resp_body,
                item.response.ok,
                status,
                item.provider,
                item.main,
                accept,
            )

            result.retry_count = attempt
        except Exception as e:
            logger.error(
                "send_doh_requests processing failed for %s: %s: %s",
                item.provider.get("url", ""),
                type(e).__name__,
                e,
            )

            result = _failed_result(item.provider, item.main, e)

        done.append(result)

    return retryable, done


async def send_doh_requests_fanout(
    doh_providers: list,
    method: str,
    accept: str,
    body_bytes: bytes | None = None,
    query: str = "",
) -> list:
    """Fan out DNS queries to multiple providers and collect results.

    Uses two asyncio.gather calls per attempt (fetch, then body read)
    to minimise Python-JS await crossings.

    Parameters:
    doh_providers (list): Provider config dicts, each with url, etc.
    method (str): HTTP method ("GET" or "POST").
    accept (str): Accept header value.
    body_bytes (bytes | None): DNS wire-format body for POST requests.
    query (str): Query string for GET JSON requests.

    Returns:
    list[ProviderResult]: One result per queried provider.
    """
    import asyncio

    # Deferred imports: only available in the Pyodide runtime.
    from js import AbortSignal, Object, Uint8Array
    from js import fetch as js_fetch
    from pyodide.ffi import to_js

    if not doh_providers:
        return []

    abort_signal = AbortSignal.timeout(config.TIMEOUT_MS)
    is_json = accept == "application/dns-json"
    is_json_query = is_json and body_bytes is None

    pending: list[_PendingFetch] = []
    for provider in doh_providers:
        if is_json_query and not provider.get("dns_json", False):
            continue

        pending.append(
            _PendingFetch(
                provider=provider,
                main=provider.get("main", False),
                request=_build_provider_fetch_request(
                    provider,
                    method,
                    accept,
                    abort_signal,
                    body_bytes,
                    query,
                ),
            ),
        )

    if not pending:
        return []

    done: list[ProviderResult] = []

    for attempt in range(1 + config.RETRY_MAX_ATTEMPTS):
        fetch_requests = [
            js_fetch(
                item.request.url,
                to_js(item.request.options, dict_converter=Object.fromEntries),
            )
            for item in pending
        ]

        responses = await asyncio.gather(*fetch_requests, return_exceptions=True)

        succeeded, fetch_failures = _partition_fetch_responses(pending, responses)
        done.extend(fetch_failures)

        if succeeded:
            bodies = await asyncio.gather(
                *[
                    item.response.text() if is_json else item.response.arrayBuffer()
                    for item in succeeded
                ],
                return_exceptions=True,
            )
        else:
            bodies = []

        pending, body_results = _process_bodies(
            succeeded,
            bodies,
            is_json,
            accept,
            attempt,
            Uint8Array,
        )

        done.extend(body_results)

        if not pending:
            break

    for item in pending:
        result = _failed_result(
            item.provider,
            item.main,
            Exception("retries exhausted"),
        )

        result.retry_count = config.RETRY_MAX_ATTEMPTS
        done.append(result)

    return done
