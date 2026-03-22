# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""DNS wire-format helpers, ECS truncation, and upstream provider fan-out."""

import base64
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import logging
import re
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

_ECS_TRUNCATION: dict = getattr(config, "ECS_TRUNCATION", {"enabled": False})
_REBIND_PROTECTION: bool = getattr(config, "REBIND_PROTECTION", True)
_TIMEOUT_MS: int = getattr(config, "TIMEOUT_MS", 5000)
_RETRY_MAX_ATTEMPTS: int = getattr(config, "RETRY_MAX_ATTEMPTS", 2)


SUPPORTED_ACCEPT_HEADERS = frozenset(
    {"application/dns-json", "application/dns-message"},
)


def _bloom_hash(domain: str) -> int:
    """Hash function shared by build (rbloom) and worker (_bloom_contains). Must stay in sync."""
    return int.from_bytes(
        hashlib.blake2b(domain.encode(), digest_size=16).digest(),
        "big",
        signed=True,
    )


def _bloom_contains(
    bit_array: bytes | bytearray | memoryview,
    num_bits: int,
    num_hashes: int,
    hash_value: int,
) -> bool:
    """Return True if domain is (possibly) in the bloom filter bit array."""
    lcg_mul = 47026247687942121848144207491837418733
    lcg_mask = (1 << 128) - 1
    state: int = hash_value
    for _ in range(num_hashes):
        state = (state * lcg_mul + 1) & lcg_mask
        bit: int = ((state >> 32) & 0xFFFFFFFFFFFFFFFF) % num_bits
        byte_index: int = bit >> 3
        if not (bit_array[byte_index] >> (bit & 7)) & 1:
            return False
    return True


def _build_servfail_wire() -> bytes:
    """
    Build a pre-computed SERVFAIL wire response for error fallback.

    Returns:
    bytes: SERVFAIL DNS wire-format response.
    """
    msg: dns.message.Message = dns.message.Message(id=0)
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
    """
    Return True if addr belongs to a private or reserved network.

    Parameters:
    addr (str): IP address to check.

    Returns:
    bool: True if private/reserved, False otherwise.
    """
    try:
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(addr)
        return any(ip in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def has_private_answers(addresses: list[str]) -> bool:
    """
    Return True if any address in the list is a private IP.

    Parameters:
    addresses (list[str]): List of IP addresses.

    Returns:
    bool: True if any address is private.
    """
    return any(_is_private_ip(addr) for addr in addresses)


def truncate_ecs(
    data: bytes,
    *,
    msg: dns.message.Message | None = None,
) -> tuple[bytes, str]:
    """
    Truncate ECS prefix lengths in a DNS wire message.

    Parameters:
    data (bytes): DNS wire-format message.
    msg (dns.message.Message | None): Parsed DNS message (optional).

    Returns:
    tuple[bytes, str]: (truncated wire, description string)
    """
    if not (_ECS_TRUNCATION and _ECS_TRUNCATION.get("enabled")):
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

    ipv4_prefix: int = _ECS_TRUNCATION.get("ipv4_prefix", 24)
    ipv6_prefix: int = _ECS_TRUNCATION.get("ipv6_prefix", 56)

    new_options: list = []
    descriptions: list[str] = []
    changed: bool = False

    for opt in msg.options:
        if isinstance(opt, dns.edns.ECSOption):
            target: int = ipv4_prefix if opt.family == 1 else ipv6_prefix

            if opt.srclen > target:
                truncated_opt: dns.edns.ECSOption = dns.edns.ECSOption(
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
    """
    Extract the first question from a parsed DNS message.

    Parameters:
    packet (dns.message.Message): Parsed DNS message.

    Returns:
    Question: DNS question tuple.
    """
    question: object = packet.question[0]
    return Question(
        name=str(question.name).rstrip("."),
        type=dns.rdatatype.to_text(question.rdtype),
    )


def parse_dns_wire_request(data: bytes) -> DnsParseResult:
    """
    Decode, ECS-truncate, and parse a DNS wire message in one step.

    Parameters:
    data (bytes): DNS wire-format message.

    Returns:
    DnsParseResult: Parsed DNS request result.
    """
    packet: dns.message.Message = dns.message.from_wire(data)
    question: Question = _extract_question(packet)
    truncated, ecs_desc = truncate_ecs(data, msg=packet)
    return DnsParseResult(question, truncated, ecs_desc, data, packet)


def compile_domain_set(domains: list) -> tuple[frozenset, tuple]:
    """
    Split a domain set into (exact_set, suffix_tuple) for fast matching.

    Parameters:
    domains (list): List of domain strings.

    Returns:
    tuple[frozenset, tuple]: (exact matches, suffix matches)
    """
    exact_domains: set[str] = set()
    wildcard_suffixes: list[str] = []
    for domain in domains:
        if domain.startswith("*."):
            wildcard_suffixes.append("." + domain[2:])
        else:
            exact_domains.add(domain)
    return frozenset(exact_domains), tuple(wildcard_suffixes)


def domain_matches(name: str, compiled: tuple[frozenset, tuple]) -> bool:
    """
    Check if a domain matches a pre-compiled (exact, suffixes) pair.

    Parameters:
    name (str): Domain name to check.
    compiled (tuple[frozenset, tuple]): Compiled domain set.

    Returns:
    bool: True if match found.
    """
    exact_domains, wildcard_suffixes = compiled
    normalized_name: str = name.rstrip(".").lower()
    if normalized_name in exact_domains:
        return True

    return any(normalized_name.endswith(suffix) for suffix in wildcard_suffixes)


_COMMENT_RE = re.compile(r"\s*#.*$")

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPV6_RE = re.compile(r"^[\[\]0-9a-fA-F:]+:[0-9a-fA-F:]*$")


def _is_ip(token: str) -> bool:
    """Return True if token looks like an IPv4 or IPv6 address."""
    return bool(_IPV4_RE.match(token) or _IPV6_RE.match(token))


def parse_blocklist_text(text: str) -> set[str]:
    """
    Parse a community block list in hosts-file or plain domain-per-line format.

    Handles hosts-file lines with IPv4 or IPv6 addresses followed by one or
    more domains (e.g. "0.0.0.0 a.example b.example" or "::1 example.com")
    and plain domain-per-line format. Comments (#) and blank lines are ignored.

    Parameters:
    text (str): Raw text content fetched from a block list URL.

    Returns:
    set[str]: Exact domain names.
    """
    exact: set[str] = set()

    for raw_line in text.splitlines():
        stripped: str = _COMMENT_RE.sub("", raw_line).strip()
        if not stripped:
            continue

        tokens: list[str] = stripped.split()
        if len(tokens) >= 2 and _is_ip(tokens[0]):
            for token in tokens[1:]:
                domain: str = token.lower().rstrip(".")
                if "." in domain:
                    exact.add(domain)

            continue

        domain = stripped.lower().rstrip(".")
        if "." in domain and " " not in domain:
            exact.add(domain)

    return exact


def make_blocked_response(
    question: Question,
    accept: str,
    request_wire: bytes | None = None,
    parsed_request: dns.message.Message | None = None,
) -> tuple:
    """
    Build a synthetic NXDOMAIN DNS response for a blocked domain.

    Parameters:
    question (Question): DNS question tuple.
    accept (str): Accept header value.
    request_wire (bytes | None): Original DNS wire message (optional).
    parsed_request (dns.message.Message | None): Parsed DNS message (optional).

    Returns:
    tuple: (response body, content type)
    """
    try:
        rdtype: int = dns.rdatatype.from_text(question.type or "A")
    except (dns.exception.SyntaxError, ValueError):
        rdtype = dns.rdatatype.A

    try:
        qname: dns.name.Name = dns.name.from_text(question.name or ".")
    except (
        dns.exception.SyntaxError,
        dns.name.LabelTooLong,
        dns.name.EmptyLabel,
        ValueError,
    ):
        qname = dns.name.from_text(".")

    if "dns-json" in accept:
        body: str = json.dumps(
            {
                "Status": 3,
                "Question": [{"name": question.name or ".", "type": int(rdtype)}],
                "Answer": [],
            },
        )

        return body, "application/dns-json"

    if parsed_request is not None:
        req: dns.message.Message = parsed_request
    elif request_wire is not None:
        try:
            req = dns.message.from_wire(request_wire)
        except Exception:
            req = dns.message.make_query(qname, rdtype)
    else:
        req = dns.message.make_query(qname, rdtype)

    try:
        resp: dns.message.Message = dns.message.make_response(req)
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
    """
    Set blocked/possibly_blocked/rebind directly on result.

    Parameters:
    result (ProviderResult): Provider result object.
    status (int): DNS status code.
    addresses (list[str]): List of IP addresses.

    Returns:
    None
    """
    blocked: bool = any(addr in _BLOCKED_ADDRS for addr in addresses)
    result.blocked = blocked
    result.possibly_blocked = status == dns.rcode.NXDOMAIN
    if _REBIND_PROTECTION and not blocked:
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
    """
    Build a URL, headers, and fetch options for an upstream DoH provider.

    Parameters:
    provider (dict): Provider config dict.
    method (str): HTTP method.
    accept (str): Accept header value.
    abort_signal (object): Abort signal object.
    body_bytes (bytes | None): DNS wire-format body (optional).
    query (str): Query string (optional).

    Returns:
    _ProviderFetchRequest: Fetch request tuple.
    """
    target_url: str = provider["url"]

    if method == "GET" and body_bytes is not None:
        encoded: str = base64.urlsafe_b64encode(body_bytes).rstrip(b"=").decode("ascii")
        target_url += "?dns=" + encoded
    elif method == "GET" and query:
        target_url += query

    headers: dict[str, str] = {}

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
    """
    Return the provider_id from config, falling back to url.

    Parameters:
    provider (dict): Provider config dict.

    Returns:
    str: Provider ID.
    """
    return provider.get("provider_id") or provider["url"]


def _failed_result(
    provider: dict,
    main: bool,
    exception: BaseException,
) -> ProviderResult:
    """
    Build a ProviderResult representing a failed upstream fetch.

    Parameters:
    provider (dict): Provider config dict.
    main (bool): Is main provider.
    exception (BaseException): The exception that caused the failure.

    Returns:
    ProviderResult: Failed provider result.
    """
    exc_str: str = f"{type(exception).__name__} {exception}".lower()
    timed_out: bool = "timeout" in exc_str or "abort" in exc_str

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
    response_ok: bool,
    status: int,
    provider: dict,
    main: bool,
    accept: str,
) -> ProviderResult:
    """
    Build a ProviderResult from pre-read response data.

    Parameters:
    resp_body (bytes | str): Response body.
    response_ok (bool): Whether the HTTP response indicated success.
    status (int): HTTP status code.
    provider (dict): Provider config dict.
    main (bool): Is main provider.
    accept (str): Accept header value.

    Returns:
    ProviderResult: Provider result object.
    """
    is_json: bool = accept == "application/dns-json"

    result: ProviderResult = ProviderResult(
        url=provider["url"],
        provider_id=_get_provider_id(provider),
        response_status=status,
        response_content_type=accept,
        response_body=resp_body,
        main=main,
        failed=not response_ok,
    )

    if not response_ok:
        return result

    if is_json:
        try:
            resp_json: dict = json.loads(resp_body)
            answers: list = resp_json.get("Answer", [])
            addresses: list[str] = [a.get("data", "") for a in answers if a.get("data")]
            _classify_answers(
                result=result,
                status=resp_json.get("Status", 0),
                addresses=addresses,
            )

            ttls: list[int] = [a["TTL"] for a in answers if "TTL" in a]
            result.min_ttl = min(ttls) if ttls else None
        except Exception:
            logger.debug(
                "Failed to parse JSON DNS response from %s",
                provider["url"],
                exc_info=True,
            )
    else:
        try:
            packet: dns.message.Message = dns.message.from_wire(resp_body)

            addresses: list[str] = [
                str(rr)
                for rrset in packet.answer
                for rr in rrset
                if rr.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA)
            ]
            _classify_answers(
                result=result,
                status=int(packet.rcode()),
                addresses=addresses,
            )

            ttls: list[int] = [rrset.ttl for rrset in packet.answer]
            result.min_ttl = min(ttls) if ttls else None
        except Exception:
            logger.debug(
                "Failed to parse binary DNS response from %s",
                provider["url"],
                exc_info=True,
            )

    return result


def get_response_min_ttl(result: ProviderResult) -> int | None:
    """
    Return the minimum TTL from the provider result, or None.

    Parameters:
    result (ProviderResult): Provider result object.

    Returns:
    int | None: Minimum TTL or None.
    """
    return result.min_ttl


class _FetchItem(NamedTuple):
    """
    Provider context for the fetch retry loop.

    Attributes:
    provider (dict): Provider config dict.
    main (bool): Is main provider.
    request (_ProviderFetchRequest): Fetch request tuple.
    """

    provider: dict
    main: bool
    request: _ProviderFetchRequest


async def send_doh_requests_fanout(
    doh_providers: list,
    method: str,
    accept: str,
    body_bytes: bytes | None = None,
    query: str = "",
    safety_timeout_ms: int = 0,
) -> list:
    """
    Fan out DNS queries to multiple providers and collect results.

    Uses asyncio.gather with workers.fetch for concurrent upstream requests.

    Parameters:
    doh_providers (list): Provider config dicts, each with url, etc.
    method (str): HTTP method ("GET" or "POST").
    accept (str): Accept header value.
    body_bytes (bytes | None): DNS wire-format body for POST requests.
    query (str): Query string for GET JSON requests.
    safety_timeout_ms (int): Overall safety timeout in milliseconds.
        When positive, all fetches use this as their AbortSignal timeout
        instead of _TIMEOUT_MS, enforcing a hard deadline across
        the entire fanout including retries.

    Returns:
    list[ProviderResult]: One result per queried provider.
    """
    import asyncio

    # Deferred imports: only available in the Pyodide/Workers runtime.
    from js import AbortSignal
    from workers import fetch as workers_fetch

    if not doh_providers:
        return []

    timeout_ms: int = safety_timeout_ms if safety_timeout_ms > 0 else _TIMEOUT_MS
    abort_signal: object = AbortSignal.timeout(timeout_ms)
    is_json: bool = accept == "application/dns-json"
    is_json_query: bool = is_json and body_bytes is None

    pending: list[_FetchItem] = []

    for provider in doh_providers:
        if is_json_query and not provider.get("dns_json", False):
            continue

        pending.append(
            _FetchItem(
                provider=provider,
                main=provider.get("main", False),
                request=_build_provider_fetch_request(
                    provider=provider,
                    method=method,
                    accept=accept,
                    abort_signal=abort_signal,
                    body_bytes=body_bytes,
                    query=query,
                ),
            ),
        )

    if not pending:
        return []

    done: list[ProviderResult] = []

    for attempt in range(1 + _RETRY_MAX_ATTEMPTS):
        responses: list = await asyncio.gather(
            *[
                workers_fetch(item.request.url, **item.request.options)
                for item in pending
            ],
            return_exceptions=True,
        )

        next_pending: list[_FetchItem] = []

        for item, resp in zip(pending, responses, strict=True):
            if isinstance(resp, BaseException):
                logger.error(
                    "send_doh_requests fetch rejected for %s: %s",
                    item.provider.get("url", ""),
                    resp,
                )

                done.append(
                    _failed_result(
                        provider=item.provider,
                        main=item.main,
                        exception=resp,
                    ),
                )
                continue

            status: int = resp.status

            if status in _RETRY_STATUS_CODES and attempt < _RETRY_MAX_ATTEMPTS:
                next_pending.append(item)
                continue

            try:
                resp_body: str | bytes
                if is_json:
                    resp_body = await resp.text()
                else:
                    resp_body = await resp.bytes()

                result: ProviderResult = _build_provider_result(
                    resp_body=resp_body,
                    response_ok=resp.ok,
                    status=status,
                    provider=item.provider,
                    main=item.main,
                    accept=accept,
                )

                result.retry_count = attempt
            except Exception as e:
                logger.error(
                    "send_doh_requests processing failed for %s: %s: %s",
                    item.provider.get("url", ""),
                    type(e).__name__,
                    e,
                )

                result = _failed_result(
                    provider=item.provider,
                    main=item.main,
                    exception=e,
                )

            done.append(result)

        pending = next_pending

        if not pending:
            break

    for item in pending:
        result = _failed_result(
            provider=item.provider,
            main=item.main,
            exception=Exception("retries exhausted"),
        )

        result.retry_count = _RETRY_MAX_ATTEMPTS
        done.append(result)

    return done
