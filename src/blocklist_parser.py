# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Blocklist text parsing for community block list formats."""

import re

_COMMENT_RE = re.compile(r"\s*[#!].*$")

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPV6_RE = re.compile(r"^[\[\]0-9a-fA-F:]+:[0-9a-fA-F:]*$")
_ADBLOCK_RE = re.compile(r"^\|\|(.+)\^(\$[^\s]*)?$")
_DNSMASQ_RE = re.compile(r"^(?:local|address|server)=/([^/]+)/$")
_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$",
)


def _is_ip(token: str) -> bool:
    """Return True if token looks like an IPv4 or IPv6 address."""
    return bool(_IPV4_RE.match(token) or _IPV6_RE.match(token))


def _normalize_domain(raw: str) -> str | None:
    """Lowercase, strip trailing dot, validate as domain.

    Returns None for wildcards since the filter only does exact matching
    and wildcard entries would silently fail to match any queries.
    """
    domain: str = raw.lower().rstrip(".")
    if domain.startswith("*."):
        return None
    if _DOMAIN_RE.match(domain):
        return domain
    return None


def parse_blocklist_text(text: str) -> set[str]:
    """
    Parse a community block list into a set of domain names.

    Supported formats:
    - Plain domain per line: "domain.example.com"
    - Hosts file: "0.0.0.0 domain" or "127.0.0.1 domain1 domain2"
    - Hosts compressed: "0.0.0.0 domain1 domain2 domain3 ..."
    - Adblock: "||domain^" or "||domain^$option"
    - DNSMasq: "local=/domain/" or "address=/domain/" or "server=/domain/"

    Wildcard entries (*.domain) are rejected since the filter only does
    exact matching and wildcards would silently fail to match any queries.
    Lines starting with # or ! are treated as comments.
    Adblock metadata lines (e.g. "[Adblock Plus]") are skipped.

    Parameters:
    text (str): Raw text content fetched from a block list URL.

    Returns:
    set[str]: Exact domain names.
    """
    exact: set[str] = set()

    for raw_line in text.splitlines():
        stripped: str = _COMMENT_RE.sub("", raw_line).strip()
        if not stripped or stripped.startswith("[") or stripped.startswith("$"):
            continue

        adblock_match = _ADBLOCK_RE.match(stripped)
        if adblock_match:
            domain: str | None = _normalize_domain(adblock_match.group(1))
            if domain:
                exact.add(domain)
            continue

        dnsmasq_match = _DNSMASQ_RE.match(stripped)
        if dnsmasq_match:
            domain = _normalize_domain(dnsmasq_match.group(1))
            if domain:
                exact.add(domain)
            continue

        tokens: list[str] = stripped.split()
        if len(tokens) >= 2 and _is_ip(tokens[0]):
            for token in tokens[1:]:
                domain = _normalize_domain(token)
                if domain:
                    exact.add(domain)
            continue

        if " " not in stripped:
            domain = _normalize_domain(stripped)
            if domain:
                exact.add(domain)

    return exact
