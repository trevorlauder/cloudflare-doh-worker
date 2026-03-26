# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Tests for the DoH worker endpoints."""

import base64
import json
import os
from pathlib import Path
import random
import string
import time
import tomllib
import urllib.error
from urllib.parse import urlparse
import urllib.request

from conftest import BASE_URL, IS_HTTPS, IS_LOCAL, SKIP_TLS, resolve_env
from curl_cffi import requests as cffi_requests
from curl_cffi.const import CurlHttpVersion
import dns.edns
import dns.message
import dns.rcode
import dns.rdatatype
import pytest

import config as _config

ALLOWED_DOMAINS: list = getattr(_config, "ALLOWED_DOMAINS", [])
BLOCKED_DOMAINS: list = getattr(_config, "BLOCKED_DOMAINS", [])
BYPASS_PROVIDER: dict = getattr(
    _config,
    "BYPASS_PROVIDER",
    {
        "url": "https://cloudflare-dns.com/dns-query",
        "dns_json": True,
    },
)
ENDPOINTS: dict = getattr(_config, "ENDPOINTS", {})
DEBUG: bool = getattr(_config, "DEBUG", False)
CACHE_DNS: bool = getattr(_config, "CACHE_DNS", True)
REBIND_PROTECTION: bool = getattr(_config, "REBIND_PROTECTION", True)
ECS_TRUNCATION: dict = getattr(_config, "ECS_TRUNCATION", {"enabled": False})

_provider_urls = (
    cfg.get("main_provider", {}).get("url", "") for cfg in ENDPOINTS.values()
)

MOCK_DOH_ENABLED = any("mock-doh" in url for url in _provider_urls)

_ENDPOINT_PREFIX = resolve_env(
    getattr(_config, "PATH_PREFIX", "/"),
).rstrip("/")

TEST_ENDPOINTS = [_ENDPOINT_PREFIX + resolve_env(e) for e in ENDPOINTS]
HEALTH_ENDPOINT = f"{_ENDPOINT_PREFIX}/health"
CONFIG_ENDPOINT = f"{_ENDPOINT_PREFIX}/config"

ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")

_ECS_ENABLED = bool(ECS_TRUNCATION and ECS_TRUNCATION.get("enabled"))
_ECS_IPV4_PREFIX = ECS_TRUNCATION.get("ipv4_prefix", 24) if ECS_TRUNCATION else 24
_ECS_IPV6_PREFIX = ECS_TRUNCATION.get("ipv6_prefix", 56) if ECS_TRUNCATION else 56

_pyproject = tomllib.loads(
    (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(),
)

DEFAULT_HEADERS = {
    "User-Agent": f"doh-test/{_pyproject['project']['version']}",
}

TIMEOUT = 10

MOCK_DOH_URL = f"https://{urlparse(BASE_URL).netloc}/mock-doh"

_HEADER_CACHE = "cloudflare-doh-worker-cache"


def _assert_worker_headers(headers: object) -> None:
    """Check debug headers are present."""
    if not DEBUG:
        return

    assert headers.get("cloudflare-doh-worker-response-from"), (
        "missing CLOUDFLARE-DOH-WORKER-RESPONSE-FROM header"
    )

    assert headers.get("cloudflare-doh-worker-response-codes"), (
        "missing CLOUDFLARE-DOH-WORKER-RESPONSE-CODES header"
    )

    assert (
        headers.get("cloudflare-doh-worker-possibly-blocked-providers") is not None
    ), "missing CLOUDFLARE-DOH-WORKER-POSSIBLY-BLOCKED-PROVIDERS header"

    assert headers.get("cloudflare-doh-worker-blocked-providers") is not None, (
        "missing CLOUDFLARE-DOH-WORKER-BLOCKED-PROVIDERS header"
    )

    assert headers.get("cloudflare-doh-worker-timed-out-providers") is not None, (
        "missing CLOUDFLARE-DOH-WORKER-TIMED-OUT-PROVIDERS header"
    )

    assert (
        headers.get("cloudflare-doh-worker-connection-error-providers") is not None
    ), "missing CLOUDFLARE-DOH-WORKER-CONNECTION-ERROR-PROVIDERS header"


def _build_dns_wire(name: str, rdtype: int = dns.rdatatype.A) -> bytes:
    return dns.message.make_query(name, rdtype).to_wire()


def _build_dns_wire_with_ecs(
    name: str,
    address: str = "203.0.113.1",
    srclen: int = 32,
) -> bytes:
    msg = dns.message.make_query(name, dns.rdatatype.A, use_edns=True)
    ecs = dns.edns.ECSOption(address, srclen=srclen, scopelen=0)
    msg.use_edns(edns=0, options=[ecs])
    return msg.to_wire()


def _first_domain(domains: object) -> str:
    return next(iter(domains)).lstrip("*").lstrip(".")


def _assert_cache_control(headers: object) -> None:
    """Check Cache-Control: max-age=N with a positive TTL."""
    cache_control = headers.get("cache-control", "")
    assert cache_control.startswith("max-age="), (
        f"expected Cache-Control: max-age=N, got {cache_control!r}"
    )
    ttl = int(cache_control.split("=", 1)[1])
    assert ttl > 0, f"expected positive TTL in Cache-Control, got {ttl}"


def _post_wire(wire: bytes, endpoint: str | None = None) -> tuple:
    ep = endpoint or TEST_ENDPOINTS[0]
    with urllib.request.urlopen(
        _request(
            f"{BASE_URL}{ep}",
            method="POST",
            headers={
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
            },
            data=wire,
        ),
        timeout=TIMEOUT,
    ) as resp:
        return resp.status, resp.headers, resp.read()


def _get_wire(wire: bytes, endpoint: str | None = None) -> tuple:
    ep = endpoint or TEST_ENDPOINTS[0]
    encoded = base64.urlsafe_b64encode(wire).rstrip(b"=").decode()
    with urllib.request.urlopen(
        _request(
            f"{BASE_URL}{ep}?dns={encoded}",
            headers={"Accept": "application/dns-message"},
        ),
        timeout=TIMEOUT,
    ) as resp:
        return resp.status, resp.headers, resp.read()


def _get_json(name: str, type: str = "A", endpoint: str | None = None) -> tuple:
    ep = endpoint or TEST_ENDPOINTS[0]
    with urllib.request.urlopen(
        _request(
            f"{BASE_URL}{ep}?name={name}&type={type}",
            headers={"Accept": "application/dns-json"},
        ),
        timeout=TIMEOUT,
    ) as resp:
        return resp.status, resp.headers, json.loads(resp.read())


def _request(
    url: str,
    *,
    method: str = "GET",
    headers: dict | None = None,
    data: bytes | None = None,
) -> urllib.request.Request:
    return urllib.request.Request(
        url,
        data=data,
        headers={**DEFAULT_HEADERS, **(headers or {})},
        method=method,
    )


def test_unknown_path_returns_403_or_404():
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(
            _request(f"{BASE_URL}/doh/does/not/exist"),
            timeout=TIMEOUT,
        )

    assert e.value.code in (403, 404)


def test_bad_accept_returns_406():
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(
            _request(
                f"{BASE_URL}{TEST_ENDPOINTS[0]}?name=example.com",
                headers={"Accept": "text/html"},
            ),
            timeout=TIMEOUT,
        )

    assert e.value.code == 406


def test_missing_param_returns_400():
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(
            _request(
                f"{BASE_URL}{TEST_ENDPOINTS[0]}",
                headers={"Accept": "application/dns-json"},
            ),
            timeout=TIMEOUT,
        )

    assert e.value.code == 400


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
def test_unsupported_method_returns_405(method: str):
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(
            _request(
                f"{BASE_URL}{TEST_ENDPOINTS[0]}",
                method=method,
                headers={"Accept": "application/dns-json"},
            ),
            timeout=TIMEOUT,
        )

    assert e.value.code == 405


@pytest.mark.skipif(not IS_HTTPS, reason="Requires HTTPS stack")
@pytest.mark.skipif(
    MOCK_DOH_ENABLED,
    reason="mock-doh provider does not support DNS-JSON",
)
def test_http3_alt_svc_advertised():
    with urllib.request.urlopen(
        _request(
            f"{BASE_URL}{TEST_ENDPOINTS[0]}?name=mozilla.org&type=A",
            headers={"Accept": "application/dns-json"},
        ),
        timeout=TIMEOUT,
    ) as resp:
        alt_svc = resp.headers.get("alt-svc", "")
        assert "h3" in alt_svc, f"alt-svc header missing h3: {alt_svc!r}"
        _assert_worker_headers(resp.headers)


@pytest.mark.skipif(
    not IS_HTTPS or IS_LOCAL,
    reason="HTTP/3 requires nginx HTTPS stack, skipped for localhost",
)
@pytest.mark.skipif(
    MOCK_DOH_ENABLED,
    reason="mock-doh provider does not support DNS-JSON",
)
def test_http3_udp():
    resp = cffi_requests.get(
        f"{BASE_URL}{TEST_ENDPOINTS[0]}?name=apple.com&type=A",
        http_version=CurlHttpVersion.V3ONLY,
        headers={"Accept": "application/dns-json", **DEFAULT_HEADERS},
        timeout=TIMEOUT,
        verify=not SKIP_TLS,
    )

    assert resp.status_code == 200, f"HTTP/3 returned {resp.status_code}"
    _assert_worker_headers(resp.headers)


@pytest.mark.skipif(
    MOCK_DOH_ENABLED,
    reason="mock-doh provider does not support DNS-JSON",
)
@pytest.mark.parametrize("endpoint", TEST_ENDPOINTS)
def test_get_dns_json_name(endpoint: str):
    status, headers, data = _get_json("nextdns.io", "A", endpoint)
    assert status == 200
    content_type = headers.get("content-type", "")
    assert "dns-json" in content_type or "json" in content_type, (
        f"unexpected content-type: {content_type}"
    )
    assert "Status" in data, "JSON response missing 'Status' key"
    _assert_worker_headers(headers)


@pytest.mark.parametrize("endpoint", TEST_ENDPOINTS)
def test_get_dns_wire_param(endpoint: str):
    wire = _build_dns_wire("google.com")
    status, headers, body = _get_wire(wire, endpoint)
    assert status == 200
    content_type = headers.get("content-type", "")
    assert "dns-message" in content_type, f"unexpected content-type: {content_type}"
    assert body[:2] == wire[:2], "transaction ID mismatch in response"
    _assert_worker_headers(headers)


@pytest.mark.parametrize("endpoint", TEST_ENDPOINTS)
def test_post_dns_wire(endpoint: str):
    wire = _build_dns_wire("cloudflare.com")
    status, headers, body = _post_wire(wire, endpoint)
    assert status == 200
    content_type = headers.get("content-type", "")
    assert "dns-message" in content_type, f"unexpected content-type: {content_type}"
    assert body[:2] == wire[:2], "transaction ID mismatch in response"
    _assert_worker_headers(headers)


@pytest.mark.skipif(not BLOCKED_DOMAINS, reason="BLOCKED_DOMAINS is empty in config")
def test_config_blocked_domain_returns_nxdomain():
    domain = _first_domain(BLOCKED_DOMAINS)
    status, headers, body = _post_wire(_build_dns_wire(domain))
    assert status == 200
    msg = dns.message.from_wire(body)
    assert msg.rcode() == dns.rcode.NXDOMAIN, (
        f"expected NXDOMAIN, got {dns.rcode.to_text(msg.rcode())}"
    )

    if DEBUG:
        response_from = headers.get("cloudflare-doh-worker-response-from", "")
        assert response_from == "config", (
            f"expected response-from 'config', got {response_from!r}"
        )

        config_blocked = headers.get("cloudflare-doh-worker-config-blocked", "")
        assert config_blocked == "1", (
            f"expected CLOUDFLARE-DOH-WORKER-CONFIG-BLOCKED to be '1', got {config_blocked!r}"
        )


@pytest.mark.skipif(not ALLOWED_DOMAINS, reason="ALLOWED_DOMAINS is empty in config")
def test_allowed_domain_uses_bypass_provider():
    status, headers, _ = _get_json(_first_domain(ALLOWED_DOMAINS), "A")
    assert status == 200

    assert headers.get("cloudflare-doh-worker-config-allowed") == "1", (
        "missing CLOUDFLARE-DOH-WORKER-CONFIG-ALLOWED header"
    )

    if DEBUG:
        response_from = headers.get("cloudflare-doh-worker-response-from", "")
        assert BYPASS_PROVIDER["url"] in response_from, (
            f"expected bypass provider {BYPASS_PROVIDER['url']!r} in response-from, got {response_from!r}"
        )
        _assert_worker_headers(headers)


@pytest.mark.skipif(
    MOCK_DOH_ENABLED,
    reason="mock-doh provider does not implement DNS filtering",
)
def test_provider_blocks_known_malware_domain():
    domain = "malware.testcategory.com"
    _, headers, data = _get_json(domain, "A")
    dns_status = data.get("Status", 0)
    answers = data.get("Answer", [])
    blocked_ips = {"0.0.0.0", "::"}
    is_nxdomain = dns_status == 3
    is_blocked_ip = any(a.get("data") in blocked_ips for a in answers)

    assert is_nxdomain or is_blocked_ip, (
        f"expected {domain!r} to resolve to NXDOMAIN or a blocked IP, got Status={dns_status}, Answer={answers}"
    )

    if DEBUG:
        blocked_by = headers.get("cloudflare-doh-worker-blocked-providers", "")

        possibly_blocked_by = headers.get(
            "cloudflare-doh-worker-possibly-blocked-providers",
            "",
        )

        assert blocked_by or possibly_blocked_by, (
            f"expected at least one provider to report blocking {domain!r}, "
            f"blocked-providers={blocked_by!r}, possibly-blocked-providers={possibly_blocked_by!r}"
        )


@pytest.mark.skipif(not CONFIG_ENDPOINT, reason="CONFIG_ENDPOINT is not set")
def test_config_without_token_returns_401():
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(
            _request(f"{BASE_URL}{CONFIG_ENDPOINT}"),
            timeout=TIMEOUT,
        )

    assert e.value.code in (401, 404), f"expected 401 or 404, got {e.value.code}"


@pytest.mark.skipif(not CONFIG_ENDPOINT, reason="CONFIG_ENDPOINT is not set")
@pytest.mark.skipif(not ADMIN_TOKEN, reason="ADMIN_TOKEN not set in environment")
def test_config_with_valid_token_returns_config():
    with urllib.request.urlopen(
        _request(
            f"{BASE_URL}{CONFIG_ENDPOINT}",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        ),
        timeout=TIMEOUT,
    ) as resp:
        assert resp.status == 200
        content_type = resp.headers.get("content-type", "")
        assert "json" in content_type, f"unexpected content-type: {content_type}"
        data = json.loads(resp.read())
        config_data = data["config"]
        assert "ENDPOINTS" in config_data, "config response missing 'ENDPOINTS' key"

        assert "BLOCKED_DOMAINS" in config_data, (
            "config response missing 'BLOCKED_DOMAINS' key"
        )

        assert "REBIND_PROTECTION" in config_data, (
            "config response missing 'REBIND_PROTECTION' key"
        )


@pytest.mark.skipif(not CONFIG_ENDPOINT, reason="CONFIG_ENDPOINT is not set")
def test_config_with_bad_token_returns_401():
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(
            _request(
                f"{BASE_URL}{CONFIG_ENDPOINT}",
                headers={"Authorization": "Bearer wrong-token-value"},
            ),
            timeout=TIMEOUT,
        )

    assert e.value.code in (401, 404), f"expected 401 or 404, got {e.value.code}"


@pytest.mark.skipif(not CONFIG_ENDPOINT, reason="CONFIG_ENDPOINT is not set")
@pytest.mark.skipif(bool(ADMIN_TOKEN), reason="ADMIN_TOKEN is set in environment")
def test_config_disabled_when_no_admin_token():
    for headers in ({}, {"Authorization": "Bearer any-value"}):
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(
                _request(f"{BASE_URL}{CONFIG_ENDPOINT}", headers=headers),
                timeout=TIMEOUT,
            )

        assert e.value.code == 404, f"expected 404, got {e.value.code}"


@pytest.mark.skipif(not HEALTH_ENDPOINT, reason="HEALTH_ENDPOINT is disabled")
def test_health_returns_ok():
    with urllib.request.urlopen(
        _request(f"{BASE_URL}{HEALTH_ENDPOINT}"),
        timeout=TIMEOUT,
    ) as resp:
        assert resp.status == 200
        body = json.loads(resp.read().decode())
        assert body["status"] == "ok"


@pytest.mark.skipif(
    MOCK_DOH_ENABLED,
    reason="mock-doh provider does not support DNS-JSON",
)
def test_cache_control_present_on_successful_dns_json():
    _, headers, _ = _get_json("google.com", "A")
    _assert_cache_control(headers)


def test_cache_control_present_on_successful_dns_wire():
    _, headers, _ = _post_wire(_build_dns_wire("google.com"))
    _assert_cache_control(headers)


@pytest.mark.skipif(not BLOCKED_DOMAINS, reason="BLOCKED_DOMAINS is empty in config")
def test_blocked_domain_returns_nxdomain_no_answer():
    status, _, body = _post_wire(_build_dns_wire(_first_domain(BLOCKED_DOMAINS)))
    assert status == 200
    msg = dns.message.from_wire(body)
    assert msg.rcode() == dns.rcode.NXDOMAIN, (
        f"expected NXDOMAIN, got {dns.rcode.to_text(msg.rcode())}"
    )
    assert len(msg.answer) == 0, (
        f"expected empty answer section for blocked domain, got {msg.answer!r}"
    )


@pytest.mark.skipif(not REBIND_PROTECTION, reason="REBIND_PROTECTION is disabled")
def test_rebind_protection_blocks_private_ip():
    domain = "doh-rebind-test.trevorlauder.dev"
    status, headers, data = _get_json(domain, "A")
    assert status == 200
    assert data["Status"] == 3, f"expected NXDOMAIN (Status 3), got {data['Status']}"
    if DEBUG:
        response_from = headers.get("cloudflare-doh-worker-response-from", "")
        assert response_from == "rebind-protection", (
            f"expected response-from 'rebind-protection', got {response_from!r}"
        )
    rebind_by = headers.get("cloudflare-doh-worker-rebind-protected", "")
    assert rebind_by == "1", (
        f"expected CLOUDFLARE-DOH-WORKER-REBIND-PROTECTED to be '1', got {rebind_by!r}"
    )


@pytest.mark.skipif(REBIND_PROTECTION, reason="REBIND_PROTECTION is enabled")
@pytest.mark.skipif(
    MOCK_DOH_ENABLED,
    reason="mock-doh provider does not support DNS-JSON",
)
def test_rebind_protection_disabled_allows_private_ip():
    domain = "doh-rebind-test.trevorlauder.dev"
    status, headers, data = _get_json(domain, "A")
    assert status == 200
    assert data["Status"] == 0, (
        f"expected NOERROR (Status 0) when rebind protection is off, got {data['Status']}"
    )
    if DEBUG:
        response_from = headers.get("cloudflare-doh-worker-response-from", "")
        assert response_from != "rebind-protection", (
            f"expected response NOT from rebind-protection, got {response_from!r}"
        )


@pytest.mark.skipif(not _ECS_ENABLED, reason="ECS_TRUNCATION is disabled")
def test_post_dns_wire_with_ecs():
    wire = _build_dns_wire_with_ecs(
        "trevorlauder.dev",
        address="203.0.113.1",
        srclen=32,
    )
    status, headers, _ = _post_wire(wire)
    assert status == 200
    ecs_truncated = headers.get("cloudflare-doh-worker-ecs-truncated", "")
    assert "203.0.113.1/32" in ecs_truncated, (
        f"expected original /32 prefix in ECS-TRUNCATED, got '{ecs_truncated}'"
    )
    assert f"/{_ECS_IPV4_PREFIX}" in ecs_truncated, (
        f"expected truncated /{_ECS_IPV4_PREFIX} prefix in ECS-TRUNCATED, got '{ecs_truncated}'"
    )


def test_post_dns_wire_with_ecs_no_truncation():
    wire = _build_dns_wire_with_ecs(
        "trevorlauder.dev",
        address="203.0.113.0",
        srclen=_ECS_IPV4_PREFIX,
    )
    status, headers, _ = _post_wire(wire)
    assert status == 200
    ecs_truncated = headers.get("cloudflare-doh-worker-ecs-truncated", "")
    assert not ecs_truncated, (
        f"expected ECS-TRUNCATED to be empty for /{_ECS_IPV4_PREFIX} prefix, got '{ecs_truncated}'"
    )


@pytest.mark.skipif(not _ECS_ENABLED, reason="ECS_TRUNCATION is disabled")
def test_get_dns_wire_with_ecs():
    wire = _build_dns_wire_with_ecs(
        "trevorlauder.dev",
        address="203.0.113.1",
        srclen=32,
    )
    status, headers, _ = _get_wire(wire)
    assert status == 200
    ecs_truncated = headers.get("cloudflare-doh-worker-ecs-truncated", "")
    assert "203.0.113.1/32" in ecs_truncated, (
        f"expected original /32 prefix in ECS-TRUNCATED for GET, got '{ecs_truncated}'"
    )
    assert f"/{_ECS_IPV4_PREFIX}" in ecs_truncated, (
        f"expected truncated /{_ECS_IPV4_PREFIX} prefix in ECS-TRUNCATED for GET, got '{ecs_truncated}'"
    )


def test_get_dns_wire_with_ecs_no_truncation():
    wire = _build_dns_wire_with_ecs(
        "trevorlauder.dev",
        address="203.0.113.0",
        srclen=_ECS_IPV4_PREFIX,
    )
    status, headers, _ = _get_wire(wire)
    assert status == 200
    ecs_truncated = headers.get("cloudflare-doh-worker-ecs-truncated", "")
    assert not ecs_truncated, (
        f"expected ECS-TRUNCATED to be empty for GET /{_ECS_IPV4_PREFIX} prefix, got '{ecs_truncated}'"
    )


@pytest.mark.skipif(not _ECS_ENABLED, reason="ECS_TRUNCATION is disabled")
def test_post_dns_wire_with_ipv6_ecs_truncated():
    wire = _build_dns_wire_with_ecs(
        "trevorlauder.dev",
        address="2001:db8::1",
        srclen=128,
    )
    status, headers, _ = _post_wire(wire)
    assert status == 200
    ecs_truncated = headers.get("cloudflare-doh-worker-ecs-truncated", "")
    assert "2001:db8::1/128" in ecs_truncated, (
        f"expected original /128 prefix in ECS-TRUNCATED, got '{ecs_truncated}'"
    )
    assert f"/{_ECS_IPV6_PREFIX}" in ecs_truncated, (
        f"expected truncated /{_ECS_IPV6_PREFIX} prefix in ECS-TRUNCATED, got '{ecs_truncated}'"
    )


def test_post_dns_wire_with_ipv6_ecs_no_truncation():
    wire = _build_dns_wire_with_ecs(
        "trevorlauder.dev",
        address="2001:db8::",
        srclen=_ECS_IPV6_PREFIX,
    )
    status, headers, _ = _post_wire(wire)
    assert status == 200
    ecs_truncated = headers.get("cloudflare-doh-worker-ecs-truncated", "")
    assert not ecs_truncated, (
        f"expected ECS-TRUNCATED to be empty for IPv6 /{_ECS_IPV6_PREFIX} prefix, got '{ecs_truncated}'"
    )


_BLOCKLIST_ENABLED = any(
    (Path(__file__).parent.parent / "blocklist").glob("shard_*.bin"),
)
_FP_CHECK_N = int(os.environ.get("FP_CHECK_PROBES", "100"))


@pytest.mark.skipif(not _BLOCKLIST_ENABLED, reason="no blocklist shards present")
def test_blocklist_domain_returns_nxdomain():
    status, headers, body = _post_wire(_build_dns_wire("analytics.archive.org"))
    assert status == 200
    msg = dns.message.from_wire(body)
    assert msg.rcode() == dns.rcode.NXDOMAIN, (
        f"expected NXDOMAIN for analytics.archive.org (blocklist), got {dns.rcode.to_text(msg.rcode())}"
    )
    if DEBUG:
        config_blocked = headers.get("cloudflare-doh-worker-config-blocked", "")
        assert config_blocked == "1", (
            f"expected CONFIG-BLOCKED to be '1', got {config_blocked!r}"
        )


@pytest.mark.skipif(not _BLOCKLIST_ENABLED, reason="no blocklist shards present")
@pytest.mark.skipif(
    not MOCK_DOH_ENABLED,
    reason="requires mock-doh upstream to guarantee NOERROR for absent domains",
)
def test_blocklist_false_positive_rate():
    """
    Query the worker with FP_CHECK_PROBES absent domains and assert none are falsely blocked.

    Uses deterministic {i}.fp-probe.invalid probe names matching the build script convention.
    The reserved .invalid TLD cannot appear in any real blocklist, and because mock-doh always
    returns NOERROR, any NXDOMAIN response can only come from the worker's blocklist filter.

    Set FP_CHECK_PROBES env var to override the default probe count (default: 1000).

    Returns:
    None
    """
    false_hits = []
    for i in range(_FP_CHECK_N):
        probe = f"{i}.fp-probe.invalid"
        _, _, body = _post_wire(_build_dns_wire(probe))
        if dns.message.from_wire(body).rcode() == dns.rcode.NXDOMAIN:
            false_hits.append(probe)

    rate = len(false_hits) / _FP_CHECK_N
    assert not false_hits, (
        f"Blocklist false-positive rate {rate:.2e} "
        f"({len(false_hits)} hits / {_FP_CHECK_N} probes): {false_hits[:5]!r}"
    )


@pytest.mark.skipif(_ECS_ENABLED, reason="ECS_TRUNCATION is enabled")
def test_ecs_disabled_no_truncation_header():
    wire = _build_dns_wire_with_ecs(
        "trevorlauder.dev",
        address="203.0.113.1",
        srclen=32,
    )
    status, headers, _ = _post_wire(wire)
    assert status == 200
    ecs_truncated = headers.get("cloudflare-doh-worker-ecs-truncated", "")
    assert not ecs_truncated, (
        f"expected no ECS-TRUNCATED header when truncation is disabled, got '{ecs_truncated}'"
    )


def test_post_empty_body_returns_400():
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(
            _request(
                f"{BASE_URL}{TEST_ENDPOINTS[0]}",
                method="POST",
                headers={
                    "Content-Type": "application/dns-message",
                    "Accept": "application/dns-message",
                },
                data=b"",
            ),
            timeout=TIMEOUT,
        )

    assert e.value.code == 400


def _assert_provider_stat_headers(headers: object) -> None:
    """Check provider stat headers on a successful response."""
    queried = headers.get("cloudflare-doh-worker-providers-queried", "")
    assert queried, (
        f"expected CLOUDFLARE-DOH-WORKER-PROVIDERS-QUERIED to be present, got {queried!r}"
    )
    assert int(queried) >= 1, (
        f"expected CLOUDFLARE-DOH-WORKER-PROVIDERS-QUERIED >= 1, got {queried!r}"
    )

    for name in (
        "cloudflare-doh-worker-providers-failed",
        "cloudflare-doh-worker-providers-timed-out",
        "cloudflare-doh-worker-providers-connection-error",
        "cloudflare-doh-worker-providers-failed-status-code",
        "cloudflare-doh-worker-providers-retried",
    ):
        val = headers.get(name)
        if val is not None:
            assert int(val) >= 1, (
                f"expected {name.upper()} > 0 when present, got {val!r}"
            )


@pytest.mark.skipif(
    MOCK_DOH_ENABLED,
    reason="mock-doh provider does not support DNS-JSON",
)
def test_provider_stat_headers_present_on_dns_json():
    status, headers, _ = _get_json("ubuntu.com", "A")
    assert status == 200
    _assert_provider_stat_headers(headers)


def test_provider_stat_headers_present_on_dns_wire():
    status, headers, _ = _post_wire(_build_dns_wire("cloudflare.com"))
    assert status == 200
    _assert_provider_stat_headers(headers)


@pytest.mark.skipif(not BLOCKED_DOMAINS, reason="BLOCKED_DOMAINS is empty in config")
def test_provider_stat_headers_absent_on_config_blocked():
    status, headers, _ = _post_wire(_build_dns_wire(_first_domain(BLOCKED_DOMAINS)))
    assert status == 200
    queried = headers.get("cloudflare-doh-worker-providers-queried", "")
    assert not queried, (
        f"expected no PROVIDERS-QUERIED header for config-blocked domain, got {queried!r}"
    )


def test_post_garbage_bytes_returns_400():
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(
            _request(
                f"{BASE_URL}{TEST_ENDPOINTS[0]}",
                method="POST",
                headers={
                    "Content-Type": "application/dns-message",
                    "Accept": "application/dns-message",
                },
                data=os.urandom(16),
            ),
            timeout=TIMEOUT,
        )

    assert e.value.code == 400


def test_get_dns_invalid_base64_returns_400():
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(
            _request(
                f"{BASE_URL}{TEST_ENDPOINTS[0]}?dns=!!!not-valid-base64!!!",
                headers={"Accept": "application/dns-message"},
            ),
            timeout=TIMEOUT,
        )

    assert e.value.code == 400


def test_get_dns_corrupt_wire_returns_400():
    garbage = base64.urlsafe_b64encode(b"\x00\x01\x02\x03").rstrip(b"=").decode()

    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(
            _request(
                f"{BASE_URL}{TEST_ENDPOINTS[0]}?dns={garbage}",
                headers={"Accept": "application/dns-message"},
            ),
            timeout=TIMEOUT,
        )

    assert e.value.code == 400


def test_head_request_returns_405():
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(
            _request(
                f"{BASE_URL}{TEST_ENDPOINTS[0]}",
                method="HEAD",
                headers={"Accept": "application/dns-json"},
            ),
            timeout=TIMEOUT,
        )

    assert e.value.code == 405


@pytest.mark.skipif(
    MOCK_DOH_ENABLED,
    reason="mock-doh provider does not support DNS-JSON",
)
@pytest.mark.parametrize("qtype", ["AAAA", "TXT", "MX"])
def test_get_dns_json_query_type(qtype: str):
    status, headers, data = _get_json("wikipedia.org", qtype)
    assert status == 200
    assert "Status" in data
    _assert_worker_headers(headers)


def test_post_dns_wire_aaaa_query():
    wire = _build_dns_wire("google.com", rdtype=dns.rdatatype.AAAA)
    status, _, _ = _post_wire(wire)
    assert status == 200


@pytest.mark.skipif(not BLOCKED_DOMAINS, reason="BLOCKED_DOMAINS is empty in config")
def test_config_blocked_domain_via_post_wire():
    wire = _build_dns_wire(_first_domain(BLOCKED_DOMAINS))
    status, headers, body = _post_wire(wire)
    assert status == 200
    msg = dns.message.from_wire(body)
    assert msg.rcode() == dns.rcode.NXDOMAIN, (
        f"expected NXDOMAIN, got {dns.rcode.to_text(msg.rcode())}"
    )
    if DEBUG:
        response_from = headers.get("cloudflare-doh-worker-response-from", "")
        assert response_from == "config"


@pytest.mark.skipif(not BLOCKED_DOMAINS, reason="BLOCKED_DOMAINS is empty in config")
def test_config_blocked_domain_via_get_wire():
    wire = _build_dns_wire(_first_domain(BLOCKED_DOMAINS))
    status, headers, body = _get_wire(wire)
    assert status == 200
    msg = dns.message.from_wire(body)
    assert msg.rcode() == dns.rcode.NXDOMAIN, (
        f"expected NXDOMAIN, got {dns.rcode.to_text(msg.rcode())}"
    )
    if DEBUG:
        response_from = headers.get("cloudflare-doh-worker-response-from", "")
        assert response_from == "config"


@pytest.mark.skipif(not ALLOWED_DOMAINS, reason="ALLOWED_DOMAINS is empty in config")
def test_allowed_domain_via_post_wire():
    wire = _build_dns_wire(_first_domain(ALLOWED_DOMAINS))
    status, headers, _ = _post_wire(wire)
    assert status == 200

    assert headers.get("cloudflare-doh-worker-config-allowed") == "1", (
        "missing CLOUDFLARE-DOH-WORKER-CONFIG-ALLOWED header"
    )
    if DEBUG:
        response_from = headers.get("cloudflare-doh-worker-response-from", "")
        assert BYPASS_PROVIDER["url"] in response_from, (
            f"expected bypass provider {BYPASS_PROVIDER['url']!r} in response-from, got {response_from!r}"
        )


@pytest.mark.skipif(
    MOCK_DOH_ENABLED,
    reason="mock-doh provider does not support DNS-JSON",
)
def test_random_subdomain_does_not_500():
    subdomain = "".join(random.choices(string.ascii_lowercase, k=20))
    domain = f"{subdomain}.trevorlauder.dev"
    status, headers, data = _get_json(domain, "A")
    assert status == 200
    assert data["Status"] in (0, 3), (
        f"expected NOERROR (0) or NXDOMAIN (3), got {data['Status']}"
    )
    _assert_worker_headers(headers)


@pytest.mark.skipif(not BLOCKED_DOMAINS, reason="BLOCKED_DOMAINS is empty in config")
@pytest.mark.skipif(not _ECS_ENABLED, reason="ECS_TRUNCATION is disabled")
def test_post_ecs_with_blocked_domain():
    wire = _build_dns_wire_with_ecs(
        _first_domain(BLOCKED_DOMAINS),
        address="203.0.113.1",
        srclen=32,
    )

    status, headers, _ = _post_wire(wire)
    assert status == 200
    ecs_truncated = headers.get("cloudflare-doh-worker-ecs-truncated", "")

    assert "203.0.113.1/32" in ecs_truncated, (
        f"expected original /32 prefix in ECS-TRUNCATED for blocked domain, got '{ecs_truncated}'"
    )

    assert f"/{_ECS_IPV4_PREFIX}" in ecs_truncated, (
        f"expected truncated /{_ECS_IPV4_PREFIX} in ECS-TRUNCATED for blocked domain, got '{ecs_truncated}'"
    )


def test_get_wire_param_with_json_accept_rejected():
    wire = _build_dns_wire("google.com")
    encoded = base64.urlsafe_b64encode(wire).rstrip(b"=").decode()

    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(
            _request(
                f"{BASE_URL}{TEST_ENDPOINTS[0]}?dns={encoded}",
                headers={"Accept": "application/dns-json"},
            ),
            timeout=TIMEOUT,
        )

    assert e.value.code == 406


def test_get_name_param_with_wire_accept_rejected():
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(
            _request(
                f"{BASE_URL}{TEST_ENDPOINTS[0]}?name=google.com&type=A",
                headers={"Accept": "application/dns-message"},
            ),
            timeout=TIMEOUT,
        )

    assert e.value.code == 406


def test_post_wire_with_json_accept_rejected():
    wire = _build_dns_wire("google.com")

    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(
            _request(
                f"{BASE_URL}{TEST_ENDPOINTS[0]}",
                method="POST",
                headers={
                    "Content-Type": "application/dns-message",
                    "Accept": "application/dns-json",
                },
                data=wire,
            ),
            timeout=TIMEOUT,
        )

    assert e.value.code == 406


def _mock_doh_reset() -> None:
    urllib.request.urlopen(
        _request(f"{MOCK_DOH_URL}/last-ecs", method="DELETE"),
        timeout=TIMEOUT,
    )


def _mock_doh_last_ecs() -> dict | None:
    with urllib.request.urlopen(
        _request(f"{MOCK_DOH_URL}/last-ecs"),
        timeout=TIMEOUT,
    ) as resp:
        return json.loads(resp.read())


@pytest.mark.skipif(not MOCK_DOH_ENABLED, reason="MOCK_DOH_ENABLED is False")
def test_mock_doh_ipv4_ecs_truncated_to_configured_prefix():
    _mock_doh_reset()
    wire = _build_dns_wire_with_ecs("example.com", address="203.0.113.1", srclen=32)
    assert _post_wire(wire)[0] == 200
    ecs = _mock_doh_last_ecs()
    assert ecs is not None, "mock-doh server recorded no ECS option"

    assert ecs["prefix"] == _ECS_IPV4_PREFIX, (
        f"expected forwarded prefix {_ECS_IPV4_PREFIX}, got {ecs['prefix']}"
    )


@pytest.mark.skipif(not MOCK_DOH_ENABLED, reason="MOCK_DOH_ENABLED is False")
def test_mock_doh_ipv4_ecs_at_configured_prefix_not_modified():
    _mock_doh_reset()

    wire = _build_dns_wire_with_ecs(
        "example.com",
        address="203.0.113.0",
        srclen=_ECS_IPV4_PREFIX,
    )

    assert _post_wire(wire)[0] == 200
    ecs = _mock_doh_last_ecs()
    assert ecs is not None, "mock-doh server recorded no ECS option"

    assert ecs["prefix"] == _ECS_IPV4_PREFIX, (
        f"expected prefix {_ECS_IPV4_PREFIX} unchanged, got {ecs['prefix']}"
    )


@pytest.mark.skipif(not MOCK_DOH_ENABLED, reason="MOCK_DOH_ENABLED is False")
def test_mock_doh_ipv6_ecs_truncated_to_configured_prefix():
    _mock_doh_reset()
    wire = _build_dns_wire_with_ecs("example.com", address="2001:db8::1", srclen=128)
    assert _post_wire(wire)[0] == 200
    ecs = _mock_doh_last_ecs()
    assert ecs is not None, "mock-doh server recorded no ECS option"

    assert ecs["prefix"] == _ECS_IPV6_PREFIX, (
        f"expected forwarded prefix {_ECS_IPV6_PREFIX}, got {ecs['prefix']}"
    )


@pytest.mark.skipif(not MOCK_DOH_ENABLED, reason="MOCK_DOH_ENABLED is False")
def test_mock_doh_ipv6_ecs_at_configured_prefix_not_modified():
    _mock_doh_reset()

    wire = _build_dns_wire_with_ecs(
        "example.com",
        address="2001:db8::",
        srclen=_ECS_IPV6_PREFIX,
    )

    assert _post_wire(wire)[0] == 200
    ecs = _mock_doh_last_ecs()
    assert ecs is not None, "mock-doh server recorded no ECS option"

    assert ecs["prefix"] == _ECS_IPV6_PREFIX, (
        f"expected prefix {_ECS_IPV6_PREFIX} unchanged, got {ecs['prefix']}"
    )


@pytest.mark.skipif(not MOCK_DOH_ENABLED, reason="MOCK_DOH_ENABLED is False")
def test_mock_doh_no_ecs_forwarded_clean():
    _mock_doh_reset()
    wire = _build_dns_wire("example.com")
    assert _post_wire(wire)[0] == 200
    ecs = _mock_doh_last_ecs()
    assert ecs is None, f"expected no ECS option forwarded, got {ecs}"


@pytest.mark.skipif(not MOCK_DOH_ENABLED, reason="MOCK_DOH_ENABLED is False")
def test_mock_doh_ipv4_ecs_below_configured_prefix_not_modified():
    _mock_doh_reset()
    below = max(1, _ECS_IPV4_PREFIX - 8)
    wire = _build_dns_wire_with_ecs("example.com", address="203.0.113.0", srclen=below)
    assert _post_wire(wire)[0] == 200
    ecs = _mock_doh_last_ecs()
    assert ecs is not None, "mock-doh server recorded no ECS option"
    assert ecs["prefix"] == below, (
        f"expected prefix {below} unchanged, got {ecs['prefix']}"
    )


@pytest.mark.skipif(not MOCK_DOH_ENABLED, reason="MOCK_DOH_ENABLED is False")
def test_mock_doh_ipv6_ecs_below_configured_prefix_not_modified():
    _mock_doh_reset()
    below = max(1, _ECS_IPV6_PREFIX - 16)
    wire = _build_dns_wire_with_ecs("example.com", address="2001:db8::", srclen=below)
    assert _post_wire(wire)[0] == 200
    ecs = _mock_doh_last_ecs()
    assert ecs is not None, "mock-doh server recorded no ECS option"
    assert ecs["prefix"] == below, (
        f"expected prefix {below} unchanged, got {ecs['prefix']}"
    )


@pytest.mark.skipif(not MOCK_DOH_ENABLED, reason="MOCK_DOH_ENABLED is False")
def test_mock_doh_ipv4_ecs_truncated_via_get():
    _mock_doh_reset()
    wire = _build_dns_wire_with_ecs("example.com", address="203.0.113.1", srclen=32)
    assert _get_wire(wire)[0] == 200
    ecs = _mock_doh_last_ecs()
    assert ecs is not None, "mock-doh server recorded no ECS option"
    assert ecs["prefix"] == _ECS_IPV4_PREFIX, (
        f"expected forwarded prefix {_ECS_IPV4_PREFIX}, got {ecs['prefix']}"
    )


@pytest.mark.skipif(not MOCK_DOH_ENABLED, reason="MOCK_DOH_ENABLED is False")
def test_mock_doh_ipv6_ecs_truncated_via_get():
    _mock_doh_reset()
    wire = _build_dns_wire_with_ecs("example.com", address="2001:db8::1", srclen=128)
    assert _get_wire(wire)[0] == 200
    ecs = _mock_doh_last_ecs()
    assert ecs is not None, "mock-doh server recorded no ECS option"
    assert ecs["prefix"] == _ECS_IPV6_PREFIX, (
        f"expected forwarded prefix {_ECS_IPV6_PREFIX}, got {ecs['prefix']}"
    )


@pytest.mark.skipif(not MOCK_DOH_ENABLED, reason="MOCK_DOH_ENABLED is False")
def test_mock_doh_ipv4_ecs_at_configured_prefix_not_modified_via_get():
    _mock_doh_reset()
    wire = _build_dns_wire_with_ecs(
        "example.com",
        address="203.0.113.0",
        srclen=_ECS_IPV4_PREFIX,
    )

    assert _get_wire(wire)[0] == 200
    ecs = _mock_doh_last_ecs()
    assert ecs is not None, "mock-doh server recorded no ECS option"
    assert ecs["prefix"] == _ECS_IPV4_PREFIX, (
        f"expected prefix {_ECS_IPV4_PREFIX} unchanged, got {ecs['prefix']}"
    )


@pytest.mark.skipif(not MOCK_DOH_ENABLED, reason="MOCK_DOH_ENABLED is False")
def test_mock_doh_ipv6_ecs_at_configured_prefix_not_modified_via_get():
    _mock_doh_reset()
    wire = _build_dns_wire_with_ecs(
        "example.com",
        address="2001:db8::",
        srclen=_ECS_IPV6_PREFIX,
    )

    assert _get_wire(wire)[0] == 200
    ecs = _mock_doh_last_ecs()
    assert ecs is not None, "mock-doh server recorded no ECS option"
    assert ecs["prefix"] == _ECS_IPV6_PREFIX, (
        f"expected prefix {_ECS_IPV6_PREFIX} unchanged, got {ecs['prefix']}"
    )


@pytest.mark.skipif(not MOCK_DOH_ENABLED, reason="MOCK_DOH_ENABLED is False")
def test_mock_doh_no_ecs_forwarded_clean_via_get():
    _mock_doh_reset()
    wire = _build_dns_wire("example.com")
    assert _get_wire(wire)[0] == 200
    ecs = _mock_doh_last_ecs()
    assert ecs is None, f"expected no ECS option forwarded, got {ecs}"


def _parse_max_age(headers: object) -> int | None:
    cc = headers.get("cache-control", "")
    return int(cc.split("=", 1)[1]) if cc.startswith("max-age=") else None


@pytest.mark.skipif(not CACHE_DNS, reason="CACHE_DNS is disabled")
@pytest.mark.skipif(MOCK_DOH_ENABLED, reason="mock-doh does not support DNS-JSON")
def test_cache_response_header_absent_on_miss():
    suffix = "".join(random.choices(string.ascii_lowercase, k=16))
    _, headers, _ = _get_json(f"miss-{suffix}.trevorlauder.dev", "A")
    assert headers.get(_HEADER_CACHE) != "HIT"


@pytest.mark.skipif(not CACHE_DNS, reason="CACHE_DNS is disabled")
@pytest.mark.skipif(IS_LOCAL, reason="Cache API not available in local dev")
@pytest.mark.skipif(MOCK_DOH_ENABLED, reason="mock-doh does not support DNS-JSON")
def test_cache_hit_on_repeated_get_json_query():
    assert _get_json("google.com", "A")[0] == 200
    time.sleep(1)
    _, headers, _ = _get_json("google.com", "A")
    assert headers.get(_HEADER_CACHE) == "HIT"


@pytest.mark.skipif(not CACHE_DNS, reason="CACHE_DNS is disabled")
@pytest.mark.skipif(IS_LOCAL, reason="Cache API not available in local dev")
@pytest.mark.skipif(MOCK_DOH_ENABLED, reason="mock-doh does not support DNS-JSON")
def test_cache_hit_remaining_ttl_not_greater_than_miss():
    miss_ttl = _parse_max_age(_get_json("cloudflare.com", "A")[1])
    assert miss_ttl is not None, "miss response missing Cache-Control: max-age"
    time.sleep(1)
    _, headers, _ = _get_json("cloudflare.com", "A")
    if headers.get(_HEADER_CACHE) == "HIT":
        hit_ttl = _parse_max_age(headers)
        assert hit_ttl is not None, "hit response missing Cache-Control: max-age"
        assert hit_ttl <= miss_ttl
