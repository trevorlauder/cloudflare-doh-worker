# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Tests for the DoH worker endpoints."""

import base64
import json
import os
import random
import string
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

import dns.edns
import dns.message
import dns.rcode
import dns.rdatatype
import pytest
from conftest import BASE_URL, IS_HTTPS, IS_LOCAL, SKIP_TLS, resolve_env
from curl_cffi import requests as cffi_requests
from curl_cffi.const import CurlHttpVersion

from config import (
  ALLOWED_DOMAINS,
  BLOCKED_DOMAINS,
  BYPASS_PROVIDER,
  CONFIG_ENDPOINT,
  DEBUG,
  ECS_TRUNCATION,
  ENDPOINTS,
  HEALTH_ENDPOINT,
  REBIND_PROTECTION,
)

TEST_ENDPOINTS = [resolve_env(e) for e in ENDPOINTS]
HEALTH_ENDPOINT = resolve_env(HEALTH_ENDPOINT)
CONFIG_ENDPOINT = resolve_env(CONFIG_ENDPOINT)

ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")

_ECS_ENABLED = bool(ECS_TRUNCATION and ECS_TRUNCATION.get("enabled"))
_ECS_IPV4_PREFIX = ECS_TRUNCATION.get("ipv4_prefix", 24) if ECS_TRUNCATION else 24
_ECS_IPV6_PREFIX = ECS_TRUNCATION.get("ipv6_prefix", 64) if ECS_TRUNCATION else 64

_pyproject = tomllib.loads(
  (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
)

DEFAULT_HEADERS = {
  "User-Agent": f"doh-test/{_pyproject['project']['version']}",
}

TIMEOUT = 10


def _assert_worker_headers(headers) -> None:
  """Assert all diagnostic headers are present (skipped when DEBUG is off)."""
  if not DEBUG:
    return

  assert headers.get("cloudflare-doh-worker-response-from"), (
    "missing CLOUDFLARE-DOH-WORKER-RESPONSE-FROM header"
  )

  assert headers.get("cloudflare-doh-worker-response-codes"), (
    "missing CLOUDFLARE-DOH-WORKER-RESPONSE-CODES header"
  )

  assert headers.get("cloudflare-doh-worker-possibly-blocked-providers") is not None, (
    "missing CLOUDFLARE-DOH-WORKER-POSSIBLY-BLOCKED-PROVIDERS header"
  )

  assert headers.get("cloudflare-doh-worker-blocked-providers") is not None, (
    "missing CLOUDFLARE-DOH-WORKER-BLOCKED-PROVIDERS header"
  )

  assert headers.get("cloudflare-doh-worker-timed-out-providers") is not None, (
    "missing CLOUDFLARE-DOH-WORKER-TIMED-OUT-PROVIDERS header"
  )

  assert headers.get("cloudflare-doh-worker-config-allowed") is not None, (
    "missing CLOUDFLARE-DOH-WORKER-CONFIG-ALLOWED header"
  )

  assert headers.get("cloudflare-doh-worker-config-blocked") is not None, (
    "missing CLOUDFLARE-DOH-WORKER-CONFIG-BLOCKED header"
  )


def _build_dns_wire(name: str, rdtype=dns.rdatatype.A) -> bytes:
  """Build a DNS query wire packet."""

  return dns.message.make_query(name, rdtype).to_wire()


def _build_dns_wire_with_ecs(
  name: str, address: str = "203.0.113.1", srclen: int = 32
) -> bytes:
  """Build a DNS query wire packet with an ECS option."""

  msg = dns.message.make_query(name, dns.rdatatype.A, use_edns=True)
  ecs = dns.edns.ECSOption(address, srclen=srclen, scopelen=0)
  msg.use_edns(edns=0, options=[ecs])
  return msg.to_wire()


def _request(
  url: str,
  *,
  method: str = "GET",
  headers: dict | None = None,
  data: bytes | None = None,
) -> urllib.request.Request:
  """Build a Request with DEFAULT_HEADERS merged in."""

  return urllib.request.Request(
    url,
    data=data,
    headers={**DEFAULT_HEADERS, **(headers or {})},
    method=method,
  )


# Test failure cases (non-200 responses)


def test_unknown_path_returns_404():
  """A path not in ENDPOINTS should return 404."""

  with pytest.raises(urllib.error.HTTPError) as e:
    urllib.request.urlopen(_request(f"{BASE_URL}/doh/does/not/exist"), timeout=TIMEOUT)

  assert e.value.code == 404


def test_bad_accept_returns_406():
  """GET with unsupported Accept header should return 406."""

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
  """GET with no name or dns param should return 400."""

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
  """PUT/PATCH/DELETE should return 405."""

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


# Test http3 support


@pytest.mark.skipif(not IS_HTTPS, reason="Requires HTTPS stack")
def test_http3_alt_svc_advertised():
  """Cloudflare should advertise HTTP/3 via the Alt-Svc response header."""

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}?name=google.com&type=A",
      headers={"Accept": "application/dns-json"},
    ),
    timeout=TIMEOUT,
  ) as resp:
    alt_svc = resp.headers.get("alt-svc", "")
    assert "h3" in alt_svc, f"alt-svc header missing h3: {alt_svc!r}"
    _assert_worker_headers(resp.headers)


@pytest.mark.skipif(
  not IS_HTTPS or IS_LOCAL,
  reason="HTTP/3 requires nginx HTTPS stack; skipped for localhost",
)
def test_http3_udp():
  """Connect using HTTP/3 (QUIC over UDP)"""

  resp = cffi_requests.get(
    f"{BASE_URL}{TEST_ENDPOINTS[0]}?name=google.com&type=A",
    http_version=CurlHttpVersion.V3ONLY,
    headers={"Accept": "application/dns-json", **DEFAULT_HEADERS},
    timeout=TIMEOUT,
    verify=not SKIP_TLS,
  )

  assert resp.status_code == 200, f"HTTP/3 returned {resp.status_code}"
  _assert_worker_headers(resp.headers)


# Per endpoint tests


@pytest.mark.parametrize("endpoint", TEST_ENDPOINTS)
def test_get_dns_json_name(endpoint: str):
  """GET ?name=google.com with Accept: application/dns-json"""

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{endpoint}?name=google.com&type=A",
      headers={"Accept": "application/dns-json"},
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    content_type = resp.headers.get("content-type", "")
    assert "dns-json" in content_type or "json" in content_type, (
      f"unexpected content-type: {content_type}"
    )
    data = json.loads(resp.read())
    assert "Status" in data, "JSON response missing 'Status' key"
    _assert_worker_headers(resp.headers)


@pytest.mark.parametrize("endpoint", TEST_ENDPOINTS)
def test_get_dns_wire_param(endpoint: str):
  """GET ?dns=<base64url wire> with Accept: application/dns-message"""

  wire = _build_dns_wire("google.com")
  encoded = base64.urlsafe_b64encode(wire).rstrip(b"=").decode()

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{endpoint}?dns={encoded}",
      headers={"Accept": "application/dns-message"},
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    content_type = resp.headers.get("content-type", "")
    assert "dns-message" in content_type, f"unexpected content-type: {content_type}"
    assert resp.read()[:2] == wire[:2], "transaction ID mismatch in response"
    _assert_worker_headers(resp.headers)


@pytest.mark.parametrize("endpoint", TEST_ENDPOINTS)
def test_post_dns_wire(endpoint: str):
  """POST DNS wire-format body with Content-Type: application/dns-message"""

  wire = _build_dns_wire("cloudflare.com")

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{endpoint}",
      method="POST",
      headers={
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
      },
      data=wire,
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    content_type = resp.headers.get("content-type", "")
    assert "dns-message" in content_type, f"unexpected content-type: {content_type}"
    assert resp.read()[:2] == wire[:2], "transaction ID mismatch in response"
    _assert_worker_headers(resp.headers)


# Config-level block / allow / provider-block tests


@pytest.mark.skipif(not BLOCKED_DOMAINS, reason="BLOCKED_DOMAINS is empty in config")
def test_config_blocked_domain_returns_nxdomain():
  """Blocked domain returns synthetic NXDOMAIN."""

  domain = next(iter(BLOCKED_DOMAINS)).lstrip("*").lstrip(".")

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}?name={domain}&type=A",
      headers={"Accept": "application/dns-json"},
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    data = json.loads(resp.read())
    assert data["Status"] == 3, f"expected NXDOMAIN (Status 3), got {data['Status']}"
    if DEBUG:
      response_from = resp.headers.get("cloudflare-doh-worker-response-from", "")
      assert response_from == "config", (
        f"expected response-from 'config', got {response_from!r}"
      )
      config_blocked = resp.headers.get("cloudflare-doh-worker-config-blocked", "")
      assert config_blocked == "1", (
        f"expected CLOUDFLARE-DOH-WORKER-CONFIG-BLOCKED to be '1', got {config_blocked!r}"
      )


@pytest.mark.skipif(not ALLOWED_DOMAINS, reason="ALLOWED_DOMAINS is empty in config")
def test_allowed_domain_uses_bypass_provider():
  """Allowed domain resolves via BYPASS_PROVIDER."""

  domain = next(iter(ALLOWED_DOMAINS)).lstrip("*").lstrip(".")

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}?name={domain}&type=A",
      headers={"Accept": "application/dns-json"},
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    if DEBUG:
      response_from = resp.headers.get("cloudflare-doh-worker-response-from", "")
      assert BYPASS_PROVIDER["host"] in response_from, (
        f"expected bypass provider {BYPASS_PROVIDER['host']!r} in response-from, got {response_from!r}"
      )
    _assert_worker_headers(resp.headers)


def test_provider_blocks_known_malware_domain():
  """Malware domain resolves to NXDOMAIN or blocked IP."""

  domain = "malware.testcategory.com"

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}?name={domain}&type=A",
      headers={"Accept": "application/dns-json"},
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    data = json.loads(resp.read())
    status = data.get("Status", 0)
    answers = data.get("Answer", [])
    blocked_ips = {"0.0.0.0", "::"}
    is_nxdomain = status == 3
    is_blocked_ip = any(a.get("data") in blocked_ips for a in answers)

    assert is_nxdomain or is_blocked_ip, (
      f"expected {domain!r} to resolve to NXDOMAIN or a blocked IP, "
      f"got Status={status}, Answer={answers}"
    )

    if DEBUG:
      blocked_by = resp.headers.get("cloudflare-doh-worker-blocked-providers", "")
      possibly_blocked_by = resp.headers.get(
        "cloudflare-doh-worker-possibly-blocked-providers", ""
      )
      assert blocked_by or possibly_blocked_by, (
        f"expected at least one provider to report blocking {domain!r}, "
        f"blocked-providers={blocked_by!r}, possibly-blocked-providers={possibly_blocked_by!r}"
      )


# Config endpoint tests


@pytest.mark.skipif(not CONFIG_ENDPOINT, reason="CONFIG_ENDPOINT is not set")
def test_config_without_token_returns_401():
  """Config endpoint without token returns 401 or 404."""

  with pytest.raises(urllib.error.HTTPError) as e:
    urllib.request.urlopen(
      _request(f"{BASE_URL}{CONFIG_ENDPOINT}"),
      timeout=TIMEOUT,
    )

  assert e.value.code in (401, 404), f"expected 401 or 404, got {e.value.code}"


@pytest.mark.skipif(not CONFIG_ENDPOINT, reason="CONFIG_ENDPOINT is not set")
@pytest.mark.skipif(not ADMIN_TOKEN, reason="ADMIN_TOKEN not set in environment")
def test_config_with_valid_token_returns_config():
  """Config endpoint with valid token returns JSON config."""

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
    assert "ENDPOINTS" in data, "config response missing 'ENDPOINTS' key"
    assert "BLOCKED_DOMAINS" in data, "config response missing 'BLOCKED_DOMAINS' key"
    assert "REBIND_PROTECTION" in data, (
      "config response missing 'REBIND_PROTECTION' key"
    )


@pytest.mark.skipif(not CONFIG_ENDPOINT, reason="CONFIG_ENDPOINT is not set")
def test_config_with_bad_token_returns_401():
  """Config endpoint with bad token returns 401 or 404."""

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
  """Config endpoint returns 404 when ADMIN_TOKEN is unset."""

  for headers in ({}, {"Authorization": "Bearer any-value"}):
    with pytest.raises(urllib.error.HTTPError) as e:
      urllib.request.urlopen(
        _request(f"{BASE_URL}{CONFIG_ENDPOINT}", headers=headers),
        timeout=TIMEOUT,
      )

    assert e.value.code == 404, f"expected 404, got {e.value.code}"


# Health endpoint


@pytest.mark.skipif(not HEALTH_ENDPOINT, reason="HEALTH_ENDPOINT is disabled")
def test_health_returns_ok():
  """GET /health should return 200 with body 'ok'."""

  with urllib.request.urlopen(
    _request(f"{BASE_URL}{HEALTH_ENDPOINT}"),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    assert resp.read().decode() == "ok"


# Cache header tests


def test_cache_control_present_on_successful_dns_json():
  """Successful DNS-JSON response has Cache-Control: max-age=N."""

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}?name=google.com&type=A",
      headers={"Accept": "application/dns-json"},
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    cache_control = resp.headers.get("cache-control", "")
    assert cache_control.startswith("max-age="), (
      f"expected Cache-Control: max-age=N, got {cache_control!r}"
    )
    ttl = int(cache_control.split("=", 1)[1])
    assert ttl > 0, f"expected positive TTL in Cache-Control, got {ttl}"


def test_cache_control_present_on_successful_dns_wire():
  """Successful DNS wire response has Cache-Control: max-age=N."""

  wire = _build_dns_wire("google.com")

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}",
      method="POST",
      headers={
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
      },
      data=wire,
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    cache_control = resp.headers.get("cache-control", "")
    assert cache_control.startswith("max-age="), (
      f"expected Cache-Control: max-age=N, got {cache_control!r}"
    )
    ttl = int(cache_control.split("=", 1)[1])
    assert ttl > 0, f"expected positive TTL in Cache-Control, got {ttl}"


@pytest.mark.skipif(not BLOCKED_DOMAINS, reason="BLOCKED_DOMAINS is empty in config")
def test_blocked_domain_json_has_empty_answer():
  """Blocked domain DNS-JSON response includes 'Answer': []."""

  domain = next(iter(BLOCKED_DOMAINS)).lstrip("*").lstrip(".")

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}?name={domain}&type=A",
      headers={"Accept": "application/dns-json"},
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    data = json.loads(resp.read())
    assert data["Status"] == 3, f"expected NXDOMAIN (Status 3), got {data['Status']}"
    assert "Answer" in data, "blocked JSON response missing 'Answer' key"
    assert data["Answer"] == [], (
      f"expected empty Answer list for blocked domain, got {data['Answer']!r}"
    )


@pytest.mark.skipif(not REBIND_PROTECTION, reason="REBIND_PROTECTION is disabled")
def test_rebind_protection_blocks_private_ip():
  """Private IP domain is blocked by rebind protection."""

  domain = "doh-rebind-test.trevorlauder.dev"

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}?name={domain}&type=A",
      headers={"Accept": "application/dns-json"},
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    data = json.loads(resp.read())
    assert data["Status"] == 3, f"expected NXDOMAIN (Status 3), got {data['Status']}"

    if DEBUG:
      response_from = resp.headers.get("cloudflare-doh-worker-response-from", "")
      assert response_from == "rebind-protection", (
        f"expected response-from 'rebind-protection', got {response_from!r}"
      )
    rebind_by = resp.headers.get("cloudflare-doh-worker-rebind-protected", "")
    assert rebind_by == "1", (
      f"expected CLOUDFLARE-DOH-WORKER-REBIND-PROTECTED to be '1', got {rebind_by!r}"
    )


@pytest.mark.skipif(REBIND_PROTECTION, reason="REBIND_PROTECTION is enabled")
def test_rebind_protection_disabled_allows_private_ip():
  """Private IP domain resolves normally when rebind protection is off."""

  domain = "doh-rebind-test.trevorlauder.dev"

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}?name={domain}&type=A",
      headers={"Accept": "application/dns-json"},
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    data = json.loads(resp.read())
    assert data["Status"] == 0, (
      f"expected NOERROR (Status 0) when rebind protection is off, got {data['Status']}"
    )

    if DEBUG:
      response_from = resp.headers.get("cloudflare-doh-worker-response-from", "")
      assert response_from != "rebind-protection", (
        f"expected response NOT from rebind-protection, got {response_from!r}"
      )
    _assert_worker_headers(resp.headers)


# ECS truncation tests


@pytest.mark.skipif(not _ECS_ENABLED, reason="ECS_TRUNCATION is disabled")
def test_post_dns_wire_with_ecs():
  """POST wire query with ECS returns valid response."""

  wire = _build_dns_wire_with_ecs("trevorlauder.dev", address="203.0.113.1", srclen=32)

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}",
      method="POST",
      headers={
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
      },
      data=wire,
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    content_type = resp.headers.get("content-type", "")
    assert "dns-message" in content_type, f"unexpected content-type: {content_type}"
    body = resp.read()
    assert len(body) > 12, "response body too short to be a valid DNS message"
    assert body[:2] == wire[:2], "transaction ID mismatch in response"
    _assert_worker_headers(resp.headers)
    ecs_truncated = resp.headers.get("cloudflare-doh-worker-ecs-truncated", "")
    assert "203.0.113.1/32" in ecs_truncated, (
      f"expected original /32 prefix in ECS-TRUNCATED, got '{ecs_truncated}'"
    )
    assert f"/{_ECS_IPV4_PREFIX}" in ecs_truncated, (
      f"expected truncated /{_ECS_IPV4_PREFIX} prefix in ECS-TRUNCATED, got '{ecs_truncated}'"
    )


def test_post_dns_wire_with_ecs_no_truncation():
  """ECS at or below configured prefix is not truncated (POST)."""

  wire = _build_dns_wire_with_ecs(
    "trevorlauder.dev", address="203.0.113.0", srclen=_ECS_IPV4_PREFIX
  )

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}",
      method="POST",
      headers={
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
      },
      data=wire,
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    ecs_truncated = resp.headers.get("cloudflare-doh-worker-ecs-truncated", "")
    assert not ecs_truncated, (
      f"expected ECS-TRUNCATED to be empty for /{_ECS_IPV4_PREFIX} prefix, got '{ecs_truncated}'"
    )


@pytest.mark.skipif(not _ECS_ENABLED, reason="ECS_TRUNCATION is disabled")
def test_get_dns_wire_with_ecs():
  """Oversized ECS prefix is truncated (GET)."""

  wire = _build_dns_wire_with_ecs("trevorlauder.dev", address="203.0.113.1", srclen=32)
  encoded = base64.urlsafe_b64encode(wire).rstrip(b"=").decode("ascii")
  url = f"{BASE_URL}{TEST_ENDPOINTS[0]}?dns={encoded}"

  with urllib.request.urlopen(
    _request(url, headers={"Accept": "application/dns-message"}),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    _assert_worker_headers(resp.headers)
    ecs_truncated = resp.headers.get("cloudflare-doh-worker-ecs-truncated", "")
    assert "203.0.113.1/32" in ecs_truncated, (
      f"expected original /32 prefix in ECS-TRUNCATED for GET, got '{ecs_truncated}'"
    )
    assert f"/{_ECS_IPV4_PREFIX}" in ecs_truncated, (
      f"expected truncated /{_ECS_IPV4_PREFIX} prefix in ECS-TRUNCATED for GET, got '{ecs_truncated}'"
    )


def test_get_dns_wire_with_ecs_no_truncation():
  """ECS at configured prefix is not truncated (GET)."""

  wire = _build_dns_wire_with_ecs(
    "trevorlauder.dev", address="203.0.113.0", srclen=_ECS_IPV4_PREFIX
  )
  encoded = base64.urlsafe_b64encode(wire).rstrip(b"=").decode("ascii")
  url = f"{BASE_URL}{TEST_ENDPOINTS[0]}?dns={encoded}"

  with urllib.request.urlopen(
    _request(url, headers={"Accept": "application/dns-message"}),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    ecs_truncated = resp.headers.get("cloudflare-doh-worker-ecs-truncated", "")
    assert not ecs_truncated, (
      f"expected ECS-TRUNCATED to be empty for GET /{_ECS_IPV4_PREFIX} prefix, got '{ecs_truncated}'"
    )


# IPv6 ECS truncation tests


@pytest.mark.skipif(not _ECS_ENABLED, reason="ECS_TRUNCATION is disabled")
def test_post_dns_wire_with_ipv6_ecs_truncated():
  """IPv6 ECS /128 prefix truncates to configured prefix."""

  wire = _build_dns_wire_with_ecs("trevorlauder.dev", address="2001:db8::1", srclen=128)

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}",
      method="POST",
      headers={
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
      },
      data=wire,
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    ecs_truncated = resp.headers.get("cloudflare-doh-worker-ecs-truncated", "")
    assert "2001:db8::1/128" in ecs_truncated, (
      f"expected original /128 prefix in ECS-TRUNCATED, got '{ecs_truncated}'"
    )
    assert f"/{_ECS_IPV6_PREFIX}" in ecs_truncated, (
      f"expected truncated /{_ECS_IPV6_PREFIX} prefix in ECS-TRUNCATED, got '{ecs_truncated}'"
    )


def test_post_dns_wire_with_ipv6_ecs_no_truncation():
  """IPv6 ECS at configured prefix is not truncated."""

  wire = _build_dns_wire_with_ecs(
    "trevorlauder.dev", address="2001:db8::", srclen=_ECS_IPV6_PREFIX
  )

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}",
      method="POST",
      headers={
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
      },
      data=wire,
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    ecs_truncated = resp.headers.get("cloudflare-doh-worker-ecs-truncated", "")
    assert not ecs_truncated, (
      f"expected ECS-TRUNCATED to be empty for IPv6 /{_ECS_IPV6_PREFIX} prefix, got '{ecs_truncated}'"
    )


@pytest.mark.skipif(_ECS_ENABLED, reason="ECS_TRUNCATION is enabled")
def test_ecs_disabled_no_truncation_header():
  """Oversized ECS prefix passes through when truncation is disabled."""

  wire = _build_dns_wire_with_ecs("trevorlauder.dev", address="203.0.113.1", srclen=32)

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}",
      method="POST",
      headers={
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
      },
      data=wire,
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    ecs_truncated = resp.headers.get("cloudflare-doh-worker-ecs-truncated", "")
    assert not ecs_truncated, (
      f"expected no ECS-TRUNCATED header when truncation is disabled, got '{ecs_truncated}'"
    )


# Invalid input edge cases


def test_post_empty_body_returns_400():
  """POST with an empty body should return 400."""

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


def test_post_garbage_bytes_returns_400():
  """POST with random garbage bytes should return 400."""

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
  """GET ?dns= with invalid base64 should return 400."""

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
  """GET ?dns= with valid base64 but corrupt DNS wire should return 400."""

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
  """HEAD request should return 405."""

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


# DNS query type coverage


def test_get_dns_json_aaaa_query():
  """GET ?name=&type=AAAA — verify IPv6 answer parsing works."""

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}?name=google.com&type=AAAA",
      headers={"Accept": "application/dns-json"},
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    data = json.loads(resp.read())
    assert "Status" in data
    assert data["Status"] == 0, f"expected NOERROR (0), got {data['Status']}"
    _assert_worker_headers(resp.headers)


def test_get_dns_json_txt_query():
  """GET ?name=&type=TXT — verify non-address record type passes through."""

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}?name=google.com&type=TXT",
      headers={"Accept": "application/dns-json"},
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    data = json.loads(resp.read())
    assert "Status" in data
    _assert_worker_headers(resp.headers)


def test_get_dns_json_mx_query():
  """GET ?name=&type=MX — verify MX record type passes through."""

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}?name=google.com&type=MX",
      headers={"Accept": "application/dns-json"},
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    data = json.loads(resp.read())
    assert "Status" in data
    _assert_worker_headers(resp.headers)


def test_post_dns_wire_aaaa_query():
  """POST DNS wire AAAA query — verify binary AAAA path."""

  wire = _build_dns_wire("google.com", rdtype=dns.rdatatype.AAAA)

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}",
      method="POST",
      headers={
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
      },
      data=wire,
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    body = resp.read()
    assert body[:2] == wire[:2], "transaction ID mismatch"
    _assert_worker_headers(resp.headers)


# Wire-format paths for config-level logic


@pytest.mark.skipif(not BLOCKED_DOMAINS, reason="BLOCKED_DOMAINS is empty in config")
def test_config_blocked_domain_via_post_wire():
  """Blocked domain via POST wire returns NXDOMAIN."""

  domain = next(iter(BLOCKED_DOMAINS)).lstrip("*").lstrip(".")
  wire = _build_dns_wire(domain)

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}",
      method="POST",
      headers={
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
      },
      data=wire,
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    content_type = resp.headers.get("content-type", "")
    assert "dns-message" in content_type, f"unexpected content-type: {content_type}"
    body = resp.read()
    msg = dns.message.from_wire(body)
    assert msg.rcode() == dns.rcode.NXDOMAIN, (
      f"expected NXDOMAIN, got {dns.rcode.to_text(msg.rcode())}"
    )
    if DEBUG:
      response_from = resp.headers.get("cloudflare-doh-worker-response-from", "")
      assert response_from == "config"


@pytest.mark.skipif(not BLOCKED_DOMAINS, reason="BLOCKED_DOMAINS is empty in config")
def test_config_blocked_domain_via_get_wire():
  """Blocked domain via GET wire returns NXDOMAIN."""

  domain = next(iter(BLOCKED_DOMAINS)).lstrip("*").lstrip(".")
  wire = _build_dns_wire(domain)
  encoded = base64.urlsafe_b64encode(wire).rstrip(b"=").decode()

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}?dns={encoded}",
      headers={"Accept": "application/dns-message"},
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    content_type = resp.headers.get("content-type", "")
    assert "dns-message" in content_type, f"unexpected content-type: {content_type}"
    body = resp.read()
    msg = dns.message.from_wire(body)
    assert msg.rcode() == dns.rcode.NXDOMAIN, (
      f"expected NXDOMAIN, got {dns.rcode.to_text(msg.rcode())}"
    )
    if DEBUG:
      response_from = resp.headers.get("cloudflare-doh-worker-response-from", "")
      assert response_from == "config"


@pytest.mark.skipif(not ALLOWED_DOMAINS, reason="ALLOWED_DOMAINS is empty in config")
def test_allowed_domain_via_post_wire():
  """Allowed domain via POST wire uses bypass provider."""

  domain = next(iter(ALLOWED_DOMAINS)).lstrip("*").lstrip(".")
  wire = _build_dns_wire(domain)

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}",
      method="POST",
      headers={
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
      },
      data=wire,
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    if DEBUG:
      response_from = resp.headers.get("cloudflare-doh-worker-response-from", "")
      assert BYPASS_PROVIDER["host"] in response_from, (
        f"expected bypass provider {BYPASS_PROVIDER['host']!r} in response-from, got {response_from!r}"
      )
    _assert_worker_headers(resp.headers)


# Non-existent domain


def test_random_subdomain_does_not_500():
  """Random subdomain resolves without crashing the worker."""

  subdomain = "".join(random.choices(string.ascii_lowercase, k=20))
  domain = f"{subdomain}.trevorlauder.dev"

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}?name={domain}&type=A",
      headers={"Accept": "application/dns-json"},
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    data = json.loads(resp.read())
    assert data["Status"] in (0, 3), (
      f"expected NOERROR (0) or NXDOMAIN (3), got {data['Status']}"
    )
    _assert_worker_headers(resp.headers)


# ECS + config-blocked interaction


@pytest.mark.skipif(not BLOCKED_DOMAINS, reason="BLOCKED_DOMAINS is empty in config")
@pytest.mark.skipif(not _ECS_ENABLED, reason="ECS_TRUNCATION is disabled")
def test_post_ecs_with_blocked_domain():
  """Blocked domain with ECS shows truncation and config headers."""

  domain = next(iter(BLOCKED_DOMAINS)).lstrip("*").lstrip(".")
  wire = _build_dns_wire_with_ecs(domain, address="203.0.113.1", srclen=32)

  with urllib.request.urlopen(
    _request(
      f"{BASE_URL}{TEST_ENDPOINTS[0]}",
      method="POST",
      headers={
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
      },
      data=wire,
    ),
    timeout=TIMEOUT,
  ) as resp:
    assert resp.status == 200
    ecs_truncated = resp.headers.get("cloudflare-doh-worker-ecs-truncated", "")
    assert "203.0.113.1/32" in ecs_truncated, (
      f"expected original /32 prefix in ECS-TRUNCATED for blocked domain, got '{ecs_truncated}'"
    )
    assert f"/{_ECS_IPV4_PREFIX}" in ecs_truncated, (
      f"expected truncated /{_ECS_IPV4_PREFIX} in ECS-TRUNCATED for blocked domain, got '{ecs_truncated}'"
    )
    if DEBUG:
      response_from = resp.headers.get("cloudflare-doh-worker-response-from", "")
      assert response_from == "config", (
        f"expected response-from 'config', got {response_from!r}"
      )
    body = resp.read()
    msg = dns.message.from_wire(body)
    assert msg.rcode() == dns.rcode.NXDOMAIN


# Mismatched Accept header tests — these non-standard combos must be rejected (406)


def test_get_wire_param_with_json_accept_rejected():
  """GET wire param with json Accept returns 406."""

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
  """GET name param with wire Accept returns 406."""

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
  """POST wire with json Accept returns 406."""

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
