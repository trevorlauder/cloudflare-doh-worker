# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Unit tests for worker internals (select_winner, secret resolution, validation)."""

import asyncio
import json
import math
from multiprocessing import Pool
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
import urllib.parse

from conftest import _workers_stub
import dns.message
import dns.rdatatype
import pytest
import upload_blocklist

import config
from dns_utils import (
    DnsParseResult,
    ProviderResult,
    Question,
    _bloom_contains,
    parse_blocklist_text,
)
import worker
from worker import (
    _handle_health,
    _negotiate_accept,
    _resolve_secrets,
    _select_winner,
    _validate_config,
    _validate_types,
)


def _result(
    *,
    main: bool = True,
    failed: bool = False,
    blocked: bool = False,
    possibly_blocked: bool = False,
    rebind: bool = False,
    url: str = "https://dns.example.com/dns-query",
) -> ProviderResult:
    return ProviderResult(
        url=url,
        provider_id=url,
        response_status=200,
        response_content_type="application/dns-message",
        response_body=b"",
        main=main,
        failed=failed,
        blocked=blocked,
        possibly_blocked=possibly_blocked,
        rebind=rebind,
    )


class _Env:
    def __init__(self, **kwargs: object) -> None:
        for k, v in kwargs.items():
            setattr(self, k, v)


def test_select_winner_empty():
    assert _select_winner([]) is None


def test_select_winner_all_failed():
    assert _select_winner([_result(failed=True), _result(failed=True)]) is None


def test_select_winner_single():
    r = _result()
    assert _select_winner([r]) is r


def test_select_winner_prefers_main():
    additional = _result(main=False)
    main = _result(main=True)
    assert _select_winner([additional, main]) is main


def test_select_winner_blocked_beats_successful():
    success = _result()
    blocked = _result(blocked=True)
    assert _select_winner([success, blocked]) is blocked


def test_select_winner_possibly_blocked_beats_successful():
    success = _result()
    possibly = _result(possibly_blocked=True)
    assert _select_winner([success, possibly]) is possibly


def test_select_winner_blocked_beats_possibly_blocked():
    possibly = _result(possibly_blocked=True)
    blocked = _result(blocked=True)
    assert _select_winner([possibly, blocked]) is blocked


def test_select_winner_rebind_replaced_when_protection_on(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(config, "REBIND_PROTECTION", True)
    rebind = _result(main=True, rebind=True)
    clean = _result(main=False, rebind=False)
    assert _select_winner([rebind, clean]) is clean


def test_select_winner_rebind_kept_when_protection_off(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "REBIND_PROTECTION", False)
    rebind = _result(main=True, rebind=True)
    clean = _result(main=False, rebind=False)
    assert _select_winner([rebind, clean]) is rebind


def test_select_winner_rebind_no_clean_alternative_kept(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(config, "REBIND_PROTECTION", True)
    rebind = _result(main=True, rebind=True)
    assert _select_winner([rebind]) is rebind


def test_select_winner_prefers_non_rebind_main_over_additional(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(config, "REBIND_PROTECTION", True)
    rebind_main = _result(main=True, rebind=True)
    clean_additional = _result(main=False, rebind=False)

    clean_main = _result(
        main=True,
        rebind=False,
        url="https://other.example.com/dns-query",
    )

    assert _select_winner([rebind_main, clean_additional, clean_main]) is clean_main


def test_resolve_secrets_plain_string():
    assert _resolve_secrets("no placeholders", _Env()) == "no placeholders"


def test_resolve_secrets_substitutes():
    env = _Env(MY_SECRET="secret_value")  # noqa: S106

    assert (
        _resolve_secrets("prefix-${MY_SECRET}-suffix", env)
        == "prefix-secret_value-suffix"
    )


def test_resolve_secrets_missing_raises():
    with pytest.raises(ValueError, match="Missing secret"):
        _resolve_secrets("${MISSING_SECRET}", _Env())


def test_resolve_secrets_multiple_missing_reported():
    with pytest.raises(ValueError, match="AAA") as exc:
        _resolve_secrets("${AAA} ${BBB}", _Env())

    assert "BBB" in str(exc.value)


def test_resolve_secrets_dict():
    env = _Env(TOKEN="abc123")  # noqa: S106

    assert _resolve_secrets({"key": "${TOKEN}", "other": "plain"}, env) == {
        "key": "abc123",
        "other": "plain",
    }


def test_resolve_secrets_list():
    env = _Env(VAL="x")
    assert _resolve_secrets(["${VAL}", "literal"], env) == ["x", "literal"]


def test_resolve_secrets_nested():
    env = _Env(A="1", B="2")
    assert _resolve_secrets({"outer": {"inner": "${A}"}, "list": ["${B}"]}, env) == {
        "outer": {"inner": "1"},
        "list": ["2"],
    }


def test_resolve_secrets_non_string_passthrough():
    assert _resolve_secrets(42, _Env()) == 42
    assert _resolve_secrets(None, _Env()) is None


def test_validate_types_valid():
    _validate_types()


def test_validate_types_wrong_bool(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "DEBUG", "not_a_bool")
    with pytest.raises(TypeError, match="DEBUG"):
        _validate_types()


def test_validate_types_wrong_int(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "TIMEOUT_MS", "5000")
    with pytest.raises(TypeError, match="TIMEOUT_MS"):
        _validate_types()


def test_validate_types_none_skipped(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "LOKI_URL", None)
    _validate_types()


def test_validate_config_no_allowed_domains(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "ALLOWED_DOMAINS", [])
    monkeypatch.setattr(config, "BLOCKLIST_LOADING_POLICY", "block")
    _validate_config()


def test_validate_config_valid(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "ALLOWED_DOMAINS", ["example.com"])
    monkeypatch.setattr(config, "BLOCKLIST_LOADING_POLICY", "block")
    monkeypatch.setattr(
        config,
        "BYPASS_PROVIDER",
        {"url": "https://dns.example.com/dns-query"},
    )

    _validate_config()


def test_validate_config_bypass_missing_url(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "ALLOWED_DOMAINS", ["example.com"])
    monkeypatch.setattr(config, "BLOCKLIST_LOADING_POLICY", "block")
    monkeypatch.setattr(config, "BYPASS_PROVIDER", {})
    with pytest.raises(ValueError, match="url"):
        _validate_config()


def test_validate_config_bypass_empty_url(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "ALLOWED_DOMAINS", ["example.com"])
    monkeypatch.setattr(config, "BLOCKLIST_LOADING_POLICY", "block")
    monkeypatch.setattr(config, "BYPASS_PROVIDER", {"url": ""})
    with pytest.raises(ValueError, match="url"):
        _validate_config()


def test_validate_config_invalid_loading_policy(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "BLOCKLIST_LOADING_POLICY", "typo")
    with pytest.raises(ValueError, match="BLOCKLIST_LOADING_POLICY"):
        _validate_config()


def test_validate_config_bypass_loading_policy(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "ALLOWED_DOMAINS", [])
    monkeypatch.setattr(config, "BLOCKLIST_LOADING_POLICY", "bypass")
    _validate_config()


def test_negotiate_accept_json():
    assert _negotiate_accept("application/dns-json") == "application/dns-json"


def test_negotiate_accept_wire():
    assert _negotiate_accept("application/dns-message") == "application/dns-message"


def test_negotiate_accept_unsupported():
    assert _negotiate_accept("text/html") == ""


def test_negotiate_accept_empty():
    assert _negotiate_accept("") == ""


def test_negotiate_accept_picks_first_supported():
    assert (
        _negotiate_accept("text/html, application/dns-json") == "application/dns-json"
    )


def test_negotiate_accept_with_quality_param():
    assert _negotiate_accept("application/dns-json; q=0.9") == "application/dns-json"


def test_negotiate_accept_wildcard_not_matched():
    assert _negotiate_accept("*/*") == ""


def test_negotiate_accept_case_insensitive():
    assert _negotiate_accept("APPLICATION/DNS-JSON") == "application/dns-json"


def test_handle_health_returns_ok():
    """_handle_health returns {"status": "ok"} with HTTP 200."""
    _handle_health()
    resp_call = _workers_stub.Response.call_args
    body_json = json.loads(resp_call[0][0])
    assert body_json["status"] == "ok"
    assert resp_call[1]["status"] == 200


def test_parse_blocklist_plain_domain():
    """Plain domain lines are parsed as exact matches."""
    exact = parse_blocklist_text("ads.example.com\ntracker.net\n")
    assert exact == {"ads.example.com", "tracker.net"}


def test_parse_blocklist_hosts_format():
    """Hosts-file lines (0.0.0.0 domain) are parsed as exact matches."""
    exact = parse_blocklist_text(
        "0.0.0.0 ads.example.com\n127.0.0.1 tracker.net\n",
    )

    assert exact == {"ads.example.com", "tracker.net"}


def test_parse_blocklist_comments_ignored():
    """Comment lines and inline comments are stripped."""
    text = "# this is a comment\nads.example.com # inline comment\n"
    exact = parse_blocklist_text(text)
    assert exact == {"ads.example.com"}


def test_parse_blocklist_skips_no_dot_entries():
    """Entries without a dot (e.g. localhost) are excluded."""
    text = "0.0.0.0 localhost\nads.example.com\n"
    exact = parse_blocklist_text(text)
    assert exact == {"ads.example.com"}


def test_parse_blocklist_lowercases_domains():
    """Domain names are normalized to lowercase."""
    exact = parse_blocklist_text("ADS.EXAMPLE.COM\n")
    assert exact == {"ads.example.com"}


def test_parse_blocklist_empty_input():
    """Empty input yields empty set."""
    exact = parse_blocklist_text("")
    assert not exact


def test_parse_blocklist_strips_trailing_dot():
    """Trailing dots are stripped from domain names."""
    exact = parse_blocklist_text("ads.example.com.\n")
    assert exact == {"ads.example.com"}


def test_parse_blocklist_mixed_formats():
    """Hosts-file and plain lines both parse correctly together."""
    text = "# OISD-style list\n0.0.0.0 ads.example.com\ntracker.net\n"
    exact = parse_blocklist_text(text)
    assert exact == {"ads.example.com", "tracker.net"}


_BLOCKLIST_SINGLE = json.loads(
    (Path(__file__).parent / "configs" / "blocklist_single.json").read_text(),
)
_BLOCKLIST_SINGLE_BIN = (
    Path(__file__).parent / "configs" / "blocklist_single.bin"
).read_bytes()

_MANIFEST_ENTRY = {
    "bloom_m": _BLOCKLIST_SINGLE["bloom_m"],
    "bloom_k": _BLOCKLIST_SINGLE["bloom_k"],
    "exact_count": _BLOCKLIST_SINGLE["exact_count"],
    "source_urls": ["https://example.com/hosts.txt"],
}


class _FakeArrayBuffer:
    """Minimal stand-in for a JS ArrayBuffer returned by KV.get(..., {type: 'arrayBuffer'})."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def to_bytes(self) -> bytes:
        return self._data


class _FakeMetadata:
    """Minimal stand-in for a JS metadata object returned by KV.getWithMetadata()."""

    def __init__(self, data: dict) -> None:
        self._data = data

    def to_py(self) -> dict:
        return self._data


class _FakeKVResult:
    """Minimal stand-in for the result of KV.getWithMetadata()."""

    def __init__(self, value: object, metadata: object) -> None:
        self.value = value
        self.metadata = metadata


class _MockKV:
    """Minimal KV binding stub for unit tests."""

    def __init__(
        self,
        metadata: dict | None = None,
        bloom_bytes: bytes | None = None,
        raise_error: bool = False,
    ) -> None:
        """
        Initialize the mock KV binding.

        Parameters:
        metadata (dict | None): Metadata dict to return with getWithMetadata(), or None
            to simulate a missing key.
        bloom_bytes (bytes | None): Raw bloom filter bytes for the bloom value.
        raise_error (bool): When True, getWithMetadata() raises RuntimeError to
            simulate a KV failure.
        """
        self._metadata = metadata
        self._bloom_bytes = bloom_bytes
        self._raise = raise_error

        async def _get_with_metadata(key: str, options: object = None) -> object:
            if self._raise:
                raise RuntimeError("KV unavailable")
            value = _FakeArrayBuffer(self._bloom_bytes) if self._bloom_bytes else None
            meta = _FakeMetadata(self._metadata) if self._metadata else None
            return _FakeKVResult(value=value, metadata=meta)

        self.getWithMetadata = _get_with_metadata


def _make_post_request(name: str = "example.com") -> MagicMock:
    """
    Build a minimal mock POST DoH request carrying a wire-format A query.

    Parameters:
    name (str): Domain name to query.

    Returns:
    MagicMock: Mock request object with method, headers, and bytes().
    """
    msg = dns.message.make_query(name, dns.rdatatype.A)
    wire = msg.to_wire()

    req = MagicMock()
    req.method = "POST"

    def _headers_get(key: str, default: object = None) -> object:
        return {
            "accept": "application/dns-message",
            "content-type": "application/dns-message",
            "cf-connecting-ip": "127.0.0.1",
        }.get(key.lower(), default)

    req.headers.get = _headers_get
    req.bytes = AsyncMock(return_value=wire)
    return req


def _minimal_cfg() -> worker._ResolvedConfig:
    """
    Return a minimal _ResolvedConfig suitable for handler unit tests.

    Returns:
    worker._ResolvedConfig: Config with no special endpoints and default providers.
    """
    return worker._ResolvedConfig(
        health_endpoint=None,
        config_endpoint=None,
        loki_url="",
        provider_lists=worker._PROVIDER_LISTS,
        bypass_provider_list=worker._BYPASS_PROVIDER_LIST,
        full_config={},
    )


def test_load_blocklist_from_kv_no_binding_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    When no KV binding is present on env, _load_blocklist_from_kv returns _EMPTY_BLOCKLIST.

    Returns:
    None
    """
    monkeypatch.setattr(worker, "_kv_blocklist_cache", None)
    monkeypatch.setattr(worker, "_kv_blocklist_loading", False)

    env = MagicMock(spec=[])
    result = asyncio.run(worker._load_blocklist_from_kv(env))

    assert result is not None
    assert result.domain_count == 0
    assert not result.check("apple.ca")


def test_load_blocklist_from_kv_kv_error_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    When KV.get() raises, _load_blocklist_from_kv returns _EMPTY_BLOCKLIST rather than
    propagating the error.

    Returns:
    None
    """
    monkeypatch.setattr(worker, "_kv_blocklist_cache", None)
    monkeypatch.setattr(worker, "_kv_blocklist_loading", False)

    env = MagicMock()
    env.BLOCKLIST = _MockKV(raise_error=True)
    result = asyncio.run(worker._load_blocklist_from_kv(env))

    assert result is not None
    assert result.domain_count == 0


def test_load_blocklist_from_kv_blocks_domain_in_filter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    When the manifest contains a bloom filter with apple.ca, check('apple.ca') returns True.

    Returns:
    None
    """
    monkeypatch.setattr(worker, "_kv_blocklist_cache", None)
    monkeypatch.setattr(worker, "_kv_blocklist_loading", False)

    env = MagicMock()
    env.BLOCKLIST = _MockKV(
        metadata=_MANIFEST_ENTRY,
        bloom_bytes=_BLOCKLIST_SINGLE_BIN,
    )
    result = asyncio.run(worker._load_blocklist_from_kv(env))

    assert result is not None
    assert result.check("apple.ca")
    assert result.manifest_urls == ("https://example.com/hosts.txt",)


def test_load_blocklist_from_kv_passes_absent_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    A domain not in the bloom filter does not trigger check().

    Returns:
    None
    """
    monkeypatch.setattr(worker, "_kv_blocklist_cache", None)
    monkeypatch.setattr(worker, "_kv_blocklist_loading", False)

    env = MagicMock()
    env.BLOCKLIST = _MockKV(
        metadata=_MANIFEST_ENTRY,
        bloom_bytes=_BLOCKLIST_SINGLE_BIN,
    )
    result = asyncio.run(worker._load_blocklist_from_kv(env))

    assert result is not None
    assert not result.check("safe.example.net")


def test_load_blocklist_from_kv_concurrent_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    When _kv_blocklist_loading is True (another coroutine is loading), returns None
    so the caller can apply the BLOCKLIST_LOADING_POLICY.

    Returns:
    None
    """
    monkeypatch.setattr(worker, "_kv_blocklist_cache", None)
    monkeypatch.setattr(worker, "_kv_blocklist_loading", True)

    env = MagicMock()
    env.BLOCKLIST = _MockKV(
        metadata=_MANIFEST_ENTRY,
        bloom_bytes=_BLOCKLIST_SINGLE_BIN,
    )
    result = asyncio.run(worker._load_blocklist_from_kv(env))

    assert result is None


class _FakeResponse:
    """
    Minimal stand-in for workers.Response that works with isinstance().

    Using this instead of the MagicMock stub lets worker.py do isinstance(parsed, Response)
    without a TypeError, and lets tests check the returned response's status directly.
    """

    def __init__(
        self,
        body: object = "",
        status: int = 200,
        headers: dict | None = None,
    ) -> None:
        """
        Initialize a fake response.

        Parameters:
        body (object): Response body.
        status (int): HTTP status code.
        headers (dict | None): Optional response headers.
        """
        self.body = body
        self.status = status
        self.headers = headers or {}


def _policy_parsed_result(name: str = "ads.example.com") -> DnsParseResult:
    """
    Build a minimal DnsParseResult representing a successful parse of a query for name.

    Parameters:
    name (str): Domain name being queried.

    Returns:
    DnsParseResult: Parsed result with the given name.
    """
    return DnsParseResult(
        question=Question(name=name, type="A"),
        body_bytes=b"",
        ecs_description="",
        request_wire=None,
        parsed_request=None,
    )


def test_kv_loading_policy_block_returns_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    When BLOCKLIST_LOADING_POLICY is 'block' and the blocklist is still loading,
    _handle_request returns HTTP 503 with Retry-After: 1.

    Returns:
    None
    """
    monkeypatch.setattr(worker, "_kv_blocklist_cache", None)
    monkeypatch.setattr(worker, "_kv_blocklist_loading", True)
    monkeypatch.setattr(config, "BLOCKLIST_LOADING_POLICY", "block")
    monkeypatch.setattr(config, "BLOCKED_DOMAINS", [])
    monkeypatch.setattr(config, "ALLOWED_DOMAINS", [])
    monkeypatch.setattr(config, "CACHE_DNS", False)

    monkeypatch.setattr(worker, "Response", _FakeResponse)

    monkeypatch.setattr(
        worker,
        "_parse_dns_request",
        AsyncMock(return_value=_policy_parsed_result()),
    )

    env = MagicMock()
    env.BLOCKLIST = _MockKV(
        metadata=_MANIFEST_ENTRY,
        bloom_bytes=_BLOCKLIST_SINGLE_BIN,
    )

    response = asyncio.run(
        worker._handle_request(
            request=MagicMock(),
            endpoint="/dns-query",
            doh_providers=next(iter(_minimal_cfg().provider_lists.values())),
            cfg=_minimal_cfg(),
            env=env,
            ctx=MagicMock(),
            parsed_url=urllib.parse.urlparse("https://localhost/dns-query"),
        ),
    )

    assert response.status == 503, f"Expected 503, got {response.status}"
    assert response.headers.get("Retry-After") == "1"


def test_kv_loading_policy_bypass_does_not_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    When BLOCKLIST_LOADING_POLICY is 'bypass' and the blocklist is still loading,
    _handle_request fans out to DNS providers and does not return 503.

    Returns:
    None
    """
    monkeypatch.setattr(worker, "_kv_blocklist_cache", None)
    monkeypatch.setattr(worker, "_kv_blocklist_loading", True)
    monkeypatch.setattr(config, "BLOCKLIST_LOADING_POLICY", "bypass")
    monkeypatch.setattr(config, "BLOCKED_DOMAINS", [])
    monkeypatch.setattr(config, "ALLOWED_DOMAINS", [])
    monkeypatch.setattr(config, "CACHE_DNS", False)

    monkeypatch.setattr(worker, "Response", _FakeResponse)

    monkeypatch.setattr(
        worker,
        "_parse_dns_request",
        AsyncMock(return_value=_policy_parsed_result()),
    )

    monkeypatch.setattr(
        worker,
        "send_doh_requests_fanout",
        AsyncMock(return_value=[_result(failed=False)]),
    )

    response = asyncio.run(
        worker._handle_request(
            request=MagicMock(),
            endpoint="/dns-query",
            doh_providers=next(iter(_minimal_cfg().provider_lists.values())),
            cfg=_minimal_cfg(),
            env=MagicMock(),
            ctx=MagicMock(),
            parsed_url=urllib.parse.urlparse("https://localhost/dns-query"),
        ),
    )

    assert response.status != 503, f"Expected non-503, got {response.status}"


def test_bloom_contains_inserted_domain() -> None:
    """Inserted domain is found in the bloom filter loaded from the static fixture."""
    bit_array = bytearray(_BLOCKLIST_SINGLE_BIN)
    assert _bloom_contains(
        bit_array,
        _BLOCKLIST_SINGLE["bloom_m"],
        _BLOCKLIST_SINGLE["bloom_k"],
        "apple.ca",
    )


def test_bloom_contains_absent_domain() -> None:
    """
    Domain not inserted into the bloom filter is not found.

    Returns:
    None
    """
    bit_array = bytearray(_BLOCKLIST_SINGLE_BIN)
    assert not _bloom_contains(
        bit_array,
        _BLOCKLIST_SINGLE["bloom_m"],
        _BLOCKLIST_SINGLE["bloom_k"],
        "safe.example.net",
    )


_fp_worker_filters: list[tuple[bytes, int, int]] = []


def _init_fp_bloom_worker(all_filters: list[tuple[bytes, int, int]]) -> None:
    global _fp_worker_filters
    _fp_worker_filters = all_filters


def _fp_bloom_chunk(chunk_range: tuple) -> int:
    start, end = chunk_range

    return sum(
        1
        for probe_index in range(start, end)
        if any(
            _bloom_contains(
                bit_array,
                num_bits,
                num_hashes,
                f"{probe_index}.fp-probe.invalid",
            )
            for bit_array, num_bits, num_hashes in _fp_worker_filters
        )
    )


def test_bloom_false_positive_rate() -> None:
    """
    Check that the bloom filter false positive rate stays within the theoretical bound.

    Loads the bloom filter from blocklist/bloom.json and probes 10,000,000
    deterministic absent domains across all CPU cores. The measured rate must not exceed
    the theoretical rate derived from the filter's k, m, and exact_count.

    Returns:
    None
    """
    bloom_json_path = Path(__file__).parent.parent / "blocklist" / "bloom.json"
    bloom_bin_path = Path(__file__).parent.parent / "blocklist" / "bloom.bin"
    bloom_json = json.loads(bloom_json_path.read_text())
    num_hashes = bloom_json["bloom_k"]
    num_bits = bloom_json["bloom_m"]
    exact_count = bloom_json["exact_count"]
    theoretical = (1.0 - math.exp(-num_hashes * exact_count / num_bits)) ** num_hashes
    all_filters = [(bloom_bin_path.read_bytes(), num_bits, num_hashes)]

    num_probes = 10_000_000
    num_workers = os.cpu_count() or 1
    chunk_size = math.ceil(num_probes / num_workers)
    chunks = [
        (i * chunk_size, min((i + 1) * chunk_size, num_probes))
        for i in range(num_workers)
    ]

    with Pool(
        processes=num_workers,
        initializer=_init_fp_bloom_worker,
        initargs=(all_filters,),
    ) as pool:
        false_hits = sum(pool.map(_fp_bloom_chunk, chunks))

    measured = false_hits / num_probes

    assert measured <= theoretical, (
        f"false positive rate {measured:.2e} exceeds theoretical {theoretical:.2e}"
    )


def test_verify_kv_binding_valid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_verify_kv_binding succeeds when wrangler.toml has the BLOCKLIST binding."""
    toml = tmp_path / "wrangler.toml"
    toml.write_text('[[kv_namespaces]]\nbinding = "BLOCKLIST"\n')
    monkeypatch.setattr(upload_blocklist, "_ROOT", tmp_path)
    upload_blocklist._verify_kv_binding()


def test_verify_kv_binding_missing_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_verify_kv_binding exits when wrangler.toml has no BLOCKLIST binding."""
    toml = tmp_path / "wrangler.toml"
    toml.write_text('[[kv_namespaces]]\nbinding = "OTHER_NS"\n')
    monkeypatch.setattr(upload_blocklist, "_ROOT", tmp_path)
    with pytest.raises(SystemExit):
        upload_blocklist._verify_kv_binding()


def test_verify_kv_binding_no_kv_section(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_verify_kv_binding exits when wrangler.toml has no kv_namespaces at all."""
    toml = tmp_path / "wrangler.toml"
    toml.write_text('name = "doh"\n')
    monkeypatch.setattr(upload_blocklist, "_ROOT", tmp_path)
    with pytest.raises(SystemExit):
        upload_blocklist._verify_kv_binding()


def test_verify_kv_binding_no_wrangler_toml(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_verify_kv_binding exits when wrangler.toml does not exist."""
    monkeypatch.setattr(upload_blocklist, "_ROOT", tmp_path)
    with pytest.raises(SystemExit):
        upload_blocklist._verify_kv_binding()
