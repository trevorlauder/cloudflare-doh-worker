# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Unit tests for worker internals (select_winner, secret resolution, validation)."""

import asyncio
import json
import math
from multiprocessing import Pool
import os
from pathlib import Path
from unittest.mock import MagicMock

from conftest import _workers_stub
import pytest

import config
from dns_utils import (
    ProviderResult,
    _bloom_contains,
    _bloom_hash,
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
    _validate_config()


def test_validate_config_valid(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "ALLOWED_DOMAINS", ["example.com"])
    monkeypatch.setattr(
        config,
        "BYPASS_PROVIDER",
        {"url": "https://dns.example.com/dns-query"},
    )

    _validate_config()


def test_validate_config_bypass_missing_url(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "ALLOWED_DOMAINS", ["example.com"])
    monkeypatch.setattr(config, "BYPASS_PROVIDER", {})
    with pytest.raises(ValueError, match="url"):
        _validate_config()


def test_validate_config_bypass_empty_url(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "ALLOWED_DOMAINS", ["example.com"])
    monkeypatch.setattr(config, "BYPASS_PROVIDER", {"url": ""})
    with pytest.raises(ValueError, match="url"):
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


class _FakeAssetResponse:
    """Minimal stand-in for a response from env.ASSETS.fetch()."""

    def __init__(
        self,
        body: str | bytes = b"",
        status: int = 200,
    ) -> None:
        self._body = body
        self.status = status

    async def text(self) -> str:
        if isinstance(self._body, bytes):
            return self._body.decode()
        return self._body

    async def bytes(self) -> bytes:
        if isinstance(self._body, bytes):
            return self._body
        return self._body.encode()


class _MockAssets:
    """Minimal ASSETS binding stub for unit tests."""

    def __init__(
        self,
        json_body: str | None = None,
        bloom_bytes: bytes | None = None,
        raise_error: bool = False,
        json_status: int = 200,
        bin_status: int = 200,
    ) -> None:
        self._json_body = json_body
        self._bloom_bytes = bloom_bytes
        self._raise = raise_error
        self._json_status = json_status
        self._bin_status = bin_status

    async def fetch(self, url: str) -> _FakeAssetResponse:
        if self._raise:
            raise RuntimeError("Assets unavailable")
        if "bloom.json" in url:
            return _FakeAssetResponse(
                body=self._json_body or "",
                status=self._json_status,
            )
        if "bloom.bin" in url:
            return _FakeAssetResponse(
                body=self._bloom_bytes or b"",
                status=self._bin_status,
            )
        return _FakeAssetResponse(status=404)


def test_load_blocklist_from_assets_no_binding_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When no ASSETS binding is present, returns _EMPTY_BLOCKLIST."""
    monkeypatch.setattr(worker, "_blocklist_cache", None)

    env = MagicMock(spec=[])
    result = asyncio.run(worker._load_blocklist_from_assets(env))

    assert result is not None
    assert result.domain_count == 0
    assert not result.check("apple.ca")


def test_load_blocklist_from_assets_fetch_error_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When assets.fetch() raises, returns _EMPTY_BLOCKLIST."""
    monkeypatch.setattr(worker, "_blocklist_cache", None)

    env = MagicMock()
    env.ASSETS = _MockAssets(raise_error=True)
    result = asyncio.run(worker._load_blocklist_from_assets(env))

    assert result is not None
    assert result.domain_count == 0


def test_load_blocklist_from_assets_json_404_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When bloom.json returns non-200, returns _EMPTY_BLOCKLIST."""
    monkeypatch.setattr(worker, "_blocklist_cache", None)

    env = MagicMock()
    env.ASSETS = _MockAssets(json_status=404)
    result = asyncio.run(worker._load_blocklist_from_assets(env))

    assert result is not None
    assert result.domain_count == 0


def test_load_blocklist_from_assets_bin_404_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When bloom.bin returns non-200, returns _EMPTY_BLOCKLIST."""
    monkeypatch.setattr(worker, "_blocklist_cache", None)

    env = MagicMock()
    env.ASSETS = _MockAssets(
        json_body=json.dumps(_BLOCKLIST_SINGLE),
        bin_status=404,
    )
    result = asyncio.run(worker._load_blocklist_from_assets(env))

    assert result is not None
    assert result.domain_count == 0


def test_load_blocklist_from_assets_blocks_domain_in_filter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When assets contain a bloom filter with apple.ca, check('apple.ca') returns True."""
    monkeypatch.setattr(worker, "_blocklist_cache", None)

    manifest = {**_BLOCKLIST_SINGLE, "source_urls": ["https://example.com/hosts.txt"]}
    env = MagicMock()
    env.ASSETS = _MockAssets(
        json_body=json.dumps(manifest),
        bloom_bytes=_BLOCKLIST_SINGLE_BIN,
    )
    result = asyncio.run(worker._load_blocklist_from_assets(env))

    assert result is not None
    assert result.check("apple.ca")
    assert result.manifest_urls == ("https://example.com/hosts.txt",)


def test_load_blocklist_from_assets_passes_absent_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A domain not in the bloom filter does not trigger check()."""
    monkeypatch.setattr(worker, "_blocklist_cache", None)

    env = MagicMock()
    env.ASSETS = _MockAssets(
        json_body=json.dumps(_BLOCKLIST_SINGLE),
        bloom_bytes=_BLOCKLIST_SINGLE_BIN,
    )
    result = asyncio.run(worker._load_blocklist_from_assets(env))

    assert result is not None
    assert not result.check("safe.example.net")


def _build_test_shards(
    domains: list[str],
    shard_count: int,
) -> tuple[dict, dict[int, bytes]]:
    """Build sharded bloom filter test fixtures from a list of domains."""
    from rbloom import Bloom

    buckets: list[set[str]] = [set() for _ in range(shard_count)]
    for domain in domains:
        idx = abs(_bloom_hash(domain)) % shard_count
        buckets[idx].add(domain)

    shard_data: dict[int, bytes] = {}
    shard_m: list[int] = []
    num_hashes: int = 0

    for i, bucket in enumerate(buckets):
        bloom = Bloom(max(len(bucket), 1), 1e-10, _bloom_hash)
        for domain in bucket:
            bloom.add(domain)
        raw = bloom.save_bytes()
        num_hashes = int.from_bytes(raw[:8], "little")
        shard_data[i] = raw[8:]
        shard_m.append(bloom.size_in_bits)

    manifest = {
        "bloom_k": num_hashes,
        "exact_count": len(domains),
        "source_urls": ["https://example.com/hosts.txt"],
        "bloom_shards": shard_count,
        "shard_m": shard_m,
    }
    return manifest, shard_data


class _MockShardedAssets:
    """ASSETS binding stub for sharded bloom filter tests."""

    def __init__(
        self,
        json_body: str | None = None,
        shards: dict[int, bytes] | None = None,
        raise_error: bool = False,
    ) -> None:
        self._json_body = json_body
        self._shards = shards or {}
        self._raise = raise_error

    async def fetch(self, url: str) -> _FakeAssetResponse:
        if self._raise:
            raise RuntimeError("Assets unavailable")
        if "bloom.json" in url:
            return _FakeAssetResponse(body=self._json_body or "", status=200)
        import re as _re

        m = _re.search(r"shard_(\d+)\.bin", url)
        if m:
            idx = int(m.group(1))
            if idx in self._shards:
                return _FakeAssetResponse(body=self._shards[idx], status=200)
            return _FakeAssetResponse(status=404)
        return _FakeAssetResponse(status=404)


def _reset_shard_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear shard cache state to avoid cross-test pollution."""
    monkeypatch.setattr(worker, "_sharded_meta", None)
    worker._shard_cache.clear()
    monkeypatch.setattr(worker, "_shard_pool_used", 0)
    monkeypatch.setattr(worker, "_shard_pool_live", 0)
    monkeypatch.setattr(worker, "_shard_compacted", False)


def test_check_sharded_blocklist_blocks_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sharded lookup finds a domain present in the correct shard."""
    _reset_shard_cache(monkeypatch)

    manifest, shards = _build_test_shards(["apple.ca"], shard_count=4)
    env = MagicMock()
    env.ASSETS = _MockShardedAssets(
        json_body=json.dumps(manifest),
        shards=shards,
    )

    blocked, cache_hit = asyncio.run(worker._check_sharded_blocklist("apple.ca", env))
    assert blocked is True
    assert cache_hit is False


def test_check_sharded_blocklist_passes_absent_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sharded lookup does not match a domain not in any shard."""
    _reset_shard_cache(monkeypatch)

    manifest, shards = _build_test_shards(["apple.ca"], shard_count=4)
    env = MagicMock()
    env.ASSETS = _MockShardedAssets(
        json_body=json.dumps(manifest),
        shards=shards,
    )

    blocked, cache_hit = asyncio.run(
        worker._check_sharded_blocklist("safe.example.net", env),
    )
    assert blocked is False
    assert cache_hit is False


def test_check_sharded_blocklist_missing_shard_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When a shard file returns 404, the check returns False."""
    _reset_shard_cache(monkeypatch)

    manifest, shards = _build_test_shards(["apple.ca"], shard_count=4)
    target_shard = abs(_bloom_hash("apple.ca")) % 4
    del shards[target_shard]

    env = MagicMock()
    env.ASSETS = _MockShardedAssets(
        json_body=json.dumps(manifest),
        shards=shards,
    )

    blocked, cache_hit = asyncio.run(worker._check_sharded_blocklist("apple.ca", env))
    assert blocked is False
    assert cache_hit is False


def test_check_sharded_blocklist_no_assets_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When ASSETS binding is missing, the check returns False."""
    _reset_shard_cache(monkeypatch)

    env = MagicMock(spec=[])
    blocked, cache_hit = asyncio.run(worker._check_sharded_blocklist("apple.ca", env))
    assert blocked is False
    assert cache_hit is False


def test_bloom_contains_inserted_domain() -> None:
    """Inserted domain is found in the bloom filter loaded from the static fixture."""
    bit_array = bytearray(_BLOCKLIST_SINGLE_BIN)
    assert _bloom_contains(
        bit_array=bit_array,
        num_bits=_BLOCKLIST_SINGLE["bloom_m"],
        num_hashes=_BLOCKLIST_SINGLE["bloom_k"],
        hash_value=_bloom_hash("apple.ca"),
    )


def test_bloom_contains_absent_domain() -> None:
    """Domain not inserted into the bloom filter is not found."""
    bit_array = bytearray(_BLOCKLIST_SINGLE_BIN)
    assert not _bloom_contains(
        bit_array=bit_array,
        num_bits=_BLOCKLIST_SINGLE["bloom_m"],
        num_hashes=_BLOCKLIST_SINGLE["bloom_k"],
        hash_value=_bloom_hash("safe.example.net"),
    )


_fp_worker_filters: list[tuple[bytes, int, int]] = []


def _init_fp_bloom_worker(all_filters: list[tuple[bytes, int, int]]) -> None:
    global _fp_worker_filters
    _fp_worker_filters = all_filters


def _fp_bloom_chunk(chunk_range: tuple[int, int]) -> int:
    start, end = chunk_range

    return sum(
        1
        for probe_index in range(start, end)
        if any(
            _bloom_contains(
                bit_array=bit_array,
                num_bits=num_bits,
                num_hashes=num_hashes,
                hash_value=_bloom_hash(f"{probe_index}.fp-probe.invalid"),
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
    """
    blocklist_dir = Path(__file__).parent.parent / "blocklist"
    bloom_json_path = blocklist_dir / "bloom.json"
    bloom_bin_path = blocklist_dir / "bloom.bin"

    bloom_json = json.loads(bloom_json_path.read_text())
    num_hashes = bloom_json["bloom_k"]
    exact_count = bloom_json["exact_count"]

    shard_count = bloom_json.get("bloom_shards", 0)
    if shard_count:
        shard_m_list = bloom_json["shard_m"]
        all_filters = [
            (
                (blocklist_dir / f"shard_{i}.bin").read_bytes(),
                shard_m_list[i],
                num_hashes,
            )
            for i in range(shard_count)
        ]
        num_bits = sum(shard_m_list)
    else:
        num_bits = bloom_json["bloom_m"]
        all_filters = [(bloom_bin_path.read_bytes(), num_bits, num_hashes)]

    theoretical = (1.0 - math.exp(-num_hashes * exact_count / num_bits)) ** num_hashes

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
