# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Unit tests for worker internals (select_winner, secret resolution, validation)."""

import asyncio
import json
import math
from pathlib import Path
import sys
from unittest.mock import MagicMock

from conftest import _workers_stub
import pytest

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
    _ShardedBlocklistMeta,
    _validate_config,
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
    monkeypatch.setattr(worker, "_REBIND_PROTECTION", True)
    rebind = _result(main=True, rebind=True)
    clean = _result(main=False, rebind=False)
    assert _select_winner([rebind, clean]) is clean


def test_select_winner_rebind_kept_when_protection_off(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(worker, "_REBIND_PROTECTION", False)
    rebind = _result(main=True, rebind=True)
    clean = _result(main=False, rebind=False)
    assert _select_winner([rebind, clean]) is rebind


def test_select_winner_rebind_no_clean_alternative_kept(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(worker, "_REBIND_PROTECTION", True)
    rebind = _result(main=True, rebind=True)
    assert _select_winner([rebind]) is rebind


def test_select_winner_prefers_non_rebind_main_over_additional(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(worker, "_REBIND_PROTECTION", True)
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
    _validate_config()


def test_validate_types_wrong_bool(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(worker, "_DEBUG", "not_a_bool")
    with pytest.raises(ValueError, match="DEBUG"):
        _validate_config()


def test_validate_types_wrong_int(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(worker, "_TIMEOUT_MS", "5000")
    with pytest.raises(ValueError, match="TIMEOUT_MS"):
        _validate_config()


def test_validate_config_no_allowed_domains(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(worker, "_ALLOWED_DOMAINS", [])
    _validate_config()


def test_validate_config_valid(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(worker, "_ALLOWED_DOMAINS", ["example.com"])
    monkeypatch.setattr(
        worker,
        "_BYPASS_PROVIDER",
        {"url": "https://dns.example.com/dns-query"},
    )

    _validate_config()


def test_validate_config_bypass_missing_url(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(worker, "_ALLOWED_DOMAINS", ["example.com"])
    monkeypatch.setattr(worker, "_BYPASS_PROVIDER", {})
    with pytest.raises((ValueError, TypeError), match="url"):
        _validate_config()


def test_validate_config_bypass_empty_url(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(worker, "_ALLOWED_DOMAINS", ["example.com"])
    monkeypatch.setattr(worker, "_BYPASS_PROVIDER", {"url": ""})
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


def test_parse_blocklist_adblock_format():
    """Adblock ||domain^ lines are parsed as exact matches."""
    text = "||ads.example.com^\n||tracker.net^\n"
    exact = parse_blocklist_text(text)
    assert exact == {"ads.example.com", "tracker.net"}


def test_parse_blocklist_adblock_with_options():
    """Adblock lines with options (||domain^$option) are parsed."""
    exact = parse_blocklist_text("||ads.example.com^$third-party\n")
    assert exact == {"ads.example.com"}


def test_parse_blocklist_adblock_metadata_skipped():
    """Adblock metadata lines like [Adblock Plus] are skipped."""
    text = "[Adblock Plus]\n! Title: My List\n||ads.example.com^\n"
    exact = parse_blocklist_text(text)
    assert exact == {"ads.example.com"}


def test_parse_blocklist_wildcard_rejected():
    """Wildcard entries are rejected since bloom filters only do exact matching."""
    exact = parse_blocklist_text("*.ads.example.com\n")
    assert exact == set()


def test_parse_blocklist_exclamation_comments():
    """Lines starting with ! are treated as comments."""
    text = "! this is a comment\nads.example.com\n"
    exact = parse_blocklist_text(text)
    assert exact == {"ads.example.com"}


def test_parse_blocklist_dnsmasq_local():
    """DNSMasq local=/domain/ lines are parsed."""
    exact = parse_blocklist_text("local=/ads.example.com/\nlocal=/tracker.net/\n")
    assert exact == {"ads.example.com", "tracker.net"}


def test_parse_blocklist_dnsmasq_address_and_server():
    """DNSMasq address= and server= variants are parsed."""
    text = "address=/ads.example.com/\nserver=/tracker.net/\n"
    exact = parse_blocklist_text(text)
    assert exact == {"ads.example.com", "tracker.net"}


def test_parse_blocklist_mixed_formats():
    """All supported formats parse correctly together."""
    text = (
        "# comment\n"
        "[Adblock Plus]\n"
        "! metadata\n"
        "0.0.0.0 hosts.example.com\n"
        "0.0.0.0 compressed1.example.com compressed2.example.com\n"
        "||adblock.example.com^\n"
        "local=/dnsmasq.example.com/\n"
        "plain.example.org\n"
    )
    exact = parse_blocklist_text(text)
    assert exact == {
        "hosts.example.com",
        "compressed1.example.com",
        "compressed2.example.com",
        "adblock.example.com",
        "dnsmasq.example.com",
        "plain.example.org",
    }


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


def _patch_bloom_meta(monkeypatch: pytest.MonkeyPatch, meta: dict) -> None:
    """Set bloom_meta module attributes from a metadata dict."""
    import bloom_meta

    monkeypatch.setattr(bloom_meta, "bloom_k", meta.get("bloom_k", 0))
    monkeypatch.setattr(bloom_meta, "exact_count", meta.get("exact_count", 0))
    monkeypatch.setattr(bloom_meta, "bloom_shards", meta.get("bloom_shards", 0))
    monkeypatch.setattr(bloom_meta, "source_urls", meta.get("source_urls", []))
    monkeypatch.setattr(bloom_meta, "shard_m", meta.get("shard_m", []))


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


def _meta_from_manifest(manifest: dict) -> _ShardedBlocklistMeta:
    """Build a _ShardedBlocklistMeta from a test manifest dict."""
    shard_count = manifest["bloom_shards"]
    shard_m = tuple(manifest["shard_m"])
    exact_count = manifest["exact_count"]
    bloom_k = manifest["bloom_k"]
    avg_m = sum(shard_m) // shard_count

    fp_rate = (
        (1.0 - math.exp(-bloom_k * exact_count / (avg_m * shard_count))) ** bloom_k
        if exact_count > 0
        else 0.0
    )

    return _ShardedBlocklistMeta(
        bloom_k=bloom_k,
        shard_count=shard_count,
        shard_m=shard_m,
        manifest_urls=tuple(manifest["source_urls"]),
        domain_count=exact_count,
        fp_rate=fp_rate,
    )


class _MockShardedAssets:
    """ASSETS binding stub for sharded bloom filter tests."""

    def __init__(
        self,
        shards: dict[int, bytes] | None = None,
        raise_error: bool = False,
    ) -> None:
        self._shards = shards or {}
        self._raise = raise_error

    async def fetch(self, url: str) -> _FakeAssetResponse:
        if self._raise:
            raise RuntimeError("Assets unavailable")
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
    monkeypatch.setattr(worker, "_shard_cache_used", 0)


def test_check_sharded_blocklist_blocks_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sharded lookup finds a domain present in the correct shard."""
    _reset_shard_cache(monkeypatch)

    manifest, shards = _build_test_shards(["apple.ca"], shard_count=4)
    meta = _meta_from_manifest(manifest)
    env = MagicMock()
    env.ASSETS = _MockShardedAssets(shards=shards)

    blocked, cache_hit = asyncio.run(
        worker._check_sharded_blocklist("apple.ca", env, meta),
    )

    assert blocked is True
    assert cache_hit is False


def test_check_sharded_blocklist_passes_absent_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sharded lookup does not match a domain not in any shard."""
    _reset_shard_cache(monkeypatch)

    manifest, shards = _build_test_shards(["apple.ca"], shard_count=4)
    meta = _meta_from_manifest(manifest)
    env = MagicMock()
    env.ASSETS = _MockShardedAssets(shards=shards)

    blocked, cache_hit = asyncio.run(
        worker._check_sharded_blocklist("safe.example.net", env, meta),
    )

    assert blocked is False
    assert cache_hit is False


def test_check_sharded_blocklist_missing_shard_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When a shard file returns 404, the check returns False."""
    _reset_shard_cache(monkeypatch)

    manifest, shards = _build_test_shards(["apple.ca"], shard_count=4)
    meta = _meta_from_manifest(manifest)
    target_shard = abs(_bloom_hash("apple.ca")) % 4
    del shards[target_shard]

    env = MagicMock()
    env.ASSETS = _MockShardedAssets(shards=shards)

    blocked, cache_hit = asyncio.run(
        worker._check_sharded_blocklist("apple.ca", env, meta),
    )
    assert blocked is False
    assert cache_hit is False


def test_check_sharded_blocklist_no_assets_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When bloom_meta has no shard config, _load_sharded_meta returns None."""
    _reset_shard_cache(monkeypatch)
    _patch_bloom_meta(monkeypatch, {"bloom_k": 0, "bloom_shards": 0})

    meta = worker._load_sharded_meta()
    assert meta is None


def test_bloom_contains_inserted_domain() -> None:
    """Inserted domain is found in the bloom filter built from test shards."""
    manifest, shards = _build_test_shards(["apple.ca"], shard_count=1)
    bit_array = bytearray(shards[0])
    assert _bloom_contains(
        bit_array=bit_array,
        num_bits=manifest["shard_m"][0],
        num_hashes=manifest["bloom_k"],
        hash_value=_bloom_hash("apple.ca"),
    )


def test_bloom_contains_absent_domain() -> None:
    """Domain not inserted into the bloom filter is not found."""
    manifest, shards = _build_test_shards(["apple.ca"], shard_count=1)
    bit_array = bytearray(shards[0])
    assert not _bloom_contains(
        bit_array=bit_array,
        num_bits=manifest["shard_m"][0],
        num_hashes=manifest["bloom_k"],
        hash_value=_bloom_hash("safe.example.net"),
    )


def test_bloom_false_positive_rate() -> None:
    """
    Check that the bloom filter false positive rate stays within the theoretical bound.

    Builds sharded bloom filters and probes 10,000,000 deterministic absent domains
    across all CPU cores. The measured rate must not exceed the theoretical rate.
    """
    sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
    from build_blocklist import (
        _fp_check,
        _parse_raw_text,
        build_sharded_bloom,
        load_urls,
    )

    blocklist_dir = Path(__file__).parent.parent / "blocklist"
    urls = load_urls()
    all_exact: set[str] = set()
    for i in range(len(urls)):
        txt_path = blocklist_dir / f"{i}.txt"
        if not txt_path.exists():
            pytest.skip(f"blocklist/{i}.txt not found")
        all_exact |= _parse_raw_text(txt_path.read_text(encoding="utf-8"))

    estimated_bits = math.ceil(
        -max(len(all_exact), 1) * math.log(1e-10) / (math.log(2) ** 2),
    )
    shard_count = max(1, math.ceil(estimated_bits / 8 / (512 * 1024)))

    meta, shard_bit_arrays = build_sharded_bloom(
        all_exact=all_exact,
        fp_rate=1e-10,
        shard_count=shard_count,
        source_urls=urls,
    )
    exact_count = meta["exact_count"]
    num_hashes = meta["bloom_k"]
    avg_m = sum(meta["shard_m"]) // shard_count

    theoretical = (
        1.0 - math.exp(-num_hashes * (exact_count / shard_count) / avg_m)
    ) ** num_hashes

    num_probes = 10_000_000
    measured = _fp_check(
        shard_bit_arrays=shard_bit_arrays,
        shard_m=meta["shard_m"],
        num_hashes=num_hashes,
        num_probes=num_probes,
    )

    assert measured <= theoretical, (
        f"false positive rate {measured:.2e} exceeds theoretical {theoretical:.2e}"
    )
