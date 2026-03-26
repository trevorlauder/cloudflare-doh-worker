#!/usr/bin/env python3
# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""
Download community block lists and build sharded bloom filters.

Reads URLs from blocklist_sources.yaml, fetches each URL, parses hosts-file
or plain domain-per-line format, deduplicates across all sources, and writes
sharded bloom filters of unique exact domains merged from all sources.

Usage:
    uv run python scripts/build_blocklist.py [options]

Options:
    --verify          Re-check every unique domain against the bloom filter after building.
    --fp-check N      Sample N deterministic absent domains and report the empirical
                      false-positive rate. Exits with an error if the measured rate exceeds
                      the theoretical target.
    --skip-download   Re-use existing blocklist/<i>.txt files instead of fetching from
                      the network.
"""

import argparse
import math
from multiprocessing import Pool
import os
from pathlib import Path
import re
import sys
import time
from urllib.request import HTTPHandler, HTTPSHandler, Request, build_opener

from rbloom import Bloom
from rich.console import Console
import yaml

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

_opener = build_opener(HTTPHandler, HTTPSHandler)

_ROOT = Path(__file__).resolve().parents[1]
_SOURCES_PATH = _ROOT / "blocklist_sources.yaml"
_BLOCKLIST_DIR = _ROOT / "blocklist"
_BLOOM_META_PATH = _ROOT / "src" / "bloom_meta.py"
_SHARD_TARGET_BYTES = 512 * 1024  # target shard size: 512 KB

sys.path.insert(0, str(_ROOT / "src"))
from dns_utils import _bloom_contains, _bloom_hash, parse_blocklist_text  # noqa: E402

_console = Console()
_err = Console(stderr=True)


def load_urls() -> list[str]:
    """
    Load block list URLs from blocklist_sources.yaml.

    Returns:
    list[str]: List of URLs.
    """
    if not _SOURCES_PATH.exists():
        _err.print(f"[red]ERROR: {_SOURCES_PATH} not found[/red]")
        raise SystemExit(1)

    data: dict | None = yaml.safe_load(_SOURCES_PATH.read_text(encoding="utf-8"))
    urls: list | object = (data or {}).get("urls", [])

    if not isinstance(urls, list):
        _err.print(
            "[red]ERROR: blocklist_sources.yaml must have a top-level 'urls' list[/red]",
        )

        raise SystemExit(1)

    return [str(url) for url in urls if url]


def fetch_url(url: str) -> str:
    """
    Fetch text content from a URL using urllib.

    Parameters:
    url (str): URL to fetch.

    Returns:
    str: Response body decoded as UTF-8.

    Raises:
    SystemExit: On HTTP or network error.
    """
    _console.print(f"  [cyan]Fetching[/cyan] {url} ...")

    try:
        req: Request = Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; blocklist-builder/1.0)"},
        )
        with _opener.open(req, timeout=30) as response:
            return response.read().decode("utf-8", errors="replace")
    except Exception as e:
        _err.print(f"  [red]ERROR fetching {url}: {e}[/red]")
        raise SystemExit(1) from e


_fp_shard_arrays: list[bytes] = []
_fp_shard_m: list[int] = []
_fp_num_hashes: int = 0


def _init_fp_worker(
    shard_arrays: list[bytes],
    shard_m: list[int],
    num_hashes: int,
) -> None:
    """Pool initializer: store shard data in each worker process."""
    global _fp_shard_arrays, _fp_shard_m, _fp_num_hashes
    _fp_shard_arrays = shard_arrays
    _fp_shard_m = shard_m
    _fp_num_hashes = num_hashes


def _fp_check_chunk(start_end: tuple[int, int]) -> int:
    """Multiprocessing worker: count false positive hits for probe indices [start, end)."""
    start, end = start_end
    shard_count: int = len(_fp_shard_arrays)
    hits: int = 0
    for i in range(start, end):
        probe: str = f"{i}.fp-probe.invalid"
        h: int = _bloom_hash(probe)
        idx: int = abs(h) % shard_count
        if _bloom_contains(
            bit_array=_fp_shard_arrays[idx],
            num_bits=_fp_shard_m[idx],
            num_hashes=_fp_num_hashes,
            hash_value=h,
        ):
            hits += 1
    return hits


def _fp_check(
    shard_bit_arrays: list[bytes],
    shard_m: list[int],
    num_hashes: int,
    num_probes: int,
) -> float:
    """
    Empirically measure the false-positive rate across sharded bloom filters.

    Each probe is checked against its assigned shard, matching the worker's
    runtime behaviour. Probes use the reserved .invalid TLD and are parallelized
    across all available CPU cores.

    Parameters:
    shard_bit_arrays (list[bytes]): List of shard bit arrays.
    shard_m (list[int]): Number of bits per shard.
    num_hashes (int): Number of hash functions (k).
    num_probes (int): Number of deterministic probe domains to test.

    Returns:
    float: Measured false-positive rate (false_hits / num_probes).
    """
    num_workers: int = os.cpu_count() or 1
    chunk_size: int = math.ceil(num_probes / num_workers)
    chunks: list[tuple[int, int]] = [
        (i * chunk_size, min((i + 1) * chunk_size, num_probes))
        for i in range(num_workers)
    ]
    with Pool(
        processes=num_workers,
        initializer=_init_fp_worker,
        initargs=(shard_bit_arrays, shard_m, num_hashes),
    ) as pool:
        false_hits: int = sum(pool.map(_fp_check_chunk, chunks))
    return false_hits / num_probes


def _parse_raw_text(raw_text: str) -> set[str]:
    """Parse raw blocklist text into a domain set, filtering out bare IPs."""
    exact: set[str] = parse_blocklist_text(raw_text)
    exact = {domain for domain in exact if not _IP_RE.match(domain)}
    _console.print(f"  [green]→ {len(exact):,} exact domains[/green]")
    return exact


def build_sharded_bloom(
    all_exact: set[str],
    fp_rate: float,
    shard_count: int,
    source_urls: list[str] | None = None,
) -> tuple[dict, list[bytes]]:
    """
    Build sharded bloom filters by partitioning domains by hash.

    Parameters:
    all_exact (set[str]): Deduplicated set of exact domains.
    fp_rate (float): Target false-positive rate per shard.
    shard_count (int): Number of shards to create.
    source_urls (list[str] | None): Original source URLs for traceability.

    Returns:
    tuple[dict, list[bytes]]: Metadata dict and list of shard bit arrays.
    """
    buckets: list[set[str]] = [set() for _ in range(shard_count)]
    for domain in all_exact:
        idx: int = abs(_bloom_hash(domain)) % shard_count
        buckets[idx].add(domain)

    shard_bit_arrays: list[bytes] = []
    shard_m_values: list[int] = []
    num_hashes: int = 0

    for bucket in buckets:
        bloom: Bloom = Bloom(max(len(bucket), 1), fp_rate, _bloom_hash)
        for domain in bucket:
            bloom.add(domain)

        raw: bytes = bloom.save_bytes()
        num_hashes = int.from_bytes(raw[:8], "little")
        bit_array: bytes = raw[8:]
        shard_m_values.append(bloom.size_in_bits)
        shard_bit_arrays.append(bit_array)

    metadata: dict = {
        "bloom_k": num_hashes,
        "exact_count": len(all_exact),
        "source_urls": source_urls or [],
        "bloom_shards": shard_count,
        "shard_m": shard_m_values,
    }

    return metadata, shard_bit_arrays


_verify_shard_arrays: list[bytes] = []
_verify_shard_m: list[int] = []
_verify_num_hashes: int = 0


def _init_verify_worker(
    shard_arrays: list[bytes],
    shard_m: list[int],
    num_hashes: int,
) -> None:
    """Pool initializer: store shard data in each worker process."""
    global _verify_shard_arrays, _verify_shard_m, _verify_num_hashes
    _verify_shard_arrays = shard_arrays
    _verify_shard_m = shard_m
    _verify_num_hashes = num_hashes


def _verify_chunk(domains: list[str]) -> list[str]:
    """Return any domains from the chunk not found in their assigned shard."""
    shard_count: int = len(_verify_shard_arrays)
    missed: list[str] = []
    for domain in domains:
        h: int = _bloom_hash(domain)
        idx: int = abs(h) % shard_count
        if not _bloom_contains(
            bit_array=_verify_shard_arrays[idx],
            num_bits=_verify_shard_m[idx],
            num_hashes=_verify_num_hashes,
            hash_value=h,
        ):
            missed.append(domain)
    return missed


_VALID_DOMAIN_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$",
)


def verify_bloom_filter(
    shard_bit_arrays: list[bytes],
    shard_m: list[int],
    num_hashes: int,
    per_source: list[set[str]],
) -> None:
    """
    Verify that every domain from every original source is present in its shard.

    First checks that every entry is a valid domain name (lowercase alphanumeric
    labels separated by dots, no leading/trailing hyphens). Then confirms every
    domain is present in its assigned shard. Both checks are parallelized across
    all available CPU cores.

    Parameters:
    shard_bit_arrays (list[bytes]): List of shard bit arrays.
    shard_m (list[int]): Number of bits per shard.
    num_hashes (int): Number of hash functions (k).
    per_source (list[set[str]]): Per-source exact domain sets as parsed.
    """
    all_domains: list[str] = [d for exact in per_source for d in exact]
    total: int = len(all_domains)

    _console.print(
        f"\n[cyan]Checking {total:,} entries are valid domain names ...[/cyan]",
    )
    invalid: list[str] = [d for d in all_domains if not _VALID_DOMAIN_RE.match(d)]
    if invalid:
        _err.print(
            f"[red]ERROR: {len(invalid):,} entry/entries are not valid domain names![/red]",
        )
        for domain in invalid[:20]:
            _err.print(f"  {domain!r}")
        raise SystemExit(1)
    _console.print("[green]OK: all entries are valid domain names.[/green]")
    num_workers: int = os.cpu_count() or 1
    _console.print(
        f"\n[cyan]Verifying all {total:,} domains from {len(per_source)} source(s) "
        f"against {len(shard_bit_arrays)} shard(s) using {num_workers} workers ...[/cyan]",
    )
    chunk_size: int = math.ceil(total / num_workers)
    chunks: list[list[str]] = [
        all_domains[i * chunk_size : (i + 1) * chunk_size] for i in range(num_workers)
    ]
    with Pool(
        processes=num_workers,
        initializer=_init_verify_worker,
        initargs=(shard_bit_arrays, shard_m, num_hashes),
    ) as pool:
        missed: list[str] = [
            domain for result in pool.map(_verify_chunk, chunks) for domain in result
        ]
    if missed:
        _err.print(
            f"[red]ERROR: {len(missed):,} domain(s) NOT found in bloom filter![/red]",
        )
        for domain in missed[:20]:
            _err.print(f"  {domain}")
        raise SystemExit(1)
    _console.print(
        f"[green]OK: all {total:,} domains confirmed present (zero false negatives).[/green]",
    )


def _write_bloom_meta(meta: dict) -> None:
    """Write bloom_meta.py with bloom filter metadata."""
    content: str = (
        "# Copyright 2025-2026 Trevor Lauder.\n"
        "# SPDX-License-Identifier: MIT\n"
        "\n"
        "# Generated by scripts/build_blocklist.py\n"
        "# Do not edit manually\n"
        "\n"
        f"bloom_k: int = {meta.get('bloom_k', 0)}\n"
        f"exact_count: int = {meta.get('exact_count', 0)}\n"
        f"bloom_shards: int = {meta.get('bloom_shards', 0)}\n"
        f"source_urls: list[str] = {meta.get('source_urls', [])}\n"
        f"shard_m: list[int] = {meta.get('shard_m', [])}\n"
    )
    if (
        _BLOOM_META_PATH.exists()
        and _BLOOM_META_PATH.read_text(encoding="utf-8") == content
    ):
        return
    _BLOOM_META_PATH.write_text(content, encoding="utf-8")


def main() -> None:
    """Entry point: download block lists, deduplicate across sources, and build bloom filter."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--verify",
        action="store_true",
        help="After building the bloom filter, re-check every unique domain to confirm zero false negatives.",
    )

    parser.add_argument(
        "--fp-check",
        type=int,
        default=0,
        metavar="N",
        help="Probe N deterministic absent domains and report the empirical false-positive rate.",
    )

    parser.add_argument(
        "--fp-rate",
        type=float,
        default=1e-10,
        metavar="RATE",
        help="Target false-positive rate for the bloom filter (default: 1e-10).",
    )

    parser.add_argument(
        "--skip-download",
        action="store_true",
        help="Re-use existing blocklist/<i>.txt files instead of fetching from the network.",
    )

    args = parser.parse_args()

    import config

    blocklist_enabled: bool = getattr(config, "BLOCKLIST_ENABLED", True)

    if not blocklist_enabled:
        _console.print(
            "[yellow]BLOCKLIST_ENABLED is False, cleaning up blocklist files.[/yellow]",
        )
        urls: list[str] = []
    else:
        urls = load_urls()

    if not urls:
        if blocklist_enabled:
            _console.print(
                "[yellow]No URLs configured in blocklist_sources.yaml, cleaning up blocklist files.[/yellow]",
            )
        if _BLOCKLIST_DIR.exists():
            for stale in sorted(_BLOCKLIST_DIR.glob("*.txt")):
                stale.unlink()
                _console.print(f"[yellow]Removed {stale.name}[/yellow]")
            for stale in sorted(_BLOCKLIST_DIR.glob("shard_*.bin")):
                stale.unlink()
                _console.print(f"[yellow]Removed {stale.name}[/yellow]")
        return

    _BLOCKLIST_DIR.mkdir(exist_ok=True)

    if args.skip_download:
        txt_count: int = len(list(_BLOCKLIST_DIR.glob("*.txt")))
        if txt_count != len(urls):
            _err.print(
                f"[red]ERROR: blocklist/ has {txt_count} .txt file(s) "
                f"but blocklist_sources.yaml has {len(urls)} URL(s)[/red]",
            )
            raise SystemExit(1)

    for stale in sorted(_BLOCKLIST_DIR.glob("*.txt")):
        try:
            if int(stale.stem) >= len(urls):
                stale.unlink()
                _console.print(f"[yellow]Removed stale {stale.name}[/yellow]")
        except ValueError:
            pass

    per_source: list[set[str]] = []
    for i, url in enumerate(urls):
        _console.print(f"\n[bold cyan]\\[{i}][/bold cyan] {url}")
        txt_path: Path = _BLOCKLIST_DIR / f"{i}.txt"
        if args.skip_download:
            if not txt_path.exists():
                _err.print(
                    f"  [red]ERROR: {txt_path} not found; run without --skip-download first[/red]",
                )
                raise SystemExit(1)
            _console.print("  [yellow]Using cached file[/yellow]")
            raw_text: str = txt_path.read_text(encoding="utf-8")
        else:
            raw_text = fetch_url(url)
            txt_path.write_text(raw_text, encoding="utf-8")
        per_source.append(_parse_raw_text(raw_text))

    total_before: int = sum(len(exact) for exact in per_source)
    all_exact: set[str] = set().union(*per_source)
    total_after: int = len(all_exact)
    removed: int = total_before - total_after
    removed_pct: float = removed / total_before * 100 if total_before else 0.0

    dedup_msg: str = (
        f"\n[bold]Deduplication:[/bold] {total_before:,} total across {len(urls)} source(s)"
        f" → [green]{total_after:,} unique[/green]"
    )
    if removed:
        dedup_msg += (
            f" ([yellow]{removed:,} duplicates removed, {removed_pct:.1f}%[/yellow])"
        )
    _console.print(dedup_msg)

    for stale in sorted(_BLOCKLIST_DIR.glob("shard_*.bin")):
        stale.unlink()

    # Estimate total filter size to determine shard count
    n: int = max(len(all_exact), 1)
    estimated_bits: int = math.ceil(-n * math.log(args.fp_rate) / (math.log(2) ** 2))
    estimated_bytes: int = math.ceil(estimated_bits / 8)
    shard_count: int = max(1, math.ceil(estimated_bytes / _SHARD_TARGET_BYTES))

    if estimated_bytes >= 1024 * 1024:
        size_str = f"{estimated_bytes / (1024 * 1024):.1f} MB"
    else:
        size_str = f"{estimated_bytes / 1024:.1f} KB"

    _console.print(
        f"\n[cyan]Building bloom filter ({size_str} estimated, "
        f"{shard_count} shard(s)) ...[/cyan]",
    )

    meta: dict
    meta, shard_bit_arrays = build_sharded_bloom(
        all_exact=all_exact,
        fp_rate=args.fp_rate,
        shard_count=shard_count,
        source_urls=urls,
    )

    for i, shard_data in enumerate(shard_bit_arrays):
        (_BLOCKLIST_DIR / f"shard_{i}.bin").write_bytes(shard_data)

    _console.print(
        f"[green]Written to {shard_count} shard(s) in {_BLOCKLIST_DIR.relative_to(_ROOT)}/[/green]",
    )

    _write_bloom_meta(meta)

    if args.verify:
        verify_bloom_filter(
            shard_bit_arrays=shard_bit_arrays,
            shard_m=meta["shard_m"],
            num_hashes=meta["bloom_k"],
            per_source=per_source,
        )

    if args.fp_check > 0:
        exact_count: int = len(all_exact)
        avg_m: int = sum(meta["shard_m"]) // shard_count
        theoretical: float = (
            1.0 - math.exp(-meta["bloom_k"] * (exact_count / shard_count) / avg_m)
        ) ** meta["bloom_k"]

        num_workers: int = os.cpu_count() or 1

        _console.print(
            f"\n[cyan]False positive check: probing {args.fp_check:,} deterministic absent domains "
            f"against {exact_count:,} unique domains using {num_workers} core(s) ...[/cyan]",
        )

        start_time: float = time.monotonic()
        measured: float = _fp_check(
            shard_bit_arrays=shard_bit_arrays,
            shard_m=meta["shard_m"],
            num_hashes=meta["bloom_k"],
            num_probes=args.fp_check,
        )
        elapsed: float = time.monotonic() - start_time

        _console.print(
            f"  Theoretical false positive rate: {theoretical:.2e}  |  Measured: {measured:.2e}"
            f"  ({int(measured * args.fp_check)} hits / {args.fp_check:,} probes)"
            f"  [{elapsed:.1f}s]",
        )

        if measured > theoretical:
            _err.print(
                f"  [red]ERROR: measured false positive rate {measured:.2e} exceeds theoretical "
                f"{theoretical:.2e}[/red]",
            )

            raise SystemExit(1)

        _console.print(
            f"  [green]OK: measured false positive rate {measured:.2e} within theoretical {theoretical:.2e}.[/green]",
        )


if __name__ == "__main__":
    main()
