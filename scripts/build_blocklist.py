#!/usr/bin/env python3
# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""
Download community block lists and write a single bloom filter file.

Reads URLs from blocklist_sources.yaml, fetches each URL, parses hosts-file
or plain domain-per-line format, deduplicates across all sources, and writes
a single blocklist/bloom.json. The file contains a bloom filter of unique
exact domains and a list of wildcard suffixes merged from all sources.
Use upload_blocklist.py to upload this file to Cloudflare KV.

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
import json
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
_BLOOM_JSON_PATH = _BLOCKLIST_DIR / "bloom.json"
_BLOOM_PATH = _BLOCKLIST_DIR / "bloom.bin"

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


_worker_filters: list[Bloom] = []


def _init_fp_worker(all_bf_bytes: list[bytes]) -> None:
    """Pool initializer: deserialize all filters once per worker process."""
    global _worker_filters
    _worker_filters = [Bloom.load_bytes(raw, _bloom_hash) for raw in all_bf_bytes]


def _fp_check_chunk(start_end: tuple[int, int]) -> int:
    """Multiprocessing worker: count false positive hits for probe indices [start, end) across all filters."""
    start, end = start_end
    return sum(
        1
        for i in range(start, end)
        if any(f"{i}.fp-probe.invalid" in bloom for bloom in _worker_filters)
    )


def _fp_check(filters: list[Bloom], num_probes: int) -> float:
    """
    Empirically measure the false-positive rate across all filters.

    A probe is a false positive if it hits ANY filter, matching the worker's
    runtime behaviour. Probes use the reserved .invalid TLD and are parallelized
    across all available CPU cores.

    Parameters:
    filters (list[Bloom]): All built bloom filters.
    num_probes (int): Number of deterministic probe domains to test.

    Returns:
    float: Measured false-positive rate (false_hits / num_probes).
    """
    all_bf_bytes: list[bytes] = [bloom.save_bytes() for bloom in filters]
    num_workers: int = os.cpu_count() or 1
    chunk_size: int = math.ceil(num_probes / num_workers)
    chunks: list[tuple[int, int]] = [
        (i * chunk_size, min((i + 1) * chunk_size, num_probes))
        for i in range(num_workers)
    ]
    with Pool(
        processes=num_workers,
        initializer=_init_fp_worker,
        initargs=(all_bf_bytes,),
    ) as pool:
        false_hits: int = sum(pool.map(_fp_check_chunk, chunks))
    return false_hits / num_probes


def fetch_and_parse_url(url: str) -> tuple[set[str], set[str], str]:
    """
    Fetch and parse one block list URL into domain sets.

    Filters out bare IP addresses from the exact domain set.

    Parameters:
    url (str): Block list URL to fetch and parse.

    Returns:
    tuple[set[str], set[str], str]: (exact domains, wildcard suffixes with leading dot, raw text)
    """
    text: str = fetch_url(url)
    exact: set[str]
    suffixes: set[str]
    exact, suffixes = parse_blocklist_text(text)
    exact = {domain for domain in exact if not _IP_RE.match(domain)}
    _console.print(
        f"  [green]→ {len(exact):,} exact domains, {len(suffixes):,} wildcard suffixes[/green]",
    )
    return exact, suffixes, text


def build_bloom_json(
    all_exact: set[str],
    all_suffixes: set[str],
    fp_rate: float,
    source_urls: list[str] | None = None,
) -> tuple[str, bytes, int, Bloom]:
    """
    Build a single bloom filter from the deduplicated union of all source domain sets.

    Parameters:
    all_exact (set[str]): Deduplicated set of exact domains across all sources.
    all_suffixes (set[str]): Deduplicated set of wildcard suffixes across all sources.
    fp_rate (float): Target false-positive rate for the bloom filter.
    source_urls (list[str] | None): Original source URLs included in the output for
        traceability. Stored in bloom.json and surfaced via the /config endpoint.

    Returns:
    tuple[str, bytes, int, Bloom]: JSON string for storage in KV, raw bloom bit array,
        number of hash functions (k), and the built bloom filter.
    """
    bloom: Bloom = Bloom(max(len(all_exact), 1), fp_rate, _bloom_hash)
    for domain in all_exact:
        bloom.add(domain)
    raw: bytes = bloom.save_bytes()
    num_hashes: int = int.from_bytes(raw[:8], "little")
    bit_array: bytes = raw[8:]
    num_bits: int = bloom.size_in_bits

    return (
        json.dumps(
            {
                "bloom_m": num_bits,
                "bloom_k": num_hashes,
                "exact_count": len(all_exact),
                "suffixes": sorted(all_suffixes),
                "source_urls": source_urls or [],
            },
            separators=(",", ":"),
        ),
        bit_array,
        num_hashes,
        bloom,
    )


def verify_bloom_filter(
    bit_array: bytes | bytearray,
    num_bits: int,
    num_hashes: int,
    per_source: list[tuple[set[str], set[str]]],
) -> None:
    """
    Verify that every domain from every original source is present in the bloom filter.

    Checks the pre-dedup total (sum of per-source counts), confirming no domain was
    dropped during cross-source deduplication. Exits with an error if any are missing.

    Parameters:
    bit_array (bytes | bytearray): Bloom filter bit array.
    num_bits (int): Number of bits in the filter (m).
    num_hashes (int): Number of hash functions (k).
    per_source (list[tuple[set[str], set[str]]]): Per-source (exact, suffixes) sets as parsed.
    """
    total: int = sum(len(exact) for exact, _ in per_source)
    _console.print(
        f"\n[cyan]Verifying all {total:,} domains from {len(per_source)} source(s) "
        f"against bloom filter ...[/cyan]",
    )
    missed: list[str] = [
        domain
        for exact, _ in per_source
        for domain in exact
        if not _bloom_contains(
            bit_array=bit_array,
            num_bits=num_bits,
            num_hashes=num_hashes,
            domain=domain,
        )
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


def main() -> None:
    """Entry point: download block lists, deduplicate across sources, and write bloom.json."""
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

    from config import BLOCKLIST_ENABLED

    if not BLOCKLIST_ENABLED:
        _console.print(
            "[yellow]BLOCKLIST_ENABLED is False, cleaning up blocklist files.[/yellow]",
        )
        urls: list[str] = []
    else:
        urls = load_urls()

    if not urls:
        if BLOCKLIST_ENABLED:
            _console.print(
                "[yellow]No URLs configured in blocklist_sources.yaml, cleaning up blocklist files.[/yellow]",
            )
        if _BLOCKLIST_DIR.exists():
            for stale in sorted(_BLOCKLIST_DIR.glob("*.txt")):
                stale.unlink()
                _console.print(f"[yellow]Removed {stale.name}[/yellow]")
            for path in (_BLOOM_JSON_PATH, _BLOOM_PATH):
                if path.exists():
                    path.unlink()
                    _console.print(f"[yellow]Removed {path.name}[/yellow]")
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

    per_source: list[tuple[set[str], set[str]]] = []
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
            exact: set[str]
            suffixes: set[str]
            exact, suffixes = parse_blocklist_text(raw_text)
            exact = {domain for domain in exact if not _IP_RE.match(domain)}
            _console.print(
                f"  [green]→ {len(exact):,} exact domains, {len(suffixes):,} wildcard suffixes[/green]",
            )
        else:
            exact, suffixes, raw_text = fetch_and_parse_url(url)
            txt_path.write_text(raw_text, encoding="utf-8")
        per_source.append((exact, suffixes))

    total_before: int = sum(len(exact) for exact, _ in per_source)
    all_exact: set[str] = set().union(*(exact for exact, _ in per_source))
    all_suffixes: set[str] = set().union(*(suffixes for _, suffixes in per_source))
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

    _console.print("[cyan]Building bloom filter ...[/cyan]")
    payload: str
    bit_array: bytes
    num_hashes: int
    bloom: Bloom
    payload, bit_array, num_hashes, bloom = build_bloom_json(
        all_exact=all_exact,
        all_suffixes=all_suffixes,
        fp_rate=args.fp_rate,
        source_urls=urls,
    )

    if args.verify:
        verify_bloom_filter(
            bit_array=bit_array,
            num_bits=bloom.size_in_bits,
            num_hashes=num_hashes,
            per_source=per_source,
        )

    _BLOOM_JSON_PATH.parent.mkdir(exist_ok=True)
    _BLOOM_JSON_PATH.write_text(payload, encoding="utf-8")
    _BLOOM_PATH.write_bytes(bit_array)
    _console.print(
        f"\n[green]Written to {_BLOOM_JSON_PATH.relative_to(_ROOT)}"
        f" and {_BLOOM_PATH.relative_to(_ROOT)}[/green]",
    )

    if args.fp_check > 0:
        filters: list[Bloom] = [bloom]
        num_bits: int = bloom.size_in_bits
        exact_count: int = len(all_exact)
        theoretical: float = (
            1.0 - math.exp(-num_hashes * exact_count / num_bits)
        ) ** num_hashes

        num_workers: int = os.cpu_count() or 1
        _console.print(
            f"\n[cyan]False positive check: probing {args.fp_check:,} deterministic absent domains "
            f"against {exact_count:,} unique domains using {num_workers} core(s) ...[/cyan]",
        )
        start_time: float = time.monotonic()
        measured: float = _fp_check(filters=filters, num_probes=args.fp_check)
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
