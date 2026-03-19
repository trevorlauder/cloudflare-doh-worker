#!/usr/bin/env python3
# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""
Upload block list data to Cloudflare KV.

Loads blocklist/bloom.json and blocklist/bloom.bin (built by build_blocklist.py)
and uploads the bloom binary as the blocklist:bloom KV value with manifest fields
and a SHA-256 content hash stored as KV metadata (retrieved in a single
getWithMetadata call by the worker). The hash in the metadata is compared via
kv key list to skip redundant uploads when content has not changed.

Usage:
    uv run python scripts/upload_blocklist.py [options]

Options:
    --dry-run       Print what would be uploaded or deleted without making changes.
    --local         Upload to the local wrangler dev KV store (omits --remote).

Prerequisites:
    A KV namespace must exist and be bound in wrangler.toml as BLOCKLIST.
    The namespace must be dedicated exclusively to blocklist data. Any key
    that is not blocklist:bloom will be deleted on every run. Do not store
    unrelated keys in this namespace.
    wrangler (uv run pywrangler) must be available on PATH.
    Run scripts/build_blocklist.py first to generate blocklist/bloom.json
    and blocklist/bloom.bin.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

from rich.console import Console

_console = Console()
_err = Console(stderr=True)

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))
_BINDING = "BLOCKLIST"


def _verify_kv_binding() -> None:
    """
    Verify that wrangler.toml contains a KV namespace bound to BLOCKLIST.

    Exits with an error if the binding is missing, preventing accidental
    operations against the wrong namespace.
    """
    wrangler_path: Path = _ROOT / "wrangler.toml"
    if not wrangler_path.exists():
        _err.print("[red]ERROR: wrangler.toml not found[/red]")
        raise SystemExit(1)

    wrangler: dict = tomllib.loads(wrangler_path.read_text(encoding="utf-8"))
    kv_namespaces: list[dict] = wrangler.get("kv_namespaces", [])
    bindings: set[str | None] = {ns.get("binding") for ns in kv_namespaces}

    if _BINDING not in bindings:
        _err.print(
            f"[red]ERROR: wrangler.toml has no KV namespace with binding={_BINDING!r}. "
            f"Found bindings: {sorted(bindings) or '(none)'}[/red]",
        )
        raise SystemExit(1)


def _pywrangler(
    *args: str,
    remote: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    """
    Run a pywrangler subcommand via uv.

    Parameters:
    args (str): Subcommand and arguments to pass to pywrangler.
    remote (bool): If True, append --remote to the command.
    capture (bool): If True, capture stdout/stderr as text instead of printing.

    Returns:
    subprocess.CompletedProcess[str]: The completed process result.
    """
    cmd: tuple[str, ...] = (
        "uv",
        "run",
        "--frozen",
        "pywrangler",
        *args,
        *(("--remote",) if remote else ()),
    )

    env: dict[str, str] = {**os.environ, "PYWRANGLER_LOG": "error"}
    return subprocess.run(
        cmd,
        cwd=str(_ROOT),
        check=False,
        capture_output=capture,
        text=capture,
        env=env,
    )


def _list_kv_entries(*, remote: bool) -> list[dict]:
    """
    List all key entries in the KV namespace.

    Returns the parsed JSON array from wrangler, where each entry has at least
    a "name" field and optionally a "metadata" field.

    Parameters:
    remote (bool): Target Cloudflare edge if True, local dev KV if False.

    Returns:
    list[dict]: Parsed key entries, or empty list on error.
    """
    result: subprocess.CompletedProcess[str] = _pywrangler(
        "kv",
        "key",
        "list",
        "--binding",
        _BINDING,
        remote=remote,
        capture=True,
    )

    if not (result.returncode == 0 and result.stdout.strip()):
        return []

    try:
        return json.loads(result.stdout)
    except Exception:
        _err.print(
            "[yellow]WARNING: failed to parse KV key list[/yellow]",
        )
        return []


def upload_bytes_to_kv(
    data: bytes,
    binding: str,
    key: str,
    *,
    remote: bool = True,
    metadata: str | None = None,
) -> None:
    """
    Upload raw bytes to Cloudflare KV using wrangler.

    Parameters:
    data (bytes): Binary content to upload.
    binding (str): KV namespace binding name (must match wrangler.toml).
    key (str): KV key name to write.
    remote (bool): Pass False to target local dev KV instead of the Cloudflare edge.
    metadata (str | None): Optional JSON metadata string to attach to the key.

    Raises:
    SystemExit: If wrangler exits with a non-zero code.
    """
    with tempfile.NamedTemporaryFile(
        mode="wb",
        suffix=".bin",
        delete=False,
    ) as f:
        f.write(data)
        tmp_path = Path(f.name)

    _upload_path_to_kv(
        tmp_path,
        binding=binding,
        key=key,
        remote=remote,
        metadata=metadata,
    )


def _upload_path_to_kv(
    tmp_path: Path,
    binding: str,
    key: str,
    *,
    remote: bool = True,
    metadata: str | None = None,
) -> None:
    """
    Upload a file at tmp_path to Cloudflare KV, then delete the temp file.

    Parameters:
    tmp_path (Path): Path to the temporary file to upload.
    binding (str): KV namespace binding name.
    key (str): KV key name to write.
    remote (bool): Target Cloudflare edge if True, local dev KV if False.
    metadata (str | None): Optional JSON metadata string to attach to the key.

    Raises:
    SystemExit: If wrangler exits with a non-zero code.
    """

    target: str = "remote" if remote else "local"

    _console.print(
        f"\n[cyan]Uploading to KV binding={binding!r} key={key!r} ({target}) ...[/cyan]",
    )

    metadata_args: tuple[str, ...] = ("--metadata", metadata) if metadata else ()

    try:
        result = _pywrangler(
            "kv",
            "key",
            "put",
            "--binding",
            binding,
            key,
            "--path",
            str(tmp_path),
            *metadata_args,
            remote=remote,
            capture=True,
        )
    finally:
        tmp_path.unlink(missing_ok=True)

    if result.returncode != 0:
        _err.print(f"[red]ERROR: wrangler exited with code {result.returncode}[/red]")

        if result.stderr:
            _err.print(result.stderr.strip())

        raise SystemExit(result.returncode)

    _console.print("[green]Upload complete.[/green]")


def _upload_blocklist(
    args: argparse.Namespace,
    *,
    remote: bool,
    kv_entries: list[dict],
) -> set[str]:
    """
    Upload blocklist data to KV if bloom files exist and content has changed.

    Parameters:
    args (argparse.Namespace): Parsed CLI arguments (uses dry_run).
    remote (bool): Target Cloudflare edge if True, local dev KV if False.
    kv_entries (list[dict]): Existing KV key entries from _list_kv_entries().

    Returns:
    set[str]: The set of KV keys that should be kept (not deleted).
    """
    bloom_json_path: Path = _ROOT / "blocklist" / "bloom.json"
    bloom_path: Path = _ROOT / "blocklist" / "bloom.bin"

    if not (bloom_json_path.exists() and bloom_path.exists()):
        _console.print(
            "[yellow]No blocklist files found, will delete all keys from KV.[/yellow]",
        )
        return set()

    entry: dict = json.loads(bloom_json_path.read_text(encoding="utf-8"))
    bloom_bytes: bytes = bloom_path.read_bytes()

    bloom_key: str = "blocklist:bloom"
    content_hash: str = hashlib.sha256(bloom_bytes).hexdigest()
    entry["hash"] = content_hash
    metadata_json: str = json.dumps(entry, separators=(",", ":"))

    metadata_size: int = len(metadata_json.encode())
    if metadata_size > 1024:
        _err.print(
            f"[red]ERROR: KV metadata is {metadata_size} bytes, exceeds 1024-byte limit. "
            f"Reduce the number of source URLs.[/red]",
        )
        raise SystemExit(1)

    stored_hash: str | None = None
    for kv_entry in kv_entries:
        if kv_entry.get("name") == bloom_key:
            metadata: dict = kv_entry.get("metadata") or {}
            stored_hash = metadata.get("hash")
            break

    if stored_hash == content_hash:
        _console.print(
            f"[yellow]{bloom_key} unchanged, skipping upload.[/yellow]",
        )
    elif args.dry_run:
        _console.print(
            f"[yellow]Would upload {bloom_key} ({len(bloom_bytes):,} bytes binary, "
            f"{metadata_size} bytes metadata)[/yellow]",
        )
    else:
        upload_bytes_to_kv(
            data=bloom_bytes,
            binding=_BINDING,
            key=bloom_key,
            remote=remote,
            metadata=metadata_json,
        )

    return {bloom_key}


def _delete_unknown_keys(
    known_keys: set[str],
    *,
    dry_run: bool,
    remote: bool,
    kv_entries: list[dict],
) -> None:
    """
    Delete any keys not in known_keys from the KV namespace.

    Parameters:
    known_keys (set[str]): Keys that should be preserved.
    dry_run (bool): If True, print what would be deleted without making changes.
    remote (bool): Target Cloudflare edge if True, local dev KV if False.
    kv_entries (list[dict]): Existing KV key entries from _list_kv_entries().
    """
    for kv_entry in kv_entries:
        key: str = kv_entry.get("name", "")
        if key and key not in known_keys:
            if dry_run:
                _console.print(f"[yellow]Would delete stale key {key}[/yellow]")
            else:
                _console.print(f"[cyan]Deleting stale key {key} from KV ...[/cyan]")
                _pywrangler(
                    "kv",
                    "key",
                    "delete",
                    "--binding",
                    _BINDING,
                    key,
                    remote=remote,
                    capture=True,
                )


def main() -> None:
    """
    Entry point: upload bloom binary with metadata to KV.
    """
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be uploaded/deleted without making changes.",
    )

    parser.add_argument(
        "--local",
        action="store_true",
        help="Upload to local dev KV (omits --remote). For use with wrangler dev.",
    )

    args = parser.parse_args()

    remote: bool = not args.local

    _verify_kv_binding()

    from config import BLOCKLIST_ENABLED

    kv_entries: list[dict] = _list_kv_entries(remote=remote)

    if not BLOCKLIST_ENABLED:
        _console.print(
            "[yellow]BLOCKLIST_ENABLED is False, deleting all keys from KV.[/yellow]",
        )
        known_keys: set[str] = set()
    else:
        known_keys = _upload_blocklist(args=args, remote=remote, kv_entries=kv_entries)

    _delete_unknown_keys(
        known_keys=known_keys,
        dry_run=args.dry_run,
        remote=remote,
        kv_entries=kv_entries,
    )


if __name__ == "__main__":
    main()
