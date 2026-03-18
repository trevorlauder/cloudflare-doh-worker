#!/usr/bin/env python3
# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""
Upload block list data to Cloudflare KV as a single manifest key.

Loads blocklist/bloom.json (built by build_blocklist.py) and uploads it
as a single blocklist:manifest KV key with all bloom filter data embedded.
A SHA-256 hash is checked before uploading. Unchanged content is skipped.

Usage:
    uv run python scripts/upload_blocklist.py [options]

Options:
    --dry-run       Print what would be uploaded or deleted without making changes.
    --local         Upload to the local wrangler dev KV store (omits --remote).

Prerequisites:
    A KV namespace must exist and be bound in wrangler.toml as BLOCK_LIST.
    The namespace must be dedicated exclusively to blocklist data. Any key
    that is not blocklist:manifest or blocklist:manifest.hash will be deleted
    on every run. Do not store unrelated keys in this namespace.
    wrangler (uv run pywrangler) must be available on PATH.
    Run scripts/build_blocklist.py first to generate blocklist/bloom.json.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib

from rich.console import Console

_console = Console()
_err = Console(stderr=True)

_ROOT = Path(__file__).resolve().parents[1]
_BINDING = "BLOCK_LIST"


def _verify_kv_binding() -> None:
    """
    Verify that wrangler.toml contains a KV namespace bound to BLOCK_LIST.

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


def get_kv_hash(binding: str, hash_key: str, *, remote: bool = True) -> str | None:
    """
    Fetch the stored content hash from KV, if it exists.

    Parameters:
    binding (str): KV namespace binding name.
    hash_key (str): KV key holding the stored hash.
    remote (bool): If True, target the Cloudflare edge. If False, target local dev KV.

    Returns:
    str | None: The stored hash string, or None if not found or on error.
    """
    result = _pywrangler(
        "kv",
        "key",
        "get",
        "--binding",
        binding,
        hash_key,
        remote=remote,
        capture=True,
    )

    if result.returncode != 0:
        return None

    return result.stdout.strip() or None


def upload_to_kv(text: str, binding: str, key: str, *, remote: bool = True) -> None:
    """
    Upload text to Cloudflare KV using wrangler.

    Parameters:
    text (str): Content to upload.
    binding (str): KV namespace binding name (must match wrangler.toml).
    key (str): KV key name to write.
    remote (bool): Pass False to target local dev KV instead of the Cloudflare edge.

    Raises:
    SystemExit: If wrangler exits with a non-zero code.
    """
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".txt",
        delete=False,
        encoding="utf-8",
    ) as f:
        f.write(text)
        tmp_path = Path(f.name)

    _upload_path_to_kv(tmp_path, binding=binding, key=key, remote=remote)


def upload_bytes_to_kv(
    data: bytes,
    binding: str,
    key: str,
    *,
    remote: bool = True,
) -> None:
    """
    Upload raw bytes to Cloudflare KV using wrangler.

    Parameters:
    data (bytes): Binary content to upload.
    binding (str): KV namespace binding name (must match wrangler.toml).
    key (str): KV key name to write.
    remote (bool): Pass False to target local dev KV instead of the Cloudflare edge.

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

    _upload_path_to_kv(tmp_path, binding=binding, key=key, remote=remote)


def _upload_path_to_kv(
    tmp_path: Path,
    binding: str,
    key: str,
    *,
    remote: bool = True,
) -> None:
    """
    Upload a file at tmp_path to Cloudflare KV, then delete the temp file.

    Raises:
    SystemExit: If wrangler exits with a non-zero code.
    """

    target: str = "remote" if remote else "local"

    _console.print(
        f"\n[cyan]Uploading to KV binding={binding!r} key={key!r} ({target}) ...[/cyan]",
    )

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


def main() -> None:
    """
    Entry point: build a single manifest with embedded bloom data and upload to KV.
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

    bloom_json_path: Path = _ROOT / "blocklist" / "bloom.json"
    if not bloom_json_path.exists():
        _err.print(
            "[red]ERROR: missing blocklist/bloom.json (run build_blocklist.py to generate)[/red]",
        )
        raise SystemExit(1)

    bloom_path: Path = _ROOT / "blocklist" / "bloom.bin"
    if not bloom_path.exists():
        _err.print(
            "[red]ERROR: missing blocklist/bloom.bin (run build_blocklist.py to generate)[/red]",
        )
        raise SystemExit(1)

    entry: dict = json.loads(bloom_json_path.read_text(encoding="utf-8"))
    bloom_bytes: bytes = bloom_path.read_bytes()
    manifest: list[dict] = [entry]

    manifest_key: str = "blocklist:manifest"
    bloom_key: str = "blocklist:bloom"
    manifest_json: str = json.dumps(manifest, separators=(",", ":"))
    manifest_hash_key: str = f"{manifest_key}.hash"
    content_hash: str = hashlib.sha256(manifest_json.encode()).hexdigest()

    stored_hash: str | None = get_kv_hash(
        binding=_BINDING,
        hash_key=manifest_hash_key,
        remote=remote,
    )
    if stored_hash == content_hash:
        _console.print(f"[yellow]{manifest_key} unchanged, skipping upload.[/yellow]")
    elif args.dry_run:
        _console.print(
            f"[yellow]Would upload {manifest_key} ({len(manifest_json)} bytes)[/yellow]",
        )
        _console.print(
            f"[yellow]Would upload {bloom_key} ({len(bloom_bytes):,} bytes binary)[/yellow]",
        )
    else:
        upload_to_kv(
            text=manifest_json,
            binding=_BINDING,
            key=manifest_key,
            remote=remote,
        )
        upload_bytes_to_kv(
            data=bloom_bytes,
            binding=_BINDING,
            key=bloom_key,
            remote=remote,
        )
        upload_to_kv(
            text=content_hash,
            binding=_BINDING,
            key=manifest_hash_key,
            remote=remote,
        )

    known_keys: set[str] = {manifest_key, bloom_key, manifest_hash_key}

    list_result: subprocess.CompletedProcess[str] = _pywrangler(
        "kv",
        "key",
        "list",
        "--binding",
        _BINDING,
        remote=remote,
        capture=True,
    )

    if list_result.returncode == 0 and list_result.stdout.strip():
        try:
            all_keys: list[str] = [
                entry["name"] for entry in json.loads(list_result.stdout)
            ]
        except Exception:
            _err.print(
                "[yellow]WARNING: failed to parse KV key list; skipping stale key cleanup[/yellow]",
            )
            all_keys: list[str] = []
        for key in all_keys:
            if key not in known_keys:
                if args.dry_run:
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


if __name__ == "__main__":
    main()
