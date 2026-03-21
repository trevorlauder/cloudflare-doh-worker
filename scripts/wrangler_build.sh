#!/bin/bash

set -e

if [ -d blocklist ]; then
    uv run python scripts/build_blocklist.py --skip-download
    mkdir -p public
    cp blocklist/bloom.json public/ 2>/dev/null || true
    cp blocklist/bloom.bin public/ 2>/dev/null || true
    cp blocklist/shard_*.bin public/ 2>/dev/null || true
fi
