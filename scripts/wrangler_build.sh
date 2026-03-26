#!/bin/bash

set -e

if [ -d blocklist ]; then
    uv run python scripts/build_blocklist.py --skip-download
    mkdir -p public
    cp blocklist/shard_*.bin public/ 2>/dev/null || true
fi
