#!/bin/bash

set -e

if [ -d blocklist ] && [ -n "$CLOUDFLARE_API_TOKEN" ]; then
    uv run python scripts/build_blocklist.py --skip-download
    uv run python scripts/upload_blocklist.py
fi
