#!/bin/bash

set -e

uv run pywrangler dev --ip 0.0.0.0 &
DEV_PID=$!

until curl -sf http://localhost:8787/health > /dev/null 2>&1; do
    sleep 1
done

uv run python scripts/upload_blocklist.py --local

wait $DEV_PID
