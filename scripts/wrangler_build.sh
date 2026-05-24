#!/bin/bash

set -e

if ls blocklist/shard_*.bin 1>/dev/null 2>&1; then
    mkdir -p public
    cp blocklist/shard_*.bin public/
fi
