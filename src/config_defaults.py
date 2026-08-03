# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Single source of truth for optional config values with defaults."""

import config

PATH_PREFIX: str = getattr(config, "PATH_PREFIX", "/")
DEBUG: bool = getattr(config, "DEBUG", False)
TIMEOUT_MS: int = getattr(config, "TIMEOUT_MS", 5000)
LOKI_TIMEOUT_MS: int = getattr(config, "LOKI_TIMEOUT_MS", 5000)
RETRY_MAX_ATTEMPTS: int = getattr(config, "RETRY_MAX_ATTEMPTS", 2)
FANOUT_DRAIN_TIMEOUT_MS: int = getattr(config, "FANOUT_DRAIN_TIMEOUT_MS", 10000)
CACHE_DNS: bool = getattr(config, "CACHE_DNS", True)
BLOCKLIST_ENABLED: bool = getattr(config, "BLOCKLIST_ENABLED", True)
LOKI_URL: str = getattr(config, "LOKI_URL", "")
REBIND_PROTECTION: bool = getattr(config, "REBIND_PROTECTION", True)
ALLOWED_DOMAINS: list = getattr(config, "ALLOWED_DOMAINS", [])
BLOCKED_DOMAINS: list = getattr(config, "BLOCKED_DOMAINS", [])
ECS_TRUNCATION: dict = getattr(config, "ECS_TRUNCATION", {"enabled": False})

BYPASS_PROVIDER: dict = getattr(
    config,
    "BYPASS_PROVIDER",
    {
        "url": "https://cloudflare-dns.com/dns-query",
        "dns_json": True,
    },
)
