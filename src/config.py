# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Configuration for the Cloudflare DoH worker proxy."""

from config_types import EcsConfig, EndpointConfig, Provider

DEBUG: bool = False

CONFIG_ENDPOINT: str = "/config"

HEALTH_ENDPOINT: str = "/health"

TIMEOUT_MS: int = 5000

ECS_TRUNCATION: EcsConfig = {
    "enabled": False,
}

REBIND_PROTECTION: bool = True

BLOCKED_DOMAINS: list = []

ALLOWED_DOMAINS: list = []

BYPASS_PROVIDER: Provider = {
    "url": "https://cloudflare-dns.com/dns-query",
    "dns_json": True,
}

LOKI_URL: str = ""

LOKI_TIMEOUT_MS: int = 5000

RETRY_MAX_ATTEMPTS: int = 2

CACHE_DNS: bool = True

BLOCKLIST_ENABLED: bool = True

ENDPOINTS: dict[str, EndpointConfig] = {
    "/my-device": {
        "main_provider": {
            "url": "https://security.cloudflare-dns.com/dns-query",
            "dns_json": True,
        },
        "additional_providers": [
            {
                "url": "https://dns11.quad9.net/dns-query",
            },
        ],
    },
}
