# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Test configuration for the integration test suite."""

from typing import Literal

from config_types import EcsConfig, EndpointConfig, Provider

DEBUG: bool = False

CONFIG_ENDPOINT: str = "/config"

HEALTH_ENDPOINT: str = "/health"

TIMEOUT_MS: int = 8000

ECS_TRUNCATION: EcsConfig = {
    "enabled": True,
    "ipv4_prefix": 20,
    "ipv6_prefix": 48,
}

REBIND_PROTECTION: bool = True

BLOCKED_DOMAINS: list = [
    "example.com",
]

ALLOWED_DOMAINS: list = [
    "malware.wicar.org",
]

BYPASS_PROVIDER: Provider = {
    "url": "https://cloudflare-dns.com/dns-query",
    "dns_json": True,
}

LOKI_URL: str = ""

LOKI_TIMEOUT_MS: int = 5000

RETRY_MAX_ATTEMPTS: int = 2

CACHE_DNS: bool = True

BLOCKLIST_LOADING_POLICY: Literal["block", "bypass"] = "block"

ENDPOINTS: dict[str, EndpointConfig] = {
    "/my/doh/path": {
        "main_provider": {
            "url": "https://cloudflare-dns.com/dns-query",
            "dns_json": True,
        },
        "additional_providers": [
            {
                "url": "https://dns11.quad9.net/dns-query",
            },
            {
                "url": "https://security.cloudflare-dns.com/dns-query",
                "dns_json": True,
            },
        ],
    },
}
