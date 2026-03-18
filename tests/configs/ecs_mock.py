# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Test configuration using the mock DoH server with custom ECS prefixes."""

from typing import Literal

from config_types import EcsConfig, EndpointConfig, Provider

DEBUG: bool = True

CONFIG_ENDPOINT: str = "/config"

HEALTH_ENDPOINT: str = "/health"

TIMEOUT_MS: int = 5000

ECS_TRUNCATION: EcsConfig = {
    "enabled": True,
    "ipv4_prefix": 20,
    "ipv6_prefix": 48,
}

REBIND_PROTECTION: bool = False

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

BLOCKLIST_LOADING_POLICY: Literal["block", "bypass"] = "block"

ENDPOINTS: dict[str, EndpointConfig] = {
    "/my-device": {
        "main_provider": {
            "url": "http://mock-doh:8080/dns-query",
        },
    },
}
