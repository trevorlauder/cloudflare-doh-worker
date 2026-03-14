# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Test configuration for the integration test suite."""

DEBUG = False

CONFIG_ENDPOINT = "/config"

HEALTH_ENDPOINT = "/health"

TIMEOUT_MS = 8000

ECS_TRUNCATION = {
    "enabled": True,
    "ipv4_prefix": 20,
    "ipv6_prefix": 48,
}

REBIND_PROTECTION = True

BLOCKED_DOMAINS = [
    "example.com",
]

ALLOWED_DOMAINS = [
    "malware.wicar.org",
]

BYPASS_PROVIDER = {
    "url": "https://cloudflare-dns.com/dns-query",
    "dns_json": True,
}

LOKI_URL = ""

LOKI_TIMEOUT_MS = 5000

RETRY_MAX_ATTEMPTS = 2

CACHE_DNS = True

ENDPOINTS = {
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
