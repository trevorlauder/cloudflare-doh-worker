# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Test configuration for the integration test suite."""

TIMEOUT_MS = 8000

ECS_TRUNCATION = {
    "enabled": True,
    "ipv4_prefix": 20,
    "ipv6_prefix": 48,
}

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
