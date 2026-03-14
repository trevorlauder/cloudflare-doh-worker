# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Default test configuration with ECS, rebind protection, and blocked/allowed domains."""

DEBUG = False

CONFIG_ENDPOINT = "/config"

HEALTH_ENDPOINT = "/health"

TIMEOUT_MS = 5000

ECS_TRUNCATION = {
    "enabled": True,
}

REBIND_PROTECTION = True

BLOCKED_DOMAINS = ["example.com"]

ALLOWED_DOMAINS = ["malware.wicar.org"]

BYPASS_PROVIDER = {
    "url": "https://cloudflare-dns.com/dns-query",
    "dns_json": True,
}

LOKI_URL = ""

LOKI_TIMEOUT_MS = 5000

RETRY_MAX_ATTEMPTS = 2

CACHE_DNS = True

ENDPOINTS = {
    "/doh/my-device": {
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
