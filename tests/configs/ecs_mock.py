# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Test configuration using the mock DoH server with custom ECS prefixes."""

DEBUG = True

CONFIG_ENDPOINT = "/config"

HEALTH_ENDPOINT = "/health"

TIMEOUT_MS = 5000

ECS_TRUNCATION = {
    "enabled": True,
    "ipv4_prefix": 20,
    "ipv6_prefix": 48,
}

REBIND_PROTECTION = False

BLOCKED_DOMAINS = []

ALLOWED_DOMAINS = []

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
            "url": "http://mock-doh:8080/dns-query",
        },
    },
}
