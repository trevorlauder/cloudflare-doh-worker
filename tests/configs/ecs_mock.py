# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Test configuration using the mock DoH server with custom ECS prefixes."""

DEBUG = True

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

ENDPOINTS = {
    "/my-device": {
        "main_provider": {
            "url": "http://mock-doh:8080/dns-query",
        },
    },
}
