# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Test configuration with ECS truncation and rebind protection disabled."""

DEBUG = True

REBIND_PROTECTION = False

BLOCKED_DOMAINS = ["example.com"]

ALLOWED_DOMAINS = ["malware.wicar.org"]

BYPASS_PROVIDER = {
    "url": "https://cloudflare-dns.com/dns-query",
    "dns_json": True,
}

ENDPOINTS = {
    "/my-device": {
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
