# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Configuration for the Cloudflare DoH worker proxy."""

ENDPOINTS = {
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
