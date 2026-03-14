# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Example configuration for the Cloudflare DoH worker proxy.

This example shows patterns you might use in a real setup. It includes a
shared list of additional providers reused across all endpoints and separate
NextDNS profiles per device with device-identifying headers. Sensitive values
like the endpoint path, provider URLs, and Loki URL use ${SECRET_NAME}
placeholders resolved from Worker secrets.

Copy this into src/config.py and adjust it for your environment.
See the README for full documentation of all available options.
"""

_ADDITIONAL_PROVIDERS: list = [
    {
        "url": "https://dns11.quad9.net/dns-query",
    },
    {
        "url": "https://security.cloudflare-dns.com/dns-query",
        "dns_json": True,
    },
]

_ENDPOINT_PREFIX = "/${ENDPOINT_SECRET}"

DEBUG = False

CONFIG_ENDPOINT = f"{_ENDPOINT_PREFIX}/config"

HEALTH_ENDPOINT = f"{_ENDPOINT_PREFIX}/health"

TIMEOUT_MS = 5000

ECS_TRUNCATION = {
    "enabled": True,
}

REBIND_PROTECTION = True

BLOCKED_DOMAINS = []

ALLOWED_DOMAINS = []

BYPASS_PROVIDER = {
    "url": "https://cloudflare-dns.com/dns-query",
    "dns_json": True,
}

LOKI_URL = "${LOKI_URL}"

LOKI_TIMEOUT_MS = 5000

RETRY_MAX_ATTEMPTS = 2

CACHE_DNS = True

ENDPOINTS = {
    f"{_ENDPOINT_PREFIX}/home/firewall": {
        "main_provider": {
            "url": "https://dns.nextdns.io/${NEXTDNS_HOME_ID}",
            "headers": {
                "X-Device-Name": "Firewall",
            },
        },
        "additional_providers": _ADDITIONAL_PROVIDERS,
    },
    f"{_ENDPOINT_PREFIX}/trevor/iphone": {
        "main_provider": {
            "url": "https://apple.dns.nextdns.io/${NEXTDNS_TREVOR_ID}",
            "headers": {
                "X-Device-Name": "Trevor's iPhone",
                "X-Device-Model": "iPhone 14 Pro Max",
            },
        },
        "additional_providers": _ADDITIONAL_PROVIDERS,
    },
    f"{_ENDPOINT_PREFIX}/trevor/macbookpro": {
        "main_provider": {
            "url": "https://apple.dns.nextdns.io/${NEXTDNS_TREVOR_ID}",
            "headers": {
                "X-Device-Name": "Trevor's MacBook Pro",
                "X-Device-Model": "MacBook Pro",
            },
        },
        "additional_providers": _ADDITIONAL_PROVIDERS,
    },
}
