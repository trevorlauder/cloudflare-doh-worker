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

from typing import Literal

from config_types import EcsConfig, EndpointConfig, Provider

_ADDITIONAL_PROVIDERS: list[Provider] = [
    {
        "url": "https://dns11.quad9.net/dns-query",
    },
    {
        "url": "https://security.cloudflare-dns.com/dns-query",
        "dns_json": True,
    },
]

_ENDPOINT_PREFIX = "/${ENDPOINT_SECRET}"

DEBUG: bool = False

CONFIG_ENDPOINT: str = f"{_ENDPOINT_PREFIX}/config"

HEALTH_ENDPOINT: str = f"{_ENDPOINT_PREFIX}/health"

TIMEOUT_MS: int = 5000

ECS_TRUNCATION: EcsConfig = {
    "enabled": True,
}

REBIND_PROTECTION: bool = True

BLOCKED_DOMAINS: list = []

ALLOWED_DOMAINS: list = []

BYPASS_PROVIDER: Provider = {
    "url": "https://cloudflare-dns.com/dns-query",
    "dns_json": True,
}

LOKI_URL: str = "${LOKI_URL}"

LOKI_TIMEOUT_MS: int = 5000

RETRY_MAX_ATTEMPTS: int = 2

CACHE_DNS: bool = True

BLOCKLIST_LOADING_POLICY: Literal["block", "bypass"] = "block"

ENDPOINTS: dict[str, EndpointConfig] = {
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
