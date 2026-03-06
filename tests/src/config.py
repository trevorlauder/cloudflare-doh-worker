# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

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
  "host": "cloudflare-dns.com",
  "path": "/dns-query",
  "dns_json": True,
}

LOKI_URL = ""

LOKI_TIMEOUT_MS = 5000

RETRY_MAX_ATTEMPTS = 2

ENDPOINTS = {
  "/my/doh/path": {
    "main_provider": {
      "host": "cloudflare-dns.com",
      "path": "/dns-query",
      "dns_json": True,
    },
    "additional_providers": [
      {
        "host": "dns11.quad9.net",
        "path": "/dns-query",
      },
      {
        "host": "security.cloudflare-dns.com",
        "path": "/dns-query",
        "dns_json": True,
      },
    ],
  },
}
