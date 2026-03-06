# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

DEBUG = False

CONFIG_ENDPOINT = "/doh/config"

HEALTH_ENDPOINT = "/doh/health"

TIMEOUT_MS = 5000

ECS_TRUNCATION = {
  "enabled": False,
}

REBIND_PROTECTION = True

BLOCKED_DOMAINS = []

ALLOWED_DOMAINS = []

BYPASS_PROVIDER = {
  "host": "cloudflare-dns.com",
  "path": "/dns-query",
  "dns_json": True,
}

LOKI_URL = ""

LOKI_TIMEOUT_MS = 5000

RETRY_MAX_ATTEMPTS = 2

ENDPOINTS = {
  "/doh/my-device": {
    "main_provider": {
      "host": "security.cloudflare-dns.com",
      "path": "/dns-query",
      "dns_json": True,
    },
    "additional_providers": [
      {
        "host": "dns11.quad9.net",
        "path": "/dns-query",
      },
    ],
  },
}
