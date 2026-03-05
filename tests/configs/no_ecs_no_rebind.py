# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

DEBUG = True

CONFIG_ENDPOINT = "/config"

HEALTH_ENDPOINT = "/health"

TIMEOUT_MS = 5000

ECS_TRUNCATION = {
  "enabled": False,
}

REBIND_PROTECTION = False

BLOCKED_DOMAINS = ["example.com"]

ALLOWED_DOMAINS = ["malware.wicar.org"]

BYPASS_PROVIDER = {
  "host": "cloudflare-dns.com",
  "path": "/dns-query",
}

LOKI_URL = ""

LOKI_TIMEOUT_MS = 5000

RETRY_MAX_ATTEMPTS = 2

ENDPOINTS = {
  "/doh/my-device": {
    "main_provider": {
      "host": "cloudflare-dns.com",
      "path": "/dns-query",
    },
    "additional_providers": [
      {
        "host": "dns11.quad9.net",
        "path": "/dns-query",
      },
      {
        "host": "security.cloudflare-dns.com",
        "path": "/dns-query",
      },
    ],
  },
}
