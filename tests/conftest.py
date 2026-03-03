# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

import os
import re
import ssl
import urllib.request


def resolve_env(s: str) -> str:
  """Substitute {VAR_NAME} placeholders with environment variable values."""

  return re.sub(
    r"\{([A-Z][A-Z0-9_]*)\}", lambda m: os.environ.get(m.group(1), m.group(0)), s
  )


BASE_URL = os.environ.get("BASE_URL", "http://localhost:8787").rstrip("/")
IS_LOCAL = "localhost" in BASE_URL or "127.0.0.1" in BASE_URL
IS_HTTPS = BASE_URL.startswith("https")
SKIP_TLS = IS_HTTPS and (
  IS_LOCAL or os.environ.get("SKIP_TLS_VERIFY", "") in ("1", "true")
)


def pytest_configure(config):
  """Install a custom opener for HTTPS with self-signed certs."""

  if SKIP_TLS:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    urllib.request.install_opener(opener)
