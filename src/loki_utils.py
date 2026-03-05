# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

import base64
import json
import logging

from config import LOKI_TIMEOUT_MS
from dns_utils import Question

logger = logging.getLogger(__name__)


def build_loki_fetch_promise(
  request_timestamp_ms: int,
  endpoint: str,
  question: Question,
  response_from: str,
  results: list,
  env,
  loki_url: str,
  client_ip: str = "",
  config_blocked: bool = False,
  config_allowed: bool = False,
  error: bool = False,
):
  """Build a Loki log entry and return a JS fetch Promise, or None on failure."""

  try:
    from js import AbortSignal, Object, fetch
    from pyodide.ffi import to_js

    loki_username = getattr(env, "LOKI_USERNAME", None)
    loki_password = getattr(env, "LOKI_PASSWORD", None)

    if not loki_username or not loki_password:
      return None

    credentials = base64.b64encode(f"{loki_username}:{loki_password}".encode()).decode()

    response_codes = {}
    blocked_ids = []
    timed_out_ids = []
    connection_error_ids = []
    rebind_ids = []
    possibly_blocked_ids = []
    failed_provider_ids = []
    retried_provider_ids = []

    for result in results:
      pid = result.provider_id
      response_codes[pid] = result.response_status
      if result.blocked:
        blocked_ids.append(pid)
      if result.timed_out:
        timed_out_ids.append(pid)
      if result.connection_error:
        connection_error_ids.append(pid)
      if result.rebind:
        rebind_ids.append(pid)
      if result.possibly_blocked:
        possibly_blocked_ids.append(pid)
      if result.failed:
        failed_provider_ids.append(f"{pid} ({result.response_status})")
      if result.retry_count > 0:
        retried_provider_ids.append(f"{pid} (x{result.retry_count})")

    is_blocked = any(r.blocked and r.provider_id == response_from for r in results)

    is_possibly_blocked = any(
      r.possibly_blocked and r.provider_id == response_from for r in results
    )

    if error:
      result_status = "error"
    elif config_blocked:
      result_status = "config blocked"
    elif config_allowed:
      result_status = "config allowed"
    elif is_blocked:
      result_status = "blocked"
    elif is_possibly_blocked:
      result_status = "possibly blocked"
    else:
      result_status = "not blocked"

    log_entry = {
      "client_ip": client_ip,
      "endpoint": endpoint,
      "question": {
        "name": question.name,
        "type": question.type,
      },
      "result_status": result_status,
      "blocked_providers": ", ".join(blocked_ids),
      "possibly_blocked_providers": ", ".join(possibly_blocked_ids),
      "timed_out_providers": ", ".join(timed_out_ids),
      "connection_error_providers": ", ".join(connection_error_ids),
      "rebind_providers": ", ".join(rebind_ids),
      "failed_providers": ", ".join(failed_provider_ids),
      "retried_providers": ", ".join(retried_provider_ids),
      "response_codes": response_codes,
      "response_from": response_from,
    }

    ts_ns = str(request_timestamp_ms * 1_000_000)

    loki_payload = {
      "streams": [
        {
          "stream": {"source": "cloudflare-doh-worker"},
          "values": [[ts_ns, json.dumps(log_entry, separators=(",", ":"))]],
        }
      ]
    }

    headers = {
      "Authorization": f"Basic {credentials}",
      "Content-Type": "application/json",
    }

    fetch_options = {
      "method": "POST",
      "headers": headers,
      "body": json.dumps(loki_payload, separators=(",", ":")),
      "signal": AbortSignal.timeout(LOKI_TIMEOUT_MS),
    }

    return fetch(loki_url, to_js(fetch_options, dict_converter=Object.fromEntries))
  except Exception as e:
    if logger.isEnabledFor(logging.DEBUG):
      logger.debug("build_loki_fetch_promise failed: %s", e)
    return None
