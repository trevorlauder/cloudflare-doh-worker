# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Loki log shipping helpers for the DoH worker."""

import base64
import json
import logging

from js import AbortSignal
from workers import fetch

import config
from dns_utils import Question

logger = logging.getLogger(__name__)

_cached_loki_credentials: str | None = None


def build_loki_fetch_promise(
    request_timestamp_ms: int,
    elapsed_ms: int,
    endpoint: str,
    question: Question,
    response_from: str,
    results: list,
    env: object,
    loki_url: str,
    client_ip: str = "",
    config_blocked: bool = False,
    config_allowed: bool = False,
    error: bool = False,
    blocklist_domain_count: int = 0,
    blocklist_shard_count: int = 0,
    shard_cache_hit: bool = False,
    shard_cache_age_ms: int = 0,
    isolate_id: str = "",
    shard_cache_count: int = 0,
    shard_cache_bytes: int = 0,
) -> object | None:
    """
    Build a Loki log entry and return a JS fetch Promise, or None on failure.

    Parameters:
    request_timestamp_ms (int): Request timestamp in milliseconds.
    endpoint (str): Endpoint path.
    question (Question): DNS question tuple.
    response_from (str): Provider ID that served the response.
    results (list): List of ProviderResult objects.
    env (object): Environment with secrets.
    loki_url (str): Loki push URL.
    client_ip (str): Client IP address.
    config_blocked (bool): Whether the request was blocked by config.
    config_allowed (bool): Whether the request was allowed by config bypass.
    elapsed_ms (int): Elapsed milliseconds from request start to just before Loki dispatch.
    error (bool): Whether the request resulted in an error.
    blocklist_shard_count (int): Number of filter shards (0 if not sharded).

    shard_cache_hit (bool): Whether the shard lookup was served from the in-memory cache.
    shard_cache_age_ms (int): Age of the cache entry in milliseconds on a hit, or 0 on a miss.
    isolate_id (str): Unique identifier for the worker isolate.
    shard_cache_count (int): Number of shards currently in the LRU cache.
    shard_cache_bytes (int): Total bytes used by cached shards.
    Returns:
    object | None: JS fetch Promise or None on failure.
    """
    try:
        global _cached_loki_credentials

        loki_username: object | None = getattr(env, "LOKI_USERNAME", None)
        loki_password: object | None = getattr(env, "LOKI_PASSWORD", None)

        if not loki_username or not loki_password:
            return None

        if _cached_loki_credentials is None:
            _cached_loki_credentials = base64.b64encode(
                f"{loki_username}:{loki_password}".encode(),
            ).decode()

        credentials: str = _cached_loki_credentials

        response_codes: dict[str, int] = {}
        blocked_ids: list[str] = []
        timed_out_ids: list[str] = []
        connection_error_ids: list[str] = []
        rebind_ids: list[str] = []
        possibly_blocked_ids: list[str] = []
        failed_provider_ids: list[str] = []
        retried_provider_ids: list[str] = []

        for result in results:
            pid: str = result.provider_id
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

        is_blocked: bool = any(
            r.blocked and r.provider_id == response_from for r in results
        )

        is_possibly_blocked: bool = any(
            r.possibly_blocked and r.provider_id == response_from for r in results
        )

        if error:
            result_status: str = "error"
        elif config_blocked:
            result_status = "worker blocked"
        elif config_allowed:
            result_status = "worker allowed"
        elif is_blocked:
            result_status = "blocked"
        elif is_possibly_blocked:
            result_status = "possibly blocked"
        else:
            result_status = "not blocked"

        log_entry: dict[str, object] = {
            "client_ip": client_ip,
            "endpoint": endpoint,
            "elapsed_ms": elapsed_ms,
            "question_name": question.name,
            "question_type": question.type,
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
            "blocklist_domain_count": blocklist_domain_count,
            "blocklist_shard_count": blocklist_shard_count,
            "shard_cache_hit": shard_cache_hit,
            "shard_cache_age_ms": shard_cache_age_ms,
            "isolate_id": isolate_id,
            "shard_cache_count": shard_cache_count,
            "shard_cache_bytes": shard_cache_bytes,
        }

        ts_ns: str = str(request_timestamp_ms * 1_000_000)

        loki_payload: dict[str, list] = {
            "streams": [
                {
                    "stream": {"source": "cloudflare-doh-worker"},
                    "values": [[ts_ns, json.dumps(log_entry, separators=(",", ":"))]],
                },
            ],
        }

        headers: dict[str, str] = {
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/json",
        }

        fetch_options: dict[str, object] = {
            "method": "POST",
            "headers": headers,
            "body": json.dumps(loki_payload, separators=(",", ":")),
            "signal": AbortSignal.timeout(getattr(config, "LOKI_TIMEOUT_MS", 5000)),
        }

        return fetch(loki_url, **fetch_options)
    except Exception as e:
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("build_loki_fetch_promise failed: %s", e)
        return None
