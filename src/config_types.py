# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Shared TypedDict definitions for worker configuration."""

from typing import NewType, NotRequired, TypedDict

PositiveInt = NewType("PositiveInt", int)
NonNegativeInt = NewType("NonNegativeInt", int)


class EcsConfig(TypedDict):
    """ECS (EDNS Client Subnet) truncation settings."""

    enabled: bool
    ipv4_prefix: NotRequired[int]
    ipv6_prefix: NotRequired[int]


class Provider(TypedDict):
    """Upstream DNS-over-HTTPS provider."""

    url: str
    dns_json: NotRequired[bool]
    headers: NotRequired[dict[str, str]]


class EndpointConfig(TypedDict):
    """Per-endpoint provider configuration."""

    main_provider: Provider
    additional_providers: NotRequired[list[Provider]]


class WorkerConfig(TypedDict):
    """Complete worker configuration for runtime validation."""

    ENDPOINTS: dict[str, EndpointConfig]
    DEBUG: NotRequired[bool]
    TIMEOUT_MS: NotRequired[PositiveInt]
    LOKI_TIMEOUT_MS: NotRequired[PositiveInt]
    RETRY_MAX_ATTEMPTS: NotRequired[NonNegativeInt]
    CACHE_DNS: NotRequired[bool]
    BLOCKLIST_ENABLED: NotRequired[bool]
    LOKI_URL: NotRequired[str]
    REBIND_PROTECTION: NotRequired[bool]
    ALLOWED_DOMAINS: NotRequired[list[str]]
    BLOCKED_DOMAINS: NotRequired[list[str]]
    ECS_TRUNCATION: NotRequired[EcsConfig]
    BYPASS_PROVIDER: NotRequired[Provider]
    PATH_PREFIX: NotRequired[str]
