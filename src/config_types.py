# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Shared TypedDict definitions for worker configuration."""

from typing import NotRequired, TypedDict


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
