# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""Unit tests for worker internals (select_winner, secret resolution, validation)."""

import json
import sys
from unittest.mock import MagicMock

_workers_stub = MagicMock()
_workers_stub.WorkerEntrypoint = object
sys.modules["workers"] = _workers_stub

import pytest  # noqa: E402

import config  # noqa: E402
from dns_utils import ProviderResult  # noqa: E402
from worker import (  # noqa: E402
    _handle_health,
    _negotiate_accept,
    _resolve_secrets,
    _ResolvedConfig,
    _select_winner,
    _validate_config,
    _validate_types,
)


def _result(
    *,
    main: bool = True,
    failed: bool = False,
    blocked: bool = False,
    possibly_blocked: bool = False,
    rebind: bool = False,
    url: str = "https://dns.example.com/dns-query",
) -> ProviderResult:
    return ProviderResult(
        url=url,
        provider_id=url,
        response_status=200,
        response_content_type="application/dns-message",
        response_body=b"",
        main=main,
        failed=failed,
        blocked=blocked,
        possibly_blocked=possibly_blocked,
        rebind=rebind,
    )


class _Env:
    def __init__(self, **kwargs: object) -> None:
        for k, v in kwargs.items():
            setattr(self, k, v)


def test_select_winner_empty():
    assert _select_winner([]) is None


def test_select_winner_all_failed():
    assert _select_winner([_result(failed=True), _result(failed=True)]) is None


def test_select_winner_single():
    r = _result()
    assert _select_winner([r]) is r


def test_select_winner_prefers_main():
    additional = _result(main=False)
    main = _result(main=True)
    assert _select_winner([additional, main]) is main


def test_select_winner_blocked_beats_successful():
    success = _result()
    blocked = _result(blocked=True)
    assert _select_winner([success, blocked]) is blocked


def test_select_winner_possibly_blocked_beats_successful():
    success = _result()
    possibly = _result(possibly_blocked=True)
    assert _select_winner([success, possibly]) is possibly


def test_select_winner_blocked_beats_possibly_blocked():
    possibly = _result(possibly_blocked=True)
    blocked = _result(blocked=True)
    assert _select_winner([possibly, blocked]) is blocked


def test_select_winner_rebind_replaced_when_protection_on(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(config, "REBIND_PROTECTION", True)
    rebind = _result(main=True, rebind=True)
    clean = _result(main=False, rebind=False)
    assert _select_winner([rebind, clean]) is clean


def test_select_winner_rebind_kept_when_protection_off(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "REBIND_PROTECTION", False)
    rebind = _result(main=True, rebind=True)
    clean = _result(main=False, rebind=False)
    assert _select_winner([rebind, clean]) is rebind


def test_select_winner_rebind_no_clean_alternative_kept(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(config, "REBIND_PROTECTION", True)
    rebind = _result(main=True, rebind=True)
    assert _select_winner([rebind]) is rebind


def test_select_winner_prefers_non_rebind_main_over_additional(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(config, "REBIND_PROTECTION", True)
    rebind_main = _result(main=True, rebind=True)
    clean_additional = _result(main=False, rebind=False)

    clean_main = _result(
        main=True,
        rebind=False,
        url="https://other.example.com/dns-query",
    )

    assert _select_winner([rebind_main, clean_additional, clean_main]) is clean_main


def test_resolve_secrets_plain_string():
    assert _resolve_secrets("no placeholders", _Env()) == "no placeholders"


def test_resolve_secrets_substitutes():
    env = _Env(MY_SECRET="secret_value")  # noqa: S106

    assert (
        _resolve_secrets("prefix-${MY_SECRET}-suffix", env)
        == "prefix-secret_value-suffix"
    )


def test_resolve_secrets_missing_raises():
    with pytest.raises(ValueError, match="Missing secret"):
        _resolve_secrets("${MISSING_SECRET}", _Env())


def test_resolve_secrets_multiple_missing_reported():
    with pytest.raises(ValueError, match="AAA") as exc:
        _resolve_secrets("${AAA} ${BBB}", _Env())

    assert "BBB" in str(exc.value)


def test_resolve_secrets_dict():
    env = _Env(TOKEN="abc123")  # noqa: S106

    assert _resolve_secrets({"key": "${TOKEN}", "other": "plain"}, env) == {
        "key": "abc123",
        "other": "plain",
    }


def test_resolve_secrets_list():
    env = _Env(VAL="x")
    assert _resolve_secrets(["${VAL}", "literal"], env) == ["x", "literal"]


def test_resolve_secrets_nested():
    env = _Env(A="1", B="2")
    assert _resolve_secrets({"outer": {"inner": "${A}"}, "list": ["${B}"]}, env) == {
        "outer": {"inner": "1"},
        "list": ["2"],
    }


def test_resolve_secrets_non_string_passthrough():
    assert _resolve_secrets(42, _Env()) == 42
    assert _resolve_secrets(None, _Env()) is None


def test_validate_types_valid():
    _validate_types()


def test_validate_types_wrong_bool(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "DEBUG", "not_a_bool")
    with pytest.raises(TypeError, match="DEBUG"):
        _validate_types()


def test_validate_types_wrong_int(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "TIMEOUT_MS", "5000")
    with pytest.raises(TypeError, match="TIMEOUT_MS"):
        _validate_types()


def test_validate_types_none_skipped(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "LOKI_URL", None)
    _validate_types()


def test_validate_config_no_allowed_domains(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "ALLOWED_DOMAINS", [])
    _validate_config()


def test_validate_config_valid(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "ALLOWED_DOMAINS", ["example.com"])
    monkeypatch.setattr(
        config,
        "BYPASS_PROVIDER",
        {"url": "https://dns.example.com/dns-query"},
    )

    _validate_config()


def test_validate_config_bypass_missing_url(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "ALLOWED_DOMAINS", ["example.com"])
    monkeypatch.setattr(config, "BYPASS_PROVIDER", {})
    with pytest.raises(ValueError, match="url"):
        _validate_config()


def test_validate_config_bypass_empty_url(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "ALLOWED_DOMAINS", ["example.com"])
    monkeypatch.setattr(config, "BYPASS_PROVIDER", {"url": ""})
    with pytest.raises(ValueError, match="url"):
        _validate_config()


def test_negotiate_accept_json():
    assert _negotiate_accept("application/dns-json") == "application/dns-json"


def test_negotiate_accept_wire():
    assert _negotiate_accept("application/dns-message") == "application/dns-message"


def test_negotiate_accept_unsupported():
    assert _negotiate_accept("text/html") == ""


def test_negotiate_accept_empty():
    assert _negotiate_accept("") == ""


def test_negotiate_accept_picks_first_supported():
    assert (
        _negotiate_accept("text/html, application/dns-json") == "application/dns-json"
    )


def test_negotiate_accept_with_quality_param():
    assert _negotiate_accept("application/dns-json; q=0.9") == "application/dns-json"


def test_negotiate_accept_wildcard_not_matched():
    assert _negotiate_accept("*/*") == ""


def test_negotiate_accept_case_insensitive():
    assert _negotiate_accept("APPLICATION/DNS-JSON") == "application/dns-json"


def _make_cfg(
    *,
    provider_lists: dict | None = None,
    bypass_provider_list: list | None = None,
) -> _ResolvedConfig:
    """
    Build a minimal _ResolvedConfig for health tests.

    Parameters:
    provider_lists (dict | None): Endpoint provider lists.
    bypass_provider_list (list | None): Bypass provider list.

    Returns:
    _ResolvedConfig: Minimal config for health handler tests.
    """
    return _ResolvedConfig(
        health_endpoint="/health",
        config_endpoint=None,
        loki_url="",
        provider_lists=provider_lists or {},
        bypass_provider_list=bypass_provider_list or [],
    )


def test_handle_health_returns_ok():
    """
    Test that _handle_health returns status 'ok' and correct endpoint count.

    Returns:
    None
    """
    cfg = _make_cfg(
        provider_lists={"/doh/test": [{"url": "https://dns.example.com/dns-query"}]},
    )
    _handle_health(cfg)
    resp_call = _workers_stub.Response.call_args
    body_json = json.loads(resp_call[0][0])
    assert body_json["status"] == "ok"
    assert body_json["endpoints"] == 1
    assert resp_call[1]["status"] == 200


def test_handle_health_reports_endpoint_count():
    """
    Test that _handle_health returns correct endpoint count for multiple endpoints.

    Returns:
    None
    """
    cfg = _make_cfg(
        provider_lists={
            "/doh/a": [{"url": "https://a.example.com"}],
            "/doh/b": [{"url": "https://b.example.com"}],
            "/doh/c": [{"url": "https://c.example.com"}],
        },
    )
    _handle_health(cfg)
    body_json = json.loads(_workers_stub.Response.call_args[0][0])
    assert body_json["endpoints"] == 3


def test_handle_health_zero_endpoints():
    """
    Test that _handle_health returns 'ok' and zero endpoints when none are configured.

    Returns:
    None
    """
    cfg = _make_cfg(provider_lists={})
    _handle_health(cfg)
    body_json = json.loads(_workers_stub.Response.call_args[0][0])
    assert body_json["status"] == "ok"
    assert body_json["endpoints"] == 0
