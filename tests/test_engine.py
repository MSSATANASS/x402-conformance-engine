"""Comprehensive tests for the x402 conformance engine.

Every check function in :mod:`x402_conformance_suite._engine.checks` is exercised
across all status paths: PASS, FAIL, CRITICAL_FAIL, ERROR, plus skip cases.
httpx is mocked via :class:`MockTransport` so tests do not perform I/O.

Run a subset:
    pytest tests/test_engine.py -k manifest
Run with coverage:
    pytest tests/test_engine.py --cov=x402_conformance_suite._engine --cov-report=term-missing
"""

from __future__ import annotations

import asyncio
import base64
import json
from typing import Any

import httpx
import pytest

from x402_conformance_suite._engine import (
    CAIP2_PATTERN,
    AuditReport,
    BazaarResult,
    Caip2Result,
    CheckMode,
    CheckResult,
    JsonResilienceResult,
    ManifestResult,
    MarketplaceResult,
    ProductResult,
    X402Auditor,
    run_audit,
)
from x402_conformance_suite._engine import checks as engine_checks
from x402_conformance_suite._engine.messages import (
    bazaar_malformed,
    bazaar_not_present,
)


# ---------------------------------------------------------------------------
# Mock httpx transport — run handlers locally without network.
# ---------------------------------------------------------------------------


def _json_response(
    status_code: int,
    body: Any | None = None,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    raw = b"" if body is None else json.dumps(body).encode("utf-8")
    final_headers = dict(headers or {})
    final_headers.setdefault("content-type", "application/json")
    return httpx.Response(
        status_code,
        content=raw,
        headers=final_headers,
        request=httpx.Request("GET", "https://example.test/"),
    )


def _payload_response(payload: Any) -> httpx.Response:
    return _json_response(200, payload)


def _b64(value: dict[str, Any]) -> str:
    """Encode ``value`` as base64(JSON) — used for header simulation."""
    return base64.b64encode(json.dumps(value).encode("utf-8")).decode("ascii")


@pytest.fixture
def mock_transport() -> httpx.MockTransport:
    """Empty MockTransport — tests customize via ``setup``."""
    handler = httpx.MockTransport(lambda req: _json_response(200, {}))
    return httpx.MockTransport(handler.handle_request)


@pytest.fixture
def make_client():
    """Provide a factory that builds an ``httpx.AsyncClient`` with a custom handler.

    Usage::

        async with make_client(lambda req: Response(200, ...)) as client:
            await engine_checks.check_manifest(client, "...")
    """

    def _make(handler: Any) -> httpx.AsyncClient:
        transport = httpx.MockTransport(handler)
        return httpx.AsyncClient(transport=transport, timeout=5.0)

    return _make


# ---------------------------------------------------------------------------
# 1. CAIP-2 pattern
# ---------------------------------------------------------------------------


class TestCAIP2Pattern:
    """Boundary-case coverage for the CAIP-2 regex."""

    @pytest.mark.parametrize("value", [
        "eip155:1", "eip155:8453", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        "polkadot:91b171bb158e2d3848fa23a9f1c25182", "bip122:000000000019d6689c085ae165831e93",
        "cosmos:cosmoshub-4",
    ])
    def test_valid(self, value: str) -> None:
        assert CAIP2_PATTERN.match(value) is not None

    @pytest.mark.parametrize("value", [
        "8453",                          # missing namespace
        "eip1558453",                    # missing colon
        "EIP155:8453",                   # uppercase namespace
        ":8453",                         # empty namespace
        "eip155:",                       # empty chain id
        "eip155:8453:",                  # trailing colon
        "eip155:8453:extra",             # too many colons
        "_invalid:1",                    # underscore prefix in namespace
        "eip155:!!",                     # invalid characters in chain id
        "",                              # empty
    ])
    def test_invalid(self, value: str) -> None:
        assert CAIP2_PATTERN.match(value) is None


# ---------------------------------------------------------------------------
# 2. Manifest discovery
# ---------------------------------------------------------------------------


class TestCheckManifest:

    @pytest.mark.asyncio
    async def test_pass_with_accepts(self, make_client) -> None:
        handler = lambda req: _payload_response(
            {"accepts": [{"scheme": "exact", "network": "eip155:8453"}]}
        )
        async with make_client(handler) as client:
            result = await engine_checks.check_manifest(client, "https://api.example.com")

        assert isinstance(result, ManifestResult)
        assert result.status == "PASS"
        assert result.check_name == "manifest_discovery"
        assert "accepts" in result.message
        assert result.details["has_accepts"] is True
        assert result.details["has_products"] is False
        assert result.details["status_code"] == 200

    @pytest.mark.asyncio
    async def test_pass_with_products(self, make_client) -> None:
        handler = lambda req: _payload_response(
            {"products": [{"id": "p1"}, {"id": "p2"}]}
        )
        async with make_client(handler) as client:
            result = await engine_checks.check_manifest(client, "https://api.example.com")

        assert result.status == "PASS"
        assert result.details["has_products"] is True
        assert result.details["product_count"] == 2
        assert "marketplace catalog" in result.message

    @pytest.mark.asyncio
    async def test_pass_with_full_url_preserves_path(self, make_client) -> None:
        seen_urls: list[str] = []
        def handler(req: httpx.Request) -> httpx.Response:
            seen_urls.append(str(req.url))
            return _payload_response({"accepts": []})
        async with make_client(handler) as client:
            await engine_checks.check_manifest(client, "https://api.example.com/v1/")
        assert seen_urls == ["https://api.example.com/v1/.well-known/x402"]

    @pytest.mark.asyncio
    async def test_fail_404(self, make_client) -> None:
        handler = lambda req: _json_response(404)
        async with make_client(handler) as client:
            result = await engine_checks.check_manifest(client, "https://api.example.com")
        assert result.status == "FAIL"
        assert "Manifest endpoint not found" in result.message

    @pytest.mark.asyncio
    async def test_fail_500(self, make_client) -> None:
        handler = lambda req: _json_response(500)
        async with make_client(handler) as client:
            result = await engine_checks.check_manifest(client, "https://api.example.com")
        assert result.status == "FAIL"

    @pytest.mark.asyncio
    async def test_fail_invalid_json(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                content=b"<!DOCTYPE html><html>not json</html>",
                headers={"content-type": "text/html"},
                request=req,
            )
        async with make_client(handler) as client:
            result = await engine_checks.check_manifest(client, "https://api.example.com")
        assert result.status == "FAIL"
        assert "not valid JSON" in result.message

    @pytest.mark.asyncio
    async def test_fail_payload_is_array(self, make_client) -> None:
        async with make_client(lambda req: _payload_response([])) as client:
            result = await engine_checks.check_manifest(client, "https://api.example.com")
        assert result.status == "FAIL"
        assert "not valid JSON" in result.message

    @pytest.mark.asyncio
    async def test_fail_payload_is_null(self, make_client) -> None:
        async with make_client(lambda req: _payload_response(None)) as client:
            result = await engine_checks.check_manifest(client, "https://api.example.com")
        assert result.status == "FAIL"

    @pytest.mark.asyncio
    async def test_fail_payload_is_string(self, make_client) -> None:
        async with make_client(lambda req: _payload_response("just a string")) as client:
            result = await engine_checks.check_manifest(client, "https://api.example.com")
        assert result.status == "FAIL"

    @pytest.mark.asyncio
    async def test_fail_empty_object(self, make_client) -> None:
        async with make_client(lambda req: _payload_response({})) as client:
            result = await engine_checks.check_manifest(client, "https://api.example.com")
        assert result.status == "FAIL"
        assert "lacks the required 'accepts' key" in result.message
        assert result.details["received_keys"] == []

    @pytest.mark.asyncio
    async def test_fail_accepts_wrong_type(self, make_client) -> None:
        async with make_client(lambda req: _payload_response({"accepts": "not a list"})) as client:
            result = await engine_checks.check_manifest(client, "https://api.example.com")
        assert result.status == "FAIL"

    @pytest.mark.asyncio
    async def test_error_timeout(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("simulated")
        async with make_client(handler) as client:
            result = await engine_checks.check_manifest(client, "https://api.example.com")
        assert result.status == "ERROR"
        assert "Could not reach manifest" in result.message

    @pytest.mark.asyncio
    async def test_error_connect_error(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("simulated")
        async with make_client(handler) as client:
            result = await engine_checks.check_manifest(client, "https://api.example.com")
        assert result.status == "ERROR"

    @pytest.mark.asyncio
    async def test_error_unexpected_exception(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise RuntimeError("simulated")
        async with make_client(handler) as client:
            result = await engine_checks.check_manifest(client, "https://api.example.com")
        assert result.status == "ERROR"
        assert "RuntimeError" in result.message or "simulated" in result.message


# ---------------------------------------------------------------------------
# 3. CAIP-2 compliance
# ---------------------------------------------------------------------------


def _b64_obj(obj: dict[str, Any], headers: dict[str, str] | None = None) -> httpx.Response:
    """Build a 402 response whose payment header carries base64(obj).

    The response body is the same dict (so JSON resilience sees a JSON object).
    """
    h = {"payment-required": _b64(obj)}
    h.update(headers or {})
    return _json_response(402, obj, headers=h)


class TestCheckCaip2:

    @pytest.mark.asyncio
    async def test_pass_payment_required_header(self, make_client) -> None:
        handler = lambda req: _b64_obj({"network": "eip155:8453"})
        async with make_client(handler) as client:
            result = await engine_checks.check_caip2(client, "https://api.example.com")
        assert isinstance(result, Caip2Result)
        assert result.status == "PASS"
        assert result.details["valid"] is True
        assert result.details["caip2_value"] == "eip155:8453"
        assert "eip155:8453" in result.message

    @pytest.mark.asyncio
    async def test_pass_chain_id_alias(self, make_client) -> None:
        """Spec also accepts `chainId` as an alias for `network`."""
        handler = lambda req: _b64_obj({"chainId": "solana:mainnet"})
        async with make_client(handler) as client:
            result = await engine_checks.check_caip2(client, "https://api.example.com")
        assert result.status == "PASS"
        assert result.details["caip2_value"] == "solana:mainnet"

    @pytest.mark.asyncio
    async def test_pass_www_authenticate_x402_prefix(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return _json_response(
                402,
                headers={"www-authenticate": f"X402 {_b64({'network': 'eip155:1'})}"},
            )
        async with make_client(handler) as client:
            result = await engine_checks.check_caip2(client, "https://api.example.com")
        assert result.status == "PASS"
        assert result.details["caip2_value"] == "eip155:1"

    @pytest.mark.asyncio
    async def test_pass_priority_first_valid_header(self, make_client) -> None:
        """When multiple headers are valid, return the most-prioritized one."""
        def handler(req: httpx.Request) -> httpx.Response:
            return _json_response(402, headers={
                "payment-required": _b64({"network": "eip155:8453"}),
                "x-402-accepts": _b64({"network": "eip155:1"}),
            })
        async with make_client(handler) as client:
            result = await engine_checks.check_caip2(client, "https://api.example.com")
        assert result.status == "PASS"
        assert result.details["caip2_value"] == "eip155:8453"

    @pytest.mark.asyncio
    async def test_fail_invalid_caip2(self, make_client) -> None:
        handler = lambda req: _b64_obj({"network": "EIP155:8453"})
        async with make_client(handler) as client:
            result = await engine_checks.check_caip2(client, "https://api.example.com")
        assert result.status == "FAIL"
        assert "is not a valid CAIP-2 identifier" in result.message
        assert "EIP155:8453" in result.message

    @pytest.mark.asyncio
    async def test_fail_missing_network_field(self, make_client) -> None:
        handler = lambda req: _b64_obj({"scheme": "exact"})
        async with make_client(handler) as client:
            result = await engine_checks.check_caip2(client, "https://api.example.com")
        assert result.status == "FAIL"
        assert "No CAIP-2 network identifier" in result.message

    @pytest.mark.asyncio
    async def test_pass_v2_accepts_network(self, make_client) -> None:
        """x402 v2 PaymentRequired carries the network at accepts[].network,
        not top level. Regression: parser used to miss this and FAIL valid
        v2 endpoints."""
        payload = {
            "x402Version": 2,
            "error": "payment required",
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "eip155:8453",
                    "amount": "10000",
                    "payTo": "0x1111111111111111111111111111111111111111",
                }
            ],
        }
        handler = lambda req: _b64_obj(payload)
        async with make_client(handler) as client:
            result = await engine_checks.check_caip2(client, "https://api.example.com")
        assert result.status == "PASS"
        assert result.details["valid"] is True
        assert result.details["caip2_value"] == "eip155:8453"

    @pytest.mark.asyncio
    async def test_pass_accepts_second_entry_valid(self, make_client) -> None:
        """First accepts entry without a network does not mask a valid one."""
        payload = {
            "x402Version": 2,
            "accepts": [
                {"scheme": "exact", "amount": "10000"},
                {"scheme": "exact", "network": "eip155:8453"},
            ],
        }
        handler = lambda req: _b64_obj(payload)
        async with make_client(handler) as client:
            result = await engine_checks.check_caip2(client, "https://api.example.com")
        assert result.status == "PASS"
        assert result.details["caip2_value"] == "eip155:8453"

    @pytest.mark.asyncio
    async def test_fail_accepts_network_invalid(self, make_client) -> None:
        payload = {
            "x402Version": 2,
            "accepts": [{"scheme": "exact", "network": "not-caip2"}],
        }
        handler = lambda req: _b64_obj(payload)
        async with make_client(handler) as client:
            result = await engine_checks.check_caip2(client, "https://api.example.com")
        assert result.status == "FAIL"
        assert "not-caip2" in result.message

    @pytest.mark.asyncio
    async def test_top_level_takes_priority_over_accepts(self, make_client) -> None:
        payload = {
            "network": "solana:mainnet",
            "accepts": [{"network": "eip155:8453"}],
        }
        handler = lambda req: _b64_obj(payload)
        async with make_client(handler) as client:
            result = await engine_checks.check_caip2(client, "https://api.example.com")
        assert result.status == "PASS"
        assert result.details["caip2_value"] == "solana:mainnet"


class TestNetworkCandidates:
    def test_top_level_network(self) -> None:
        assert engine_checks._network_candidates({"network": "eip155:1"}) == ["eip155:1"]

    def test_chain_id_alias(self) -> None:
        assert engine_checks._network_candidates({"chainId": "solana:mainnet"}) == ["solana:mainnet"]

    def test_accepts_entries_in_order(self) -> None:
        obj = {"accepts": [{"network": "eip155:1"}, {"network": "eip155:8453"}]}
        assert engine_checks._network_candidates(obj) == ["eip155:1", "eip155:8453"]

    def test_top_level_first_then_accepts(self) -> None:
        obj = {"network": "eip155:1", "accepts": [{"network": "eip155:8453"}]}
        assert engine_checks._network_candidates(obj) == ["eip155:1", "eip155:8453"]

    def test_non_dict_accepts_entries_skipped(self) -> None:
        obj = {"accepts": ["nope", 7, {"network": "eip155:8453"}]}
        assert engine_checks._network_candidates(obj) == ["eip155:8453"]

    def test_empty_when_no_network_anywhere(self) -> None:
        assert engine_checks._network_candidates({"scheme": "exact"}) == []

    @pytest.mark.asyncio
    async def test_fail_no_payment_headers(self, make_client) -> None:
        handler = lambda req: _json_response(200, {"hello": "world"})
        async with make_client(handler) as client:
            result = await engine_checks.check_caip2(client, "https://api.example.com")
        assert result.status == "FAIL"

    @pytest.mark.asyncio
    async def test_fail_www_authenticate_wrong_prefix(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return _json_response(
                402,
                headers={"www-authenticate": f"Bearer {_b64({'network': 'eip155:8453'})}"},
            )
        async with make_client(handler) as client:
            result = await engine_checks.check_caip2(client, "https://api.example.com")
        assert result.status == "FAIL"

    @pytest.mark.asyncio
    async def test_fail_malformed_base64_skips(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return _json_response(402, headers={"payment-required": "%%not-base64%%"})
        async with make_client(handler) as client:
            result = await engine_checks.check_caip2(client, "https://api.example.com")
        assert result.status == "FAIL"

    @pytest.mark.asyncio
    async def test_fail_malformed_json_inside_base64(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return _json_response(
                402,
                headers={"payment-required": base64.b64encode(b"not json {").decode("ascii")},
            )
        async with make_client(handler) as client:
            result = await engine_checks.check_caip2(client, "https://api.example.com")
        assert result.status == "FAIL"

    @pytest.mark.asyncio
    async def test_fail_base64_decodes_to_non_dict(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return _json_response(
                402,
                headers={"payment-required": base64.b64encode(b'"just a string"').decode("ascii")},
            )
        async with make_client(handler) as client:
            result = await engine_checks.check_caip2(client, "https://api.example.com")
        assert result.status == "FAIL"

    @pytest.mark.asyncio
    async def test_pass_x_payment_required_header(self, make_client) -> None:
        """``x-payment-required`` is probed when ``payment-required`` is missing."""
        def handler(req: httpx.Request) -> httpx.Response:
            return _json_response(
                402,
                headers={"x-payment-required": _b64({"network": "eip155:8453"})},
            )
        async with make_client(handler) as client:
            result = await engine_checks.check_caip2(client, "https://api.example.com")
        assert result.status == "PASS"
        assert result.details["caip2_value"] == "eip155:8453"
        assert "X-Payment-Required" in result.message

    @pytest.mark.asyncio
    async def test_error_timeout(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("simulated")
        async with make_client(handler) as client:
            result = await engine_checks.check_caip2(client, "https://api.example.com")
        assert result.status == "FAIL"  # no headers found

    @pytest.mark.asyncio
    async def test_error_connect(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("simulated")
        async with make_client(handler) as client:
            result = await engine_checks.check_caip2(client, "https://api.example.com")
        assert result.status == "FAIL"  # no headers found

    @pytest.mark.asyncio
    async def test_error_generic(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise RuntimeError("simulated")
        async with make_client(handler) as client:
            result = await engine_checks.check_caip2(client, "https://api.example.com")
        assert result.status == "FAIL"

    @pytest.mark.asyncio
    async def test_error_http_error_subclass(self, make_client) -> None:
        """httpx.HTTPError subclasses (e.g., RemoteProtocolError) are swallowed by _safe_get."""
        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.RemoteProtocolError("simulated")
        async with make_client(handler) as client:
            result = await engine_checks.check_caip2(client, "https://api.example.com")
        assert result.status == "FAIL"


# ---------------------------------------------------------------------------
# 3b. Bot-wall detection
# ---------------------------------------------------------------------------


class TestCheckBotWall:

    @pytest.mark.asyncio
    async def test_pass_plain_200(self, make_client) -> None:
        async with make_client(lambda req: _json_response(200, {"ok": True})) as client:
            result = await engine_checks.check_bot_wall(client, "https://api.example.com")
        assert result.status == "PASS"
        assert result.details["blocked"] is False

    @pytest.mark.asyncio
    async def test_fail_cloudflare_challenge_403(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return _json_response(
                403,
                {"error": "forbidden"},
                headers={"cf-mitigated": "challenge", "server": "cloudflare"},
            )
        async with make_client(handler) as client:
            result = await engine_checks.check_bot_wall(client, "https://api.example.com")
        assert result.status == "FAIL"
        assert result.details["blocked"] is True
        assert any("cf-mitigated" in s for s in result.details["signals"])

    @pytest.mark.asyncio
    async def test_fail_sucuri_header(self, make_client) -> None:
        async with make_client(
            lambda req: _json_response(403, {"e": "x"}, headers={"x-sucuri-block": "1"})
        ) as client:
            result = await engine_checks.check_bot_wall(client, "https://api.example.com")
        assert result.status == "FAIL"
        assert result.details["blocked"] is True

    @pytest.mark.asyncio
    async def test_pass_403_without_bot_signals(self, make_client) -> None:
        """A plain 403 with no bot-wall fingerprints is not flagged."""
        async with make_client(lambda req: _json_response(403, {"error": "forbidden"})) as client:
            result = await engine_checks.check_bot_wall(client, "https://api.example.com")
        assert result.status == "PASS"
        assert result.details["blocked"] is False

    @pytest.mark.asyncio
    async def test_fail_503_two_body_markers(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(
                503,
                content=b"<html>cf_chl_xxxx <script src=\"g-recaptcha\"></script></html>",
                headers={"content-type": "text/html"},
            )
        async with make_client(handler) as client:
            result = await engine_checks.check_bot_wall(client, "https://api.example.com")
        assert result.status == "FAIL"
        assert result.details["blocked"] is True

    @pytest.mark.asyncio
    async def test_error_on_network_failure(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("simulated")
        async with make_client(handler) as client:
            result = await engine_checks.check_bot_wall(client, "https://api.example.com")
        assert result.status == "ERROR"


# ---------------------------------------------------------------------------
# 3c. accepts[] completeness
# ---------------------------------------------------------------------------


_COMPLETE_V2: dict[str, Any] = {
    "x402Version": 2,
    "error": "payment required",
    "accepts": [
        {
            "scheme": "exact",
            "network": "eip155:8453",
            "amount": "5000",
            "payTo": "0x1111111111111111111111111111111111111111",
            "resource": "https://api.example.com",
        }
    ],
}


class TestCheckAcceptsCompleteness:

    @pytest.mark.asyncio
    async def test_pass_complete_v2(self, make_client) -> None:
        async with make_client(lambda req: _b64_obj(_COMPLETE_V2)) as client:
            result = await engine_checks.check_accepts_completeness(client, "https://api.example.com")
        assert result.status == "PASS"
        assert result.details["entries_checked"] == 1
        assert result.details["findings"] == []

    @pytest.mark.asyncio
    async def test_fail_missing_payto_and_resource(self, make_client) -> None:
        payload = {
            "x402Version": 2,
            "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": "5000"}],
        }
        async with make_client(lambda req: _b64_obj(payload)) as client:
            result = await engine_checks.check_accepts_completeness(client, "https://api.example.com")
        assert result.status == "FAIL"
        joined = " ".join(result.details["findings"])
        assert "payTo" in joined
        assert "resource" in joined

    @pytest.mark.asyncio
    async def test_fail_dollar_amount(self, make_client) -> None:
        payload = {
            "x402Version": 2,
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "eip155:8453",
                    "amount": "0.005",
                    "payTo": "0x1111111111111111111111111111111111111111",
                    "resource": "https://api.example.com",
                }
            ],
        }
        async with make_client(lambda req: _b64_obj(payload)) as client:
            result = await engine_checks.check_accepts_completeness(client, "https://api.example.com")
        assert result.status == "FAIL"
        assert any("atomic" in f for f in result.details["findings"])

    @pytest.mark.asyncio
    async def test_fail_missing_x402version(self, make_client) -> None:
        payload = {k: v for k, v in _COMPLETE_V2.items() if k != "x402Version"}
        async with make_client(lambda req: _b64_obj(payload)) as client:
            result = await engine_checks.check_accepts_completeness(client, "https://api.example.com")
        assert result.status == "FAIL"
        assert any("x402Version" in f for f in result.details["findings"])

    @pytest.mark.asyncio
    async def test_fail_empty_accepts(self, make_client) -> None:
        async with make_client(lambda req: _b64_obj({"x402Version": 2, "accepts": []})) as client:
            result = await engine_checks.check_accepts_completeness(client, "https://api.example.com")
        assert result.status == "FAIL"
        assert any("accepts[]" in f for f in result.details["findings"])

    @pytest.mark.asyncio
    async def test_skip_non_402(self, make_client) -> None:
        async with make_client(lambda req: _json_response(200, {})) as client:
            result = await engine_checks.check_accepts_completeness(client, "https://api.example.com")
        assert result.status == "PASS"
        assert result.details["applicable"] is False

    @pytest.mark.asyncio
    async def test_fail_resource_url_mismatch(self, make_client) -> None:
        payload = dict(_COMPLETE_V2)
        payload["resource"] = {"url": "https://other.example.com/x"}
        async with make_client(lambda req: _b64_obj(payload)) as client:
            result = await engine_checks.check_accepts_completeness(client, "https://api.example.com")
        assert result.status == "FAIL"
        assert any("resource" in f for f in result.details["findings"])


# ---------------------------------------------------------------------------
# 3d. Discovery resource listing
# ---------------------------------------------------------------------------


class TestCheckDiscoveryResourceListing:

    @pytest.mark.asyncio
    async def test_pass_resource_listed(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            if "/.well-known/x402" in str(req.url):
                return _payload_response({"resources": [{"url": "https://api.example.com"}]})
            return _b64_obj(_COMPLETE_V2)
        async with make_client(handler) as client:
            result = await engine_checks.check_discovery_resource_listing(client, "https://api.example.com")
        assert result.status == "PASS"
        assert result.details["listed"] is True

    @pytest.mark.asyncio
    async def test_fail_resource_not_listed(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            if "/.well-known/x402" in str(req.url):
                return _payload_response({"resources": []})
            return _b64_obj(_COMPLETE_V2)
        async with make_client(handler) as client:
            result = await engine_checks.check_discovery_resource_listing(client, "https://api.example.com")
        assert result.status == "FAIL"
        assert "not listed" in result.message
        assert result.details["listed"] is False

    @pytest.mark.asyncio
    async def test_skip_non_402(self, make_client) -> None:
        async with make_client(lambda req: _json_response(200, {})) as client:
            result = await engine_checks.check_discovery_resource_listing(client, "https://api.example.com")
        assert result.status == "PASS"
        assert result.details["applicable"] is False

    @pytest.mark.asyncio
    async def test_pass_no_resource_declared(self, make_client) -> None:
        payload = {
            "x402Version": 2,
            "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": "5000", "payTo": "0xabc"}],
        }
        async with make_client(lambda req: _b64_obj(payload)) as client:
            result = await engine_checks.check_discovery_resource_listing(client, "https://api.example.com")
        assert result.status == "PASS"
        assert result.details["listed"] is None

    @pytest.mark.asyncio
    async def test_error_catalog_unreachable(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            if "/.well-known/x402" in str(req.url):
                raise httpx.ConnectError("simulated")
            return _b64_obj(_COMPLETE_V2)
        async with make_client(handler) as client:
            result = await engine_checks.check_discovery_resource_listing(client, "https://api.example.com")
        assert result.status == "ERROR"


# ---------------------------------------------------------------------------
# 4. JSON resilience
# ---------------------------------------------------------------------------


class TestCheckJsonResilience:

    @pytest.mark.asyncio
    async def test_pass_status_200(self, make_client) -> None:
        async with make_client(lambda req: _json_response(200)) as client:
            result = await engine_checks.check_json_resilience(client, "https://api.example.com")
        assert result.status == "PASS"
        assert result.details["status_code"] == 200

    @pytest.mark.asyncio
    async def test_pass_402_with_dict_body(self, make_client) -> None:
        async with make_client(lambda req: _json_response(402, {"accepts": []})) as client:
            result = await engine_checks.check_json_resilience(client, "https://api.example.com")
        assert result.status == "PASS"
        assert result.details["is_dict"] is True

    @pytest.mark.asyncio
    async def test_critical_fail_402_with_string(self, make_client) -> None:
        async with make_client(lambda req: _json_response(402, "just a string")) as client:
            result = await engine_checks.check_json_resilience(client, "https://api.example.com")
        assert result.status == "CRITICAL_FAIL"
        assert "JSON primitive" in result.message
        assert "object" in result.message

    @pytest.mark.asyncio
    async def test_critical_fail_402_with_number(self, make_client) -> None:
        async with make_client(lambda req: _json_response(402, 42)) as client:
            result = await engine_checks.check_json_resilience(client, "https://api.example.com")
        assert result.status == "CRITICAL_FAIL"

    @pytest.mark.asyncio
    async def test_critical_fail_402_with_array(self, make_client) -> None:
        async with make_client(lambda req: _json_response(402, ["x", "y"])) as client:
            result = await engine_checks.check_json_resilience(client, "https://api.example.com")
        assert result.status == "CRITICAL_FAIL"

    @pytest.mark.asyncio
    async def test_critical_fail_402_with_null(self, make_client) -> None:
        async with make_client(lambda req: _json_response(402, None)) as client:
            result = await engine_checks.check_json_resilience(client, "https://api.example.com")
        assert result.status == "CRITICAL_FAIL"

    @pytest.mark.asyncio
    async def test_critical_fail_402_invalid_json(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(402, content=b"<html>not json</html>", request=req)
        async with make_client(handler) as client:
            result = await engine_checks.check_json_resilience(client, "https://api.example.com")
        assert result.status == "CRITICAL_FAIL"

    @pytest.mark.asyncio
    async def test_error_timeout(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("simulated")
        async with make_client(handler) as client:
            result = await engine_checks.check_json_resilience(client, "https://api.example.com")
        assert result.status == "ERROR"

    @pytest.mark.asyncio
    async def test_error_connect_error(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("nope")
        async with make_client(handler) as client:
            result = await engine_checks.check_json_resilience(client, "https://api.example.com")
        assert result.status == "ERROR"

    @pytest.mark.asyncio
    async def test_error_unexpected_exception(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise ValueError("simulated")
        async with make_client(handler) as client:
            result = await engine_checks.check_json_resilience(client, "https://api.example.com")
        assert result.status == "ERROR"


# ---------------------------------------------------------------------------
# 5. Bazaar compliance
# ---------------------------------------------------------------------------


class TestCheckBazaar:
    """Shape verified against every production capture that carries the
    block (Viridis regulatory-radar, Viridis ghg-ledger, AsterPay
    crypto-prices, AsterPay sentiment) — see upstream PR #16
    (smartflowproai-lang/x402-endpoint-validator) for the full derivation.
    The block is OPTIONAL: absence is conformant (PASS)."""

    def test_pass_full(self) -> None:
        body = {
            "extensions": {
                "bazaar": {
                    "info": {
                        "input": {"type": "http", "method": "POST"},
                        "output": {"type": "json", "example": {"ok": True}},
                    },
                    "schema": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"},
                }
            }
        }
        result = engine_checks.check_bazaar(body)
        assert isinstance(result, BazaarResult)
        assert result.status == "PASS"
        assert "matches the observed production shape" in result.message
        assert result.details["missing_fields"] == []
        assert result.details["bazaar_present"] is True

    def test_pass_full_without_schema(self) -> None:
        """schema is recommended but not strictly required by any capture check."""
        body = {
            "extensions": {
                "bazaar": {
                    "info": {
                        "input": {"type": "http", "method": "GET"},
                        "output": {"type": "json", "example": {}},
                    }
                }
            }
        }
        result = engine_checks.check_bazaar(body)
        assert result.status == "PASS"

    def test_pass_no_body(self) -> None:
        """No 402 body → bazaar check skipped, treated as PASS."""
        result = engine_checks.check_bazaar(None)
        assert result.status == "PASS"
        assert "skipped" in result.message

    def test_pass_missing_bazaar_block(self) -> None:
        """Block is optional — absence is conformant, not a failure."""
        result = engine_checks.check_bazaar({"extensions": {}})
        assert result.status == "PASS"
        assert bazaar_not_present() == result.message
        assert result.details["bazaar_present"] is False

    def test_pass_no_extensions_at_all(self) -> None:
        result = engine_checks.check_bazaar({"x402Version": 2, "accepts": []})
        assert result.status == "PASS"
        assert result.details["bazaar_present"] is False

    def test_pass_non_dict_body(self) -> None:
        """Non-dict body: nothing to validate, treated as absent (PASS)."""
        result = engine_checks.check_bazaar("not a dict")
        assert result.status == "PASS"
        assert result.details["bazaar_present"] is False

    def test_fail_bazaar_not_an_object(self) -> None:
        body = {"extensions": {"bazaar": "not-an-object"}}
        result = engine_checks.check_bazaar(body)
        assert result.status == "FAIL"
        assert result.details["bazaar_present"] is True

    def test_fail_missing_info(self) -> None:
        body = {"extensions": {"bazaar": {"schema": {"type": "object"}}}}
        result = engine_checks.check_bazaar(body)
        assert result.status == "FAIL"
        assert any("info" in m for m in result.details["missing_fields"])

    def test_fail_missing_input_method(self) -> None:
        body = {
            "extensions": {
                "bazaar": {
                    "info": {
                        "input": {"type": "http"},
                        "output": {"type": "json", "example": {}},
                    }
                }
            }
        }
        result = engine_checks.check_bazaar(body)
        assert result.status == "FAIL"
        assert any("info.input.method" in m for m in result.details["missing_fields"])

    def test_fail_missing_input_type(self) -> None:
        body = {
            "extensions": {
                "bazaar": {
                    "info": {
                        "input": {"method": "GET"},
                        "output": {"type": "json", "example": {}},
                    }
                }
            }
        }
        result = engine_checks.check_bazaar(body)
        assert result.status == "FAIL"
        assert any("info.input.type" in m for m in result.details["missing_fields"])

    def test_fail_missing_output_type(self) -> None:
        body = {
            "extensions": {
                "bazaar": {
                    "info": {
                        "input": {"type": "http", "method": "GET"},
                        "output": {"example": {}},
                    }
                }
            }
        }
        result = engine_checks.check_bazaar(body)
        assert result.status == "FAIL"
        assert any("info.output.type" in m for m in result.details["missing_fields"])

    def test_fail_missing_output(self) -> None:
        body = {
            "extensions": {
                "bazaar": {
                    "info": {
                        "input": {"type": "http", "method": "GET"},
                    }
                }
            }
        }
        result = engine_checks.check_bazaar(body)
        assert result.status == "FAIL"
        assert any("info.output" in m for m in result.details["missing_fields"])

    def test_fail_schema_not_an_object(self) -> None:
        body = {
            "extensions": {
                "bazaar": {
                    "info": {
                        "input": {"type": "http", "method": "GET"},
                        "output": {"type": "json", "example": {}},
                    },
                    "schema": "not-an-object",
                }
            }
        }
        result = engine_checks.check_bazaar(body)
        assert result.status == "FAIL"
        assert any("schema" in m for m in result.details["missing_fields"])

    def test_fail_multiple_missing_fields(self) -> None:
        body = {"extensions": {"bazaar": {"info": {}}}}
        result = engine_checks.check_bazaar(body)
        assert result.status == "FAIL"
        missing = result.details["missing_fields"]
        assert any("info.input" in m for m in missing)
        assert any("info.output" in m for m in missing)

    def test_pass_real_viridis_regulatory_radar_shape(self) -> None:
        """Regression guard against the real Viridis capture shape."""
        body = {
            "extensions": {
                "bazaar": {
                    "info": {
                        "input": {
                            "body": {"jurisdiction": "US", "query": "x", "sector": "energy"},
                            "bodyType": "json",
                            "method": "POST",
                            "type": "http",
                        },
                        "output": {"example": {"status": "success"}, "type": "json"},
                    },
                    "schema": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"},
                }
            }
        }
        result = engine_checks.check_bazaar(body)
        assert result.status == "PASS"

    def test_pass_real_asterpay_shape(self) -> None:
        """Regression guard against the real AsterPay capture shape."""
        body = {
            "extensions": {
                "bazaar": {
                    "info": {
                        "input": {"type": "http", "method": "GET", "queryParams": {"symbols": "BTC"}},
                        "output": {"type": "json", "example": {"BTC": {"price": 1}}},
                    },
                    "schema": {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"},
                }
            }
        }
        result = engine_checks.check_bazaar(body)
        assert result.status == "PASS"


# ---------------------------------------------------------------------------
# 6. Bazaar from URL convenience wrapper
# ---------------------------------------------------------------------------


class TestCheckBazaarForUrl:

    @pytest.mark.asyncio
    async def test_pass_full(self, make_client) -> None:
        body = {
            "extensions": {
                "bazaar": {
                    "info": {
                        "input": {"type": "http", "method": "POST"},
                        "output": {"type": "json", "example": {}},
                    }
                }
            }
        }
        handler = lambda req: _json_response(402, body)
        async with make_client(handler) as client:
            result = await engine_checks.check_bazaar_for_url(client, "https://api.example.com")
        assert result.status == "PASS"

    @pytest.mark.asyncio
    async def test_pass_absent_block_is_optional(self, make_client) -> None:
        """Block is optional — absence is conformant, not a failure."""
        handler = lambda req: _json_response(402, {"x402Version": 2, "accepts": []})
        async with make_client(handler) as client:
            result = await engine_checks.check_bazaar_for_url(client, "https://api.example.com")
        assert result.status == "PASS"

    @pytest.mark.asyncio
    async def test_fail_present_but_malformed(self, make_client) -> None:
        body = {"extensions": {"bazaar": {"info": {}}}}
        handler = lambda req: _json_response(402, body)
        async with make_client(handler) as client:
            result = await engine_checks.check_bazaar_for_url(client, "https://api.example.com")
        assert result.status == "FAIL"

    @pytest.mark.asyncio
    async def test_skipped_no_402(self, make_client) -> None:
        handler = lambda req: _json_response(200)
        async with make_client(handler) as client:
            result = await engine_checks.check_bazaar_for_url(client, "https://api.example.com")
        assert result.status == "PASS"
        assert "skipped" in result.message

    @pytest.mark.asyncio
    async def test_skipped_primitive_402(self, make_client) -> None:
        """Primitive 402 → bazaar skipped because body is not a dict."""
        async with make_client(lambda req: _json_response(402, "string")) as client:
            result = await engine_checks.check_bazaar_for_url(client, "https://api.example.com")
        assert result.status == "PASS"
        assert "skipped" in result.message


# ---------------------------------------------------------------------------
# 7. Marketplace catalog
# ---------------------------------------------------------------------------


def _valid_product(pid: str = "p1") -> dict[str, Any]:
    return {
        "id": pid,
        "name": f"Product {pid}",
        "endpoint": f"/x/{pid}",
        "x402": {
            "scheme": "exact",
            "network": "eip155:8453",
            "pay_to": "0xabc",
            "facilitator_url": "https://facilitator.example",
        },
    }


class TestCheckMarketplace:

    @pytest.mark.asyncio
    async def test_pass_all_conformant(self, make_client) -> None:
        manifest = {"products": [_valid_product("a"), _valid_product("b")]}
        async with make_client(lambda req: _json_response(200, {})) as client:
            result = await engine_checks.check_marketplace(client, "https://api.example.com", manifest)
        assert isinstance(result, MarketplaceResult)
        assert result.status == "PASS"
        assert result.total_products == 2
        assert result.conformant_count == 2

    @pytest.mark.asyncio
    async def test_fail_missing_x402_block(self, make_client) -> None:
        manifest = {"products": [{"id": "p1", "name": "x", "endpoint": "/x"}]}
        async with make_client(lambda req: _json_response(200, {})) as client:
            result = await engine_checks.check_marketplace(client, "https://api.example.com", manifest)
        assert result.status == "FAIL"
        assert result.conformant_count == 0
        assert result.details["product_details"][0]["errors"] == ["missing x402 block"]

    @pytest.mark.asyncio
    async def test_fail_wrong_scheme(self, make_client) -> None:
        p = _valid_product("p1")
        p["x402"]["scheme"] = "upto"
        async with make_client(lambda req: _json_response(200, {})) as client:
            result = await engine_checks.check_marketplace(client, "https://api.example.com", {"products": [p]})
        assert result.status == "FAIL"
        errors = result.details["product_details"][0]["errors"]
        assert any("scheme should be 'exact'" in e for e in errors), f"got errors={errors}"


    @pytest.mark.asyncio
    async def test_fail_invalid_caip2_network(self, make_client) -> None:
        p = _valid_product("p1")
        p["x402"]["network"] = "ethereum"
        async with make_client(lambda req: _json_response(200, {})) as client:
            result = await engine_checks.check_marketplace(client, "https://api.example.com", {"products": [p]})
        assert result.status == "FAIL"

    @pytest.mark.asyncio
    async def test_fail_missing_pay_to(self, make_client) -> None:
        p = _valid_product("p1")
        del p["x402"]["pay_to"]
        async with make_client(lambda req: _json_response(200, {})) as client:
            result = await engine_checks.check_marketplace(client, "https://api.example.com", {"products": [p]})
        assert result.status == "FAIL"

    @pytest.mark.asyncio
    async def test_fail_missing_facilitator_url(self, make_client) -> None:
        p = _valid_product("p1")
        del p["x402"]["facilitator_url"]
        async with make_client(lambda req: _json_response(200, {})) as client:
            result = await engine_checks.check_marketplace(client, "https://api.example.com", {"products": [p]})
        assert result.status == "FAIL"

    @pytest.mark.asyncio
    async def test_fail_non_get_method(self, make_client) -> None:
        p = _valid_product("p1")
        p["method"] = "POST"
        async with make_client(lambda req: _json_response(200, {})) as client:
            result = await engine_checks.check_marketplace(client, "https://api.example.com", {"products": [p]})
        assert result.status == "FAIL"

    @pytest.mark.asyncio
    async def test_fail_pay_to_alias_accepted(self, make_client) -> None:
        """`payTo` is an accepted alias for `pay_to`."""
        p = _valid_product("p1")
        del p["x402"]["pay_to"]
        p["x402"]["payTo"] = "0xabc"
        async with make_client(lambda req: _json_response(200, {})) as client:
            result = await engine_checks.check_marketplace(client, "https://api.example.com", {"products": [p]})
        assert result.status == "PASS"

    @pytest.mark.asyncio
    async def test_fail_no_products(self, make_client) -> None:
        async with make_client(lambda req: _json_response(200, {})) as client:
            result = await engine_checks.check_marketplace(client, "https://api.example.com", {})
        assert result.status == "FAIL"
        assert result.total_products == 0

    @pytest.mark.asyncio
    async def test_fail_products_not_list(self, make_client) -> None:
        async with make_client(lambda req: _json_response(200, {})) as client:
            result = await engine_checks.check_marketplace(client, "https://api.example.com", {"products": "x"})
        assert result.status == "FAIL"

    @pytest.mark.asyncio
    async def test_handles_non_dict_product(self, make_client) -> None:
        manifest = {"products": [_valid_product("a"), "not a dict", _valid_product("b")]}
        async with make_client(lambda req: _json_response(200, {})) as client:
            result = await engine_checks.check_marketplace(client, "https://api.example.com", manifest)
        assert result.status == "FAIL"
        assert result.total_products == 3
        assert result.conformant_count == 2

    @pytest.mark.asyncio
    async def test_x402_block_not_dict(self, make_client) -> None:
        """A product with x402 that's not a dict should be marked non-conformant."""
        manifest = {"products": [_valid_product("a") | {"x402": "invalid"}]}
        async with make_client(lambda req: _json_response(200, {})) as client:
            result = await engine_checks.check_marketplace(client, "https://api.example.com", {"products": manifest["products"]})
        errors = result.details["product_details"][0]["errors"]
        assert any("x402 block is not an object" in e for e in errors)


# ---------------------------------------------------------------------------
# 8. Per-product endpoint walk
# ---------------------------------------------------------------------------


class TestCheckProductEndpoint:

    @pytest.mark.asyncio
    async def test_pass_free_200(self, make_client) -> None:
        handler = lambda req: _json_response(200)
        async with make_client(handler) as client:
            result = await engine_checks.check_product_endpoint(
                client, "https://api.example.com", {"id": "f1", "name": "Free", "endpoint": "/free"}
            )
        assert isinstance(result, ProductResult)
        assert result.status == "PASS"
        assert result.details["is_free"] is True

    @pytest.mark.asyncio
    async def test_fail_free_wrong_status(self, make_client) -> None:
        handler = lambda req: _json_response(403)
        async with make_client(handler) as client:
            result = await engine_checks.check_product_endpoint(
                client, "https://api.example.com", {"id": "f1", "name": "Free", "endpoint": "/free"}
            )
        assert result.status == "FAIL"

    @pytest.mark.asyncio
    async def test_pass_paid_402_with_header(self, make_client) -> None:
        handler = lambda req: _json_response(402, headers={"payment-required": _b64({"network": "eip155:1"})})
        async with make_client(handler) as client:
            result = await engine_checks.check_product_endpoint(
                client,
                "https://api.example.com",
                _valid_product("p1"),
            )
        assert result.status == "PASS"
        assert result.details["has_payment_header"] is True

    @pytest.mark.asyncio
    async def test_pass_paid_402_with_x_header_alias(self, make_client) -> None:
        handler = lambda req: _json_response(402, headers={"x-payment-required": _b64({"network": "eip155:1"})})
        async with make_client(handler) as client:
            result = await engine_checks.check_product_endpoint(
                client,
                "https://api.example.com",
                _valid_product("p2"),
            )
        assert result.status == "PASS"

    @pytest.mark.asyncio
    async def test_fail_paid_402_no_header(self, make_client) -> None:
        handler = lambda req: _json_response(402, {"x402Version": 2, "accepts": []})
        async with make_client(handler) as client:
            result = await engine_checks.check_product_endpoint(
                client,
                "https://api.example.com",
                _valid_product("p3"),
            )
        assert result.status == "FAIL"
        assert "Payment-Required header is absent" in result.message

    @pytest.mark.asyncio
    async def test_fail_paid_returns_200(self, make_client) -> None:
        async with make_client(lambda req: _json_response(200)) as client:
            result = await engine_checks.check_product_endpoint(
                client,
                "https://api.example.com",
                _valid_product("p4"),
            )
        assert result.status == "FAIL"
        assert "should return 402" in result.message

    @pytest.mark.asyncio
    async def test_fail_no_endpoint(self, make_client) -> None:
        async with make_client(lambda req: _json_response(200)) as client:
            result = await engine_checks.check_product_endpoint(
                client,
                "https://api.example.com",
                {"id": "p5", "name": "x"},
            )
        assert result.status == "ERROR"
        assert "no 'endpoint' field" in result.message

    @pytest.mark.asyncio
    async def test_error_timeout(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("simulated")
        async with make_client(handler) as client:
            result = await engine_checks.check_product_endpoint(
                client,
                "https://api.example.com",
                _valid_product("p6"),
            )
        assert result.status == "ERROR"
        assert "timed out" in result.message

    @pytest.mark.asyncio
    async def test_error_connect_error(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("nope")
        async with make_client(handler) as client:
            result = await engine_checks.check_product_endpoint(
                client,
                "https://api.example.com",
                _valid_product("p7"),
            )
        assert result.status == "ERROR"

    @pytest.mark.asyncio
    async def test_unexpected_status(self, make_client) -> None:
        handler = lambda req: _json_response(503)
        async with make_client(handler) as client:
            result = await engine_checks.check_product_endpoint(
                client,
                "https://api.example.com",
                _valid_product("p8"),
            )
        assert result.status == "ERROR"

    @pytest.mark.asyncio
    async def test_error_unexpected_exception(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise RuntimeError("simulated")
        async with make_client(handler) as client:
            result = await engine_checks.check_product_endpoint(
                client,
                "https://api.example.com",
                _valid_product("p9"),
            )
        assert result.status == "ERROR"


# ---------------------------------------------------------------------------
# 9. X402Auditor orchestrator
# ---------------------------------------------------------------------------


class TestX402Auditor:

    def test_construction_parameters(self) -> None:
        a = X402Auditor(timeout=5.0, default_headers={"X-Test": "1"})
        assert a._timeout == 5.0
        assert a._default_headers == {"X-Test": "1"}

    @pytest.mark.asyncio
    async def test_auditor_requires_context(self) -> None:
        a = X402Auditor()
        with pytest.raises(RuntimeError, match="async with X402Auditor"):
            await a.run_full_audit("https://api.example.com")

    @pytest.mark.asyncio
    async def test_invalid_mode_raises(self) -> None:
        async with X402Auditor() as auditor:
            with pytest.raises(ValueError, match="mode must be"):
                await auditor.run_full_audit("https://api.example.com", mode="bogus")

    @pytest.mark.asyncio
    async def test_aggregates_passing_checks(self, make_client) -> None:
        """All 7 checks pass when endpoint serves a manifest listing the audited
        resource, returns 402 with valid Payment-Required header whose accepts[]
        entry is complete, and 402 body is JSON + bazaar."""

        bazaar = {
            "info": {
                "input": {"type": "http", "method": "POST"},
                "output": {"type": "json", "example": {"temp_f": 72}},
            },
        }
        payment = {
            "network": "eip155:8453",
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "100",
                "payTo": "0x1111111111111111111111111111111111111111",
                "resource": "https://api.example.com",
            }],
            "x402Version": 2,
            "extensions": {"bazaar": bazaar},
        }

        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "/.well-known/x402" in url:
                return _payload_response({
                    "accepts": [{"scheme": "exact", "network": "eip155:8453"}],
                    "resources": [{"url": "https://api.example.com"}],
                })
            return _b64_obj(payment)

        async with X402Auditor(transport=httpx.MockTransport(handler)) as auditor:
            report = await auditor.run_full_audit("https://api.example.com")

        assert isinstance(report, AuditReport)
        assert report.overall_status == "PASS", \
            f"checks={[c.check_name + '=' + c.status for c in report.checks]}"
        assert len(report.checks) == 7

    @pytest.mark.asyncio
    async def test_aggregates_critical_fail_priority(self, make_client) -> None:
        """CRITICAL_FAIL must dominate FAIL in overall_status."""

        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "/.well-known/x402" in url:
                return _json_response(404)
            return _json_response(402, "not a dict")
        async with X402Auditor(transport=httpx.MockTransport(handler)) as auditor:
            report = await auditor.run_full_audit("https://api.example.com")
        assert report.overall_status == "CRITICAL_FAIL"
        statuses = [c.status for c in report.checks]
        assert "CRITICAL_FAIL" in statuses

    @pytest.mark.asyncio
    async def test_aggregates_fail_priority_over_error(self, make_client) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "/.well-known/x402" in url:
                return _json_response(404)
            raise httpx.ConnectError("simulated")

        async with X402Auditor(transport=httpx.MockTransport(handler)) as auditor:
            report = await auditor.run_full_audit("https://api.example.com")
        assert report.overall_status == "FAIL"

    @pytest.mark.asyncio
    async def test_marketplace_mode_runs_extra_checks(self, make_client) -> None:
        handler = lambda req: _payload_response({"products": [_valid_product("a")]})
        async with X402Auditor(transport=httpx.MockTransport(handler)) as auditor:
            report = await auditor.run_full_audit(
                "https://api.example.com", mode=CheckMode.MARKETPLACE,
            )
        names = [c.check_name for c in report.checks]
        assert "marketplace_products" in names
        assert any(n.startswith("product_check") for n in names)

    @pytest.mark.asyncio
    async def test_marketplace_caip2_falls_back_to_product_payloads(self, make_client) -> None:
        """A free-discovery root (HTTP 200, no payment headers) must not mask
        the valid CAIP-2 networks declared in paid products' 402
        PaymentRequired payloads. Regression: the audit used to FAIL
        caip2_compliance against the root alone and never look at products."""
        product = _valid_product("paid1")
        v2_payload = {
            "x402Version": 2,
            "error": "payment required",
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "eip155:8453",
                    "amount": "10000",
                    "payTo": "0x1111111111111111111111111111111111111111",
                }
            ],
        }

        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "/.well-known/x402" in url:
                return _payload_response({"products": [product]})
            if product["endpoint"] in url:
                return _b64_obj(v2_payload)
            return _json_response(200, {"catalog": "free"})

        async with X402Auditor(transport=httpx.MockTransport(handler)) as auditor:
            report = await auditor.run_full_audit(
                "https://api.example.com", mode=CheckMode.MARKETPLACE,
            )

        caip2 = [c for c in report.checks if c.check_name == "caip2_compliance"]
        assert caip2, "caip2 check missing from report"
        assert not any(c.status == "FAIL" for c in caip2), \
            f"checks={[c.check_name + '=' + c.status for c in report.checks]}"
        assert caip2[0].status == "PASS"
        assert caip2[0].details["header_name"] == "product.payment-required"
        assert caip2[0].details["caip2_value"] == "eip155:8453"
        assert report.overall_status == "PASS", \
            f"checks={[c.check_name + '=' + c.status for c in report.checks]}"

    @pytest.mark.asyncio
    async def test_manifest_accepts_network_fallback_standard_mode(self, make_client) -> None:
        """Standard mode: free root (200) + manifest declaring accepts[].network
        must yield caip2 PASS. Regression: AsterPay's manifest declares
        accepts[].network = eip155:8453 yet audited FAIL before this fix."""
        bazaar = {
            "info": {
                "input": {"type": "http", "method": "GET"},
                "output": {"type": "json"},
            },
        }

        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "/.well-known/x402" in url:
                return _payload_response({
                    "x402Version": 2,
                    "payTo": "0xabc",
                    "accepts": [
                        {"scheme": "exact", "network": "eip155:8453"}
                    ],
                    "resources": [],
                })
            return _json_response(200, {"docs": "free"})

        async with X402Auditor(transport=httpx.MockTransport(handler)) as auditor:
            report = await auditor.run_full_audit("https://api.example.com")

        caip2 = [c for c in report.checks if c.check_name == "caip2_compliance"]
        assert len(caip2) == 1
        assert caip2[0].status == "PASS"
        assert caip2[0].details["header_name"] == "manifest.accepts"
        assert caip2[0].details["caip2_value"] == "eip155:8453"

    @pytest.mark.asyncio
    async def test_manifest_resources_accepts_network_fallback(self, make_client) -> None:
        """Networks declared under resources[].accepts[].network also count."""
        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "/.well-known/x402" in url:
                return _payload_response({
                    "resources": [
                        {
                            "url": "https://api.example.com/v1/price",
                            "accepts": [
                                {"scheme": "exact", "network": "eip155:8453"}
                            ],
                        }
                    ]
                })
            return _json_response(200, {"docs": "free"})

        async with X402Auditor(transport=httpx.MockTransport(handler)) as auditor:
            report = await auditor.run_full_audit("https://api.example.com")

        caip2 = [c for c in report.checks if c.check_name == "caip2_compliance"]
        assert len(caip2) == 1
        assert caip2[0].status == "PASS"
        assert caip2[0].details["header_name"] == "manifest.resources.accepts"

    @pytest.mark.asyncio
    async def test_no_fallback_when_root_has_valid_header(self, make_client) -> None:
        """Root header result wins when present; manifest fallback stays out."""
        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "/.well-known/x402" in url:
                return _payload_response({"network": "solana:mainnet"})
            return _b64_obj({"network": "eip155:8453"})

        async with X402Auditor(transport=httpx.MockTransport(handler)) as auditor:
            report = await auditor.run_full_audit("https://api.example.com")

        caip2 = [c for c in report.checks if c.check_name == "caip2_compliance"]
        assert caip2[0].details["caip2_value"] == "eip155:8453"
        assert caip2[0].details["header_name"] != "manifest.network"

    @pytest.mark.asyncio
    async def test_marketplace_mode_handles_manifest_fetch_error(self, make_client) -> None:
        """If the manifest fetch fails in marketplace mode, marketplace check still runs."""
        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "/.well-known/x402" in url:
                raise httpx.ConnectError("simulated")
            return _json_response(200, {})
        async with X402Auditor(transport=httpx.MockTransport(handler)) as auditor:
            report = await auditor.run_full_audit(
                "https://api.example.com", mode=CheckMode.MARKETPLACE,
            )
        # Should still complete without raising — overall status is whatever
        # the worst check was.
        assert isinstance(report, AuditReport)

    @pytest.mark.asyncio
    async def test_marketplace_mode_probes_top_level_network(self, make_client) -> None:
        """Manifest declares network at top level — extra CAIP-2 check fires."""
        manifest = {
            "network": "eip155:8453",
            "products": [_valid_product("a"), _valid_product("b")],
        }
        handler = lambda req: _payload_response(manifest)
        async with X402Auditor(transport=httpx.MockTransport(handler)) as auditor:
            report = await auditor.run_full_audit(
                "https://api.example.com", mode=CheckMode.MARKETPLACE,
            )

        # Look for the manifest.network check explicitly.
        manifest_network_checks = [
            c for c in report.checks
            if c.details
            and isinstance(c.details, dict)
            and c.details.get("header_name") == "manifest.network"
        ]
        assert manifest_network_checks, (
            f"missing manifest.network check; checks={[c.check_name for c in report.checks]}"
        )
        assert manifest_network_checks[0].status == "PASS"

    @pytest.mark.asyncio
    async def test_marketplace_mode_per_product_bazaar_pass(self, make_client) -> None:
        """When a paid product returns 402 + bazaar, a per-product bazaar check is added."""
        product = _valid_product("paid_x")
        bazaar = {"info": {"input": {"type": "http", "method": "POST"}, "output": {"type": "json", "example": {}}}}
        payment = {
            "network": "eip155:8453",
            "x402Version": 2,
            "accepts": [],
            "extensions": {"bazaar": bazaar},
        }

        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "/.well-known/x402" in url:
                return _payload_response({"products": [product]})
            return _b64_obj(payment)

        async with X402Auditor(transport=httpx.MockTransport(handler)) as auditor:
            report = await auditor.run_full_audit(
                "https://api.example.com", mode=CheckMode.MARKETPLACE,
            )

        per_product_bazaar = [c for c in report.checks if c.check_name == "bazaar_paid_x"]
        assert per_product_bazaar, f"missing per-product bazaar; checks={[c.check_name for c in report.checks]}"
        assert per_product_bazaar[0].status == "PASS"

    @pytest.mark.asyncio
    async def test_marketplace_mode_handles_manifest_non_dict(self, make_client) -> None:
        """If manifest body parses as non-dict (e.g., list), treat as empty products."""
        def handler(req: httpx.Request) -> httpx.Response:
            if ".well-known/x402" in str(req.url):
                return _payload_response([])
            return _json_response(200, {})
        async with X402Auditor(transport=httpx.MockTransport(handler)) as auditor:
            report = await auditor.run_full_audit(
                "https://api.example.com", mode=CheckMode.MARKETPLACE,
            )
        assert any(c.check_name == "marketplace_products" for c in report.checks)

    @pytest.mark.asyncio
    async def test_marketplace_mode_handles_products_string(self, make_client) -> None:
        """If 'products' is not a list, skip per-product loop."""
        def handler(req: httpx.Request) -> httpx.Response:
            if ".well-known/x402" in str(req.url):
                return _payload_response({"products": "not a list"})
            return _json_response(200, {})
        async with X402Auditor(transport=httpx.MockTransport(handler)) as auditor:
            report = await auditor.run_full_audit(
                "https://api.example.com", mode=CheckMode.MARKETPLACE,
            )
        names = [c.check_name for c in report.checks]
        # marketplace_products ran but no product_check entries appended
        assert "marketplace_products" in names
        assert not any(n.startswith("product_check") for n in names)

    @pytest.mark.asyncio
    async def test_marketplace_mode_skips_non_dict_products(self, make_client) -> None:
        """An entry in products that isn't a dict must be skipped (no crash)."""
        valid = _valid_product("a")
        def handler(req: httpx.Request) -> httpx.Response:
            if ".well-known/x402" in str(req.url):
                return _payload_response({"products": [valid, "not a dict"]})
            return _json_response(200, {})
        async with X402Auditor(transport=httpx.MockTransport(handler)) as auditor:
            report = await auditor.run_full_audit(
                "https://api.example.com", mode=CheckMode.MARKETPLACE,
            )
        product_checks = [c for c in report.checks if c.check_name == "product_check"]
        assert len(product_checks) == 1
        assert product_checks[0].product_id == "a"

    @pytest.mark.asyncio
    async def test_marketplace_mode_handles_unreachable_403(self, make_client) -> None:
        """When a paid endpoint returns non-402, per-product bazaar is skipped."""
        product = _valid_product("a")
        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "/.well-known/x402" in url:
                return _payload_response({"products": [product]})
            # Force product endpoint to return 200 (not 402) — express uses
            # this to short-circuit _fetch_402_body.
            return _json_response(200, {})
        async with X402Auditor(transport=httpx.MockTransport(handler)) as auditor:
            report = await auditor.run_full_audit(
                "https://api.example.com", mode=CheckMode.MARKETPLACE,
            )
        # product_check should be FAIL (paid returned 200), and no per-product
        # bazaar_<id> entries appended. The standard 'bazaar_compliance' check
        # is unrelated and will still be present.
        per_product_bazaar = [
            c for c in report.checks
            if c.check_name.startswith("bazaar_") and c.check_name != "bazaar_compliance"
        ]
        assert per_product_bazaar == []



    @pytest.mark.asyncio
    async def test_marketplace_mode_bazaar_endpoint_throws(self, make_client) -> None:
        """Exception while fetching a paid endpoint's body is swallowed by _fetch_402_body."""
        product = _valid_product("a")
        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "/.well-known/x402" in url:
                return _payload_response({"products": [product]})
            if url.endswith("/") and "/a" not in url.rstrip("/")[:-1]:
                return _b64_obj({"network": "eip155:8453", "x402Version": 2,
                                "accepts": [], "extensions": {"bazaar": {"info": {"input": {"type": "http", "method": "POST"}, "output": {"type": "json", "example": {}}}}}})
            if "/a" in url:
                # 402 with valid Payment-Required header BUT body that fails to parse
                return httpx.Response(402, content=b"<broken",
                                      request=req,
                                      headers={"payment-required": _b64({"network": "eip155:8453"}),
                                               "content-type": "application/json"})
            return _json_response(200, {})
        async with X402Auditor(transport=httpx.MockTransport(handler)) as auditor:
            report = await auditor.run_full_audit(
                "https://api.example.com", mode=CheckMode.MARKETPLACE,
            )
        per_product_bazaar = [c for c in report.checks if c.check_name.startswith("bazaar_") and c.check_name != "bazaar_compliance"]
        assert len(per_product_bazaar) >= 1

    @pytest.mark.asyncio
    async def test_marketplace_mode_bazaar_endpoint_non_dict_body(self, make_client) -> None:
        """402 Response with non-dict body to _fetch_402_body short-circuits to None."""
        product = _valid_product("a")
        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "/.well-known/x402" in url:
                return _payload_response({"products": [product]})
            if url.endswith("/") and "/a" not in url.rstrip("/")[:-1]:
                return _b64_obj({"network": "eip155:8453", "x402Version": 2,
                                "accepts": [], "extensions": {"bazaar": {"info": {"input": {"type": "http", "method": "POST"}, "output": {"type": "json", "example": {}}}}}})
            if "/a" in url:
                # 402 with valid header BUT body is JSON primitive, not dict
                return httpx.Response(402, content=b'"just a string"',
                                      request=req,
                                      headers={"payment-required": _b64({"network": "eip155:8453"}),
                                               "content-type": "application/json"})
            return _json_response(200, {})
        async with X402Auditor(transport=httpx.MockTransport(handler)) as auditor:
            report = await auditor.run_full_audit(
                "https://api.example.com", mode=CheckMode.MARKETPLACE,
            )
        per_product_bazaar = [c for c in report.checks if c.check_name.startswith("bazaar_") and c.check_name != "bazaar_compliance"]
        assert len(per_product_bazaar) >= 1

    @pytest.mark.asyncio
    async def test_marketplace_mode_bazaar_endpoint_exception(self, make_client) -> None:
        """Generic exception in _fetch_402_body is swallowed; bazaar falls through."""
        product = _valid_product("a")
        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "/.well-known/x402" in url:
                return _payload_response({"products": [product]})
            if url.endswith("/") and "/a" not in url.rstrip("/")[:-1]:
                return _b64_obj({"network": "eip155:8453", "x402Version": 2,
                                "accepts": [], "extensions": {"bazaar": {"info": {"input": {"type": "http", "method": "POST"}, "output": {"type": "json", "example": {}}}}}})
            if "/a" in url:
                return httpx.Response(402, content=b"not json {{",
                                      request=req,
                                      headers={"payment-required": _b64({"network": "eip155:8453"}),
                                               "content-type": "application/json"})
            return _json_response(200, {})
        async with X402Auditor(transport=httpx.MockTransport(handler)) as auditor:
            report = await auditor.run_full_audit(
                "https://api.example.com", mode=CheckMode.MARKETPLACE,
            )
        assert any(c.check_name.startswith("bazaar_") and c.check_name != "bazaar_compliance" for c in report.checks)

    @pytest.mark.asyncio
    async def test_marketplace_mode_bazaar_endpoint_200(self, make_client) -> None:
        """_fetch_402_body returns None for non-402 responses (200 from a redirect)."""
        product = _valid_product("a")  # endpoint='/x/a'
        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "/.well-known/x402" in url:
                return _payload_response({"products": [product]})
            if url == "https://api.example.com/":
                return _b64_obj({"network": "eip155:8453", "x402Version": 2,
                                "accepts": [], "extensions": {"bazaar": {"info": {"input": {"type": "http", "method": "POST"}, "output": {"type": "json", "example": {}}}}}})
            if url == "https://api.example.com/x/a":
                # Without trailing slash — check_product_endpoint probes
                return httpx.Response(402, content=b"",
                                      request=req,
                                      headers={"payment-required": _b64({"network": "eip155:8453"}),
                                               "content-type": "application/json"})
            if url == "https://api.example.com/x/a/":
                # With trailing slash — _fetch_402_body gets 200
                return _json_response(200, {})
            return _json_response(200, {})
        async with X402Auditor(transport=httpx.MockTransport(handler)) as auditor:
            report = await auditor.run_full_audit(
                "https://api.example.com", mode=CheckMode.MARKETPLACE,
            )
        per_product_bazaar = [c for c in report.checks if c.check_name.startswith("bazaar_") and c.check_name != "bazaar_compliance"]
        assert len(per_product_bazaar) == 1, f"got bazaar checks: {[c.check_name for c in report.checks]}"
        assert per_product_bazaar[0].status == "PASS"
        assert "skipped" in per_product_bazaar[0].message


# ---------------------------------------------------------------------------
# 10. Module-level run_audit entry point
# ---------------------------------------------------------------------------


class TestRunAudit:

    @pytest.mark.asyncio
    async def test_calls_auditor_and_closes(self, make_client) -> None:
        payment = {
            "network": "eip155:8453",
            "accepts": [{
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "100",
                "payTo": "0x1111111111111111111111111111111111111111",
                "resource": "https://api.example.com",
            }],
            "x402Version": 2,
            "extensions": {"bazaar": {"info": {"input": {"type": "http", "method": "POST"}, "output": {"type": "json", "example": {}}}}},
        }
        def handler(req: httpx.Request) -> httpx.Response:
            url = str(req.url)
            if "/.well-known/x402" in url:
                return _payload_response({
                    "accepts": [],
                    "resources": [{"url": "https://api.example.com"}],
                })
            return _b64_obj(payment)
        report = await run_audit(
            "https://api.example.com",
            transport=httpx.MockTransport(handler),
            timeout=2.0,
        )
        assert report.overall_status == "PASS", \
            f"checks={[c.check_name + '=' + c.status for c in report.checks]}"


# ---------------------------------------------------------------------------
# 11. AuditReport aggregation helpers
# ---------------------------------------------------------------------------


class TestAuditReport:
    def test_worst_status_empty(self) -> None:
        assert X402Auditor._worst_status([]) == "PASS"

    def test_worst_status_priority(self) -> None:
        results = [
            CheckResult(check_name="a", status="PASS", message=""),
            CheckResult(check_name="b", status="ERROR", message=""),
            CheckResult(check_name="c", status="FAIL", message=""),
            CheckResult(check_name="d", status="CRITICAL_FAIL", message=""),
        ]
        assert X402Auditor._worst_status(results) == "CRITICAL_FAIL"
