"""Single-responsibility x402 conformance checks.

Every check function takes a httpx client + URL and returns one of the typed
result models from ``_engine.models``. Each function:

    - Performs exactly ONE conceptual check.
    - Never raises (network/HTTP errors become ``status=ERROR``).
    - Builds human messages via ``_engine.messages``.

The ``X402Auditor`` (see ``_engine.auditor``) is the public orchestrator.
This module is the lower layer: stateless, framework-agnostic.

Adding a new check:
    1. Define a CheckResult subclass in ``_engine.models``.
    2. Add a check function here that returns it.
    3. Wire it into ``X402Auditor.run_full_audit``.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Mapping

import httpx

from x402_conformance_suite._engine import messages as msg
from x402_conformance_suite._engine.constants import (
    BOT_WALL_BODY_MARKERS,
    BOT_WALL_HEADERS,
    CAIP2_PATTERN,
    MANIFEST_PATH_SUFFIX,
    PAYMENT_HEADERS,
)
from x402_conformance_suite._engine.models import (
    AcceptsCompletenessResult,
    BazaarResult,
    BotWallResult,
    Caip2Result,
    CheckResult,
    DiscoveryResourceResult,
    JsonResilienceResult,
    ManifestResult,
    MarketplaceResult,
    ProductResult,
)


# ---------------------------------------------------------------------------
# Network helpers (private)
# ---------------------------------------------------------------------------


async def _safe_get(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    """GET ``url`` and return the Response, or None if any network/HTTP error.

    Avoids raising so callers can return ``status=ERROR`` results instead.
    """
    try:
        return await client.get(url)
    except httpx.TimeoutException:
        return None
    except httpx.ConnectError:
        return None
    except httpx.HTTPError:
        return None
    except Exception:
        return None


def _b64_to_obj(token: str) -> dict[str, Any] | None:
    """Decode base64(JSON) into a dict; return None on any failure.

    Tolerates missing padding, urlsafe encoding, and JSON parse errors so the
    caller can simply skip malformed headers.
    """
    try:
        padded = token + ("=" * (-len(token) % 4))
        try:
            decoded = base64.b64decode(padded, validate=False)
        except Exception:
            decoded = base64.urlsafe_b64decode(padded)
        obj = json.loads(decoded.decode("utf-8"))
        if not isinstance(obj, dict):
            return None
        return obj
    except Exception:
        return None


def _network_candidates(obj: dict[str, Any]) -> list[str]:
    """Collect network identifier candidates from a decoded payment payload.

    x402 v2 PaymentRequired carries the network per payment option at
    ``accepts[].network`` (e.g. ``eip155:8453``); legacy/v1 shapes put it at
    top level (``network`` or ``chainId``). Both are returned, top-level
    first, so the caller can accept the first CAIP-2 match.
    """
    candidates: list[str] = []
    top_level = obj.get("network") or obj.get("chainId")
    if top_level:
        candidates.append(str(top_level))
    accepts = obj.get("accepts")
    if isinstance(accepts, list):
        for entry in accepts:
            if isinstance(entry, dict) and entry.get("network"):
                candidates.append(str(entry["network"]))
    return candidates


# ---------------------------------------------------------------------------
# Manifest discovery
# ---------------------------------------------------------------------------


async def check_manifest(
    client: httpx.AsyncClient, base_url: str
) -> ManifestResult:
    """GET ``{base_url}/.well-known/x402``; require ``accepts`` or ``products``.

    PASS — JSON object with ``accepts`` OR non-empty ``products`` array.
    FAIL — non-200, non-JSON, missing both keys, etc.
    ERROR — network/transport failure.
    """
    url = base_url.rstrip("/") + MANIFEST_PATH_SUFFIX

    try:
        response = await client.get(url)
    except httpx.TimeoutException:
        return ManifestResult(
            status="ERROR",
            message=msg.manifest_error(url, "timeout"),
            details={"url": url, "status_code": None, "error": "timeout"},
        )
    except httpx.ConnectError as e:
        return ManifestResult(
            status="ERROR",
            message=msg.manifest_error(url, f"connection: {e}"),
            details={"url": url, "status_code": None, "error": str(e)},
        )
    except Exception as e:
        return ManifestResult(
            status="ERROR",
            message=msg.manifest_error(url, str(e)),
            details={"url": url, "status_code": None, "error": str(e)},
        )

    status_code = response.status_code

    if status_code != 200:
        return ManifestResult(
            status="FAIL",
            message=msg.manifest_missing(url),
            details={
                "url": url,
                "status_code": status_code,
                "has_accepts": False,
                "has_products": False,
                "headers": dict(response.headers),
            },
        )

    try:
        payload = response.json()
    except json.JSONDecodeError:
        return ManifestResult(
            status="FAIL",
            message=msg.manifest_non_json(url, status_code),
            details={
                "url": url,
                "status_code": status_code,
                "has_accepts": False,
                "has_products": False,
                "headers": dict(response.headers),
            },
        )

    if not isinstance(payload, dict):
        return ManifestResult(
            status="FAIL",
            message=msg.manifest_non_json(url, status_code),
            details={
                "url": url,
                "status_code": status_code,
                "has_accepts": False,
                "has_products": False,
                "payload_type": type(payload).__name__,
            },
        )

    has_accepts = "accepts" in payload and isinstance(payload["accepts"], list)
    products = payload.get("products") if isinstance(payload.get("products"), list) else []
    has_products = len(products) > 0

    if has_accepts or has_products:
        return ManifestResult(
            status="PASS",
            message=msg.manifest_ok(has_accepts, len(products), url),
            details={
                "url": url,
                "status_code": status_code,
                "has_accepts": has_accepts,
                "has_products": has_products,
                "product_count": len(products) if has_products else 0,
                "headers": dict(response.headers),
            },
        )

    return ManifestResult(
        status="FAIL",
        message=msg.manifest_missing_accepts(url, payload),
        details={
            "url": url,
            "status_code": status_code,
            "has_accepts": False,
            "has_products": False,
            "headers": dict(response.headers),
            "received_keys": sorted(list(payload.keys())),
        },
    )


# ---------------------------------------------------------------------------
# CAIP-2 compliance
# ---------------------------------------------------------------------------


def _header_display_name(name: str) -> str:
    if name == "www-authenticate":
        return "WWW-Authenticate"
    if name == "x-payment-required":
        return "X-Payment-Required"
    return name  # already-canonical like "payment-required"


async def check_caip2(
    client: httpx.AsyncClient, target_url: str
) -> Caip2Result:
    """Probe payment headers on the target URL; verify a valid CAIP-2 network.

    Priority order: ``payment-required``, ``x-payment-required``,
    ``x-402-accepts``, ``www-authenticate``. Each is expected to be
    base64(JSON) containing a ``network`` field in CAIP-2 form.

    PASS — at least one header carries a valid CAIP-2 network.
    FAIL — none found or all malformed.
    """
    response = await _safe_get(client, target_url)
    headers: Mapping[str, str] = response.headers if response is not None else {}

    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header_name in PAYMENT_HEADERS:
        raw = headers_lower.get(header_name)
        if not raw:
            continue

        encoded = raw
        if header_name == "www-authenticate":
            prefix = "x402 "
            lower_raw = raw.lower()
            if not lower_raw.startswith(prefix):
                continue
            encoded = raw[len(prefix):].strip()

        obj = _b64_to_obj(encoded)
        if obj is None:
            continue

        candidates = _network_candidates(obj)
        if not candidates:
            continue

        display = _header_display_name(header_name)
        for network_str in candidates:
            if CAIP2_PATTERN.match(network_str):
                return Caip2Result(
                    status="PASS",
                    message=msg.caip2_ok(display, network_str),
                    details={
                        "header_present": True,
                        "header_name": display,
                        "caip2_value": network_str,
                        "valid": True,
                    },
                )
        return Caip2Result(
            status="FAIL",
            message=msg.caip2_invalid(display, candidates[0]),
            details={
                "header_present": True,
                "header_name": display,
                "caip2_value": candidates[0],
                "valid": False,
            },
        )

    return Caip2Result(
        status="FAIL",
        message=msg.caip2_missing(),
        details={
            "header_present": False,
            "header_name": None,
            "caip2_value": None,
            "valid": False,
        },
    )


# ---------------------------------------------------------------------------
# JSON resilience
# ---------------------------------------------------------------------------


async def check_json_resilience(
    client: httpx.AsyncClient, endpoint_url: str
) -> JsonResilienceResult:
    """Verify that any HTTP 402 response has a JSON object body.

    PASS — endpoint not 402 OR 402 body is a JSON object.
    CRITICAL_FAIL — 402 body is a JSON primitive (string/number/array/null)
                    or non-JSON. This crashes the reference verifier.
    ERROR — network failure.
    """
    try:
        response = await client.get(endpoint_url)
    except httpx.TimeoutException:
        return JsonResilienceResult(
            status="ERROR",
            message=msg.network_timeout(),
            details={"status_code": None, "payload_type": None, "is_dict": None},
        )
    except httpx.ConnectError as e:
        return JsonResilienceResult(
            status="ERROR",
            message=msg.network_connect(str(e)),
            details={"status_code": None, "payload_type": None, "is_dict": None},
        )
    except Exception as e:
        return JsonResilienceResult(
            status="ERROR",
            message=msg.network_unexpected(str(e)),
            details={"status_code": None, "payload_type": None, "is_dict": None},
        )

    status_code = response.status_code

    if status_code != 402:
        return JsonResilienceResult(
            status="PASS",
            message=msg.json_not_applicable(status_code),
            details={
                "status_code": status_code,
                "payload_type": None,
                "is_dict": None,
            },
        )

    try:
        payload = response.json()
    except json.JSONDecodeError:
        return JsonResilienceResult(
            status="CRITICAL_FAIL",
            message=msg.json_invalid_body(),
            details={
                "status_code": 402,
                "payload_type": "invalid_json",
                "is_dict": False,
            },
        )

    payload_type = type(payload).__name__
    is_dict = type(payload) is dict

    if is_dict:
        return JsonResilienceResult(
            status="PASS",
            message=msg.json_ok(),
            details={
                "status_code": 402,
                "payload_type": payload_type,
                "is_dict": True,
            },
        )

    sample = str(payload)[:100] if payload is not None else "null"
    return JsonResilienceResult(
        status="CRITICAL_FAIL",
        message=msg.json_primitive_error(payload_type, sample),
        details={
            "status_code": 402,
            "payload_type": payload_type,
            "is_dict": False,
            "sample": sample,
        },
    )


# ---------------------------------------------------------------------------
# Bazaar compliance
# ---------------------------------------------------------------------------


def check_bazaar(response_body: dict[str, Any] | None) -> BazaarResult:
    """Validate the optional ``extensions.bazaar`` marketplace-discovery block.

    Shape verified against every production capture that carries the block
    (Viridis regulatory-radar, Viridis ghg-ledger, AsterPay crypto-prices,
    AsterPay sentiment — all four agree byte-for-byte):

        extensions.bazaar.info.input.type    == "http"
        extensions.bazaar.info.input.method  (e.g. "GET" / "POST")
        extensions.bazaar.info.output.type   (e.g. "json")
        extensions.bazaar.schema             (JSON Schema object, when present)

    The block is OPTIONAL — it is a marketplace-discovery extension, not
    part of the core x402 PaymentRequired contract. Its absence is
    conformant (PASS). Present-but-malformed shapes FAIL.

    PASS — block absent, OR present and matches the shape above.
    FAIL — block present but missing/invalid info.input.method,
           info.output, or (when present) schema is not an object.
    SKIP — no 402 body available (returns PASS, not applicable).
    """
    if response_body is None:
        return BazaarResult(
            status="PASS",
            message=msg.bazaar_skipped(),
            details={
                "bazaar_present": False,
                "missing_fields": [],
            },
        )

    if not isinstance(response_body, dict):
        return BazaarResult(
            status="PASS",
            message=msg.bazaar_not_present(),
            details={
                "bazaar_present": False,
                "missing_fields": [],
            },
        )

    extensions = response_body.get("extensions", {})
    bazaar = extensions.get("bazaar") if isinstance(extensions, dict) else None

    if bazaar is None:
        return BazaarResult(
            status="PASS",
            message=msg.bazaar_not_present(),
            details={
                "bazaar_present": False,
                "missing_fields": [],
            },
        )

    if not isinstance(bazaar, dict):
        return BazaarResult(
            status="FAIL",
            message=msg.bazaar_malformed(["extensions.bazaar is present but not an object"]),
            details={
                "bazaar_present": True,
                "missing_fields": ["extensions.bazaar (not an object)"],
            },
        )

    missing: list[str] = []
    info = bazaar.get("info")

    if not isinstance(info, dict):
        missing.append("extensions.bazaar.info missing or not an object")
    else:
        input_block = info.get("input")
        if not isinstance(input_block, dict):
            missing.append("extensions.bazaar.info.input missing or not an object")
        else:
            if not input_block.get("type"):
                missing.append("extensions.bazaar.info.input.type missing")
            if not input_block.get("method"):
                missing.append("extensions.bazaar.info.input.method missing")

        output_block = info.get("output")
        if not isinstance(output_block, dict):
            missing.append("extensions.bazaar.info.output missing or not an object")
        else:
            if not output_block.get("type"):
                missing.append("extensions.bazaar.info.output.type missing")

    schema = bazaar.get("schema")
    if schema is not None and not isinstance(schema, dict):
        missing.append("extensions.bazaar.schema present but not an object")

    if missing:
        return BazaarResult(
            status="FAIL",
            message=msg.bazaar_malformed(missing),
            details={
                "bazaar_present": True,
                "missing_fields": missing,
            },
        )

    return BazaarResult(
        status="PASS",
        message=msg.bazaar_ok(),
        details={
            "bazaar_present": True,
            "missing_fields": [],
        },
    )


async def check_bazaar_for_url(
    client: httpx.AsyncClient, target_url: str
) -> BazaarResult:
    """Convenience wrapper: GET the target URL, extract 402 body, run ``check_bazaar``."""
    body = await _get_402_body(client, target_url)
    return check_bazaar(body)


async def _get_402_body(
    client: httpx.AsyncClient, target_url: str
) -> dict[str, Any] | None:
    """GET the target; return its 402 body if a dict, else None."""
    try:
        full_url = target_url.rstrip("/") + "/"
        response = await client.get(full_url)
        if response.status_code != 402:
            return None
        payload = response.json()
        return payload if isinstance(payload, dict) else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Marketplace catalog
# ---------------------------------------------------------------------------


async def check_marketplace(
    client: httpx.AsyncClient, base_url: str, manifest_payload: dict[str, Any]
) -> MarketplaceResult:
    """Validate each product in ``manifest['products']`` conforms to x402.

    Per product requirement (each x402 block):
        - scheme == "exact"
        - network matches CAIP-2 pattern
        - pay_to (or payTo) is set
        - facilitator_url is set
        - method == "GET" if specified
    """
    products = manifest_payload.get("products", [])
    if not isinstance(products, list) or not products:
        return MarketplaceResult(
            status="FAIL",
            message=msg.marketplace_summary(0, 0),
            total_products=0,
            conformant_count=0,
            details={"product_count": 0, "conformant": 0, "product_details": []},
        )

    product_details: list[dict[str, Any]] = []
    conformant = 0

    for i, product in enumerate(products):
        if not isinstance(product, dict):
            product_details.append(
                {
                    "product_id": f"index_{i}",
                    "name": f"index_{i}",
                    "endpoint": "",
                    "status": "non_conformant",
                    "errors": ["product entry is not an object"],
                    "x402": None,
                }
            )
            continue

        pid = str(product.get("id", f"product_{i}"))
        name = str(product.get("name", pid))
        x402_block = product.get("x402")
        errors: list[str] = []

        if x402_block is None:
            errors.append("missing x402 block")
        elif isinstance(x402_block, dict):
            scheme = x402_block.get("scheme")
            network = x402_block.get("network")
            pay_to = x402_block.get("pay_to") or x402_block.get("payTo")
            facilitator = x402_block.get("facilitator_url")

            if scheme != "exact":
                errors.append(f"scheme should be 'exact', got '{scheme}'")
            if not network or not CAIP2_PATTERN.match(str(network)):
                errors.append(f"invalid CAIP-2 network: {network!r}")
            if not pay_to:
                errors.append("missing pay_to address")
            if not facilitator:
                errors.append("missing facilitator_url")
        else:
            errors.append("x402 block is not an object")

        if product.get("method") and product["method"] != "GET":
            errors.append(f"method should be GET, got {product['method']!r}")

        if not errors:
            conformant += 1

        product_details.append(
            {
                "product_id": pid,
                "name": name,
                "endpoint": str(product.get("endpoint", "")),
                "status": "conformant" if not errors else "non_conformant",
                "errors": errors,
                "x402": x402_block,
            }
        )

    total = len(products)
    return MarketplaceResult(
        status="PASS" if conformant == total else "FAIL",
        message=msg.marketplace_summary(conformant, total),
        total_products=total,
        conformant_count=conformant,
        details={
            "product_count": total,
            "conformant": conformant,
            "product_details": product_details,
        },
    )


# ---------------------------------------------------------------------------
# Per-product endpoint walk
# ---------------------------------------------------------------------------


async def check_product_endpoint(
    client: httpx.AsyncClient,
    base_url: str,
    product: dict[str, Any],
) -> ProductResult:
    """GET ``{base_url}{product['endpoint']}`` and validate the response.

    Free products (no x402 block) should return HTTP 200.
    Paid products (with x402 block) should return HTTP 402 with a
    Payment-Required header.
    """
    pid = str(product.get("id", "unknown"))
    name = str(product.get("name", pid))
    endpoint = str(product.get("endpoint", "") or "")
    x402_block = product.get("x402")
    is_free = x402_block is None

    if not endpoint:
        return ProductResult(
            status="ERROR",
            message=msg.product_endpoint_no_endpoint(pid),
            product_id=pid,
            endpoint_url="",
            details={"error": "no endpoint defined"},
        )

    full_url = base_url.rstrip("/") + endpoint

    try:
        resp = await client.get(full_url)
    except httpx.TimeoutException:
        return ProductResult(
            status="ERROR",
            message=msg.product_timeout(name),
            product_id=pid,
            endpoint_url=full_url,
            details={"endpoint": endpoint, "error": "timeout"},
        )
    except httpx.ConnectError as e:
        return ProductResult(
            status="ERROR",
            message=msg.product_connect_error(name, str(e)),
            product_id=pid,
            endpoint_url=full_url,
            details={"endpoint": endpoint, "error": str(e)},
        )
    except Exception as e:
        return ProductResult(
            status="ERROR",
            message=msg.product_unexpected(name, -1),
            product_id=pid,
            endpoint_url=full_url,
            details={"endpoint": endpoint, "error": str(e)},
        )

    status = resp.status_code

    if is_free:
        if status == 200:
            return ProductResult(
                status="PASS",
                message=msg.product_free_pass(name),
                product_id=pid,
                endpoint_url=full_url,
                details={"endpoint": endpoint, "status_code": status, "is_free": True},
            )
        return ProductResult(
            status="FAIL",
            message=msg.product_free_fail(name, status),
            product_id=pid,
            endpoint_url=full_url,
            details={"endpoint": endpoint, "status_code": status, "is_free": True},
        )

    if status == 402:
        headers_lower = {k.lower() for k in resp.headers.keys()}
        has_pr = "payment-required" in headers_lower or "x-payment-required" in headers_lower
        if has_pr:
            return ProductResult(
                status="PASS",
                message=msg.product_paid_ok_with_header(name),
                product_id=pid,
                endpoint_url=full_url,
                details={
                    "endpoint": endpoint,
                    "status_code": status,
                    "is_free": False,
                    "has_payment_header": True,
                    "headers": dict(resp.headers),
                },
            )
        return ProductResult(
            status="FAIL",
            message=msg.product_paid_ok_no_header(name),
            product_id=pid,
            endpoint_url=full_url,
            details={
                "endpoint": endpoint,
                "status_code": status,
                "is_free": False,
                "has_payment_header": False,
                "headers": dict(resp.headers),
            },
        )

    if status == 200:
        return ProductResult(
            status="FAIL",
            message=msg.product_paid_wrong(name, status),
            product_id=pid,
            endpoint_url=full_url,
            details={"endpoint": endpoint, "status_code": status, "is_free": False},
        )

    return ProductResult(
        status="ERROR",
        message=msg.product_unexpected(name, status),
        product_id=pid,
        endpoint_url=full_url,
        details={"endpoint": endpoint, "status_code": status, "is_free": False},
    )


# ---------------------------------------------------------------------------
# Bot-wall detection
# ---------------------------------------------------------------------------


async def check_bot_wall(client: httpx.AsyncClient, target_url: str) -> BotWallResult:
    """Detect bot-protection layers (Cloudflare, Sucuri, Incapsula) answering
    instead of the origin, which blocks agent buyers before the paywall.

    PASS — no bot-wall signal in status/headers/body.
    FAIL — HTTP 403 with any header/server/body signal, OR HTTP 403/503 with
           two or more challenge-body markers.
    ERROR — network/transport failure.
    """
    response = await _safe_get(client, target_url)
    if response is None:
        return BotWallResult(
            status="ERROR",
            message=f"Network failure probing {target_url} — bot-wall check could not run.",
            details={"status_code": None, "signals": [], "blocked": False},
        )

    status = response.status_code
    signals: list[str] = []

    headers_lower = {k.lower(): v for k, v in response.headers.items()}
    for header, needles in BOT_WALL_HEADERS.items():
        value = headers_lower.get(header)
        if value is None:
            continue
        if not needles or any(n.lower() in value.lower() for n in needles):
            signals.append(f"{header}: {value}")

    server = headers_lower.get("server", "")
    if any(v in server.lower() for v in ("cloudflare", "sucuri", "incapsula")):
        signals.append(f"server: {server}")

    body_hits: list[str] = []
    if status in (403, 503):
        body_lower = response.text.lower()
        body_hits = [m for m in BOT_WALL_BODY_MARKERS if m.lower() in body_lower]
        signals.extend(f"body: {m}" for m in body_hits)

    blocked = (status == 403 and bool(signals)) or (
        status in (403, 503) and len(body_hits) >= 2
    )

    if blocked:
        return BotWallResult(
            status="FAIL",
            message=(
                f"Bot-protection ({', '.join(signals)}) answered with HTTP {status}"
                " — agent buyers are blocked before they ever see your paywall."
                " Allowlist agent user-agents or disable challenge for API paths."
            ),
            details={"status_code": status, "signals": signals, "blocked": True},
        )

    return BotWallResult(
        status="PASS",
        message=f"No bot-protection detected (HTTP {status}).",
        details={"status_code": status, "signals": signals, "blocked": False},
    )


# ---------------------------------------------------------------------------
# Accepts completeness
# ---------------------------------------------------------------------------


def _decode_payment_required(response: httpx.Response) -> dict[str, Any] | None:
    """Extract the PaymentRequired payload from a 402 response.

    Tries the ``payment-required`` / ``x-payment-required`` headers
    (base64 JSON) first, then falls back to a JSON object body.
    """
    headers_lower = {k.lower(): v for k, v in response.headers.items()}
    for name in ("payment-required", "x-payment-required"):
        raw = headers_lower.get(name)
        if raw:
            obj = _b64_to_obj(raw)
            if obj is not None:
                return obj
    try:
        body = response.json()
    except Exception:
        return None
    return body if isinstance(body, dict) else None


async def check_accepts_completeness(
    client: httpx.AsyncClient, target_url: str
) -> AcceptsCompletenessResult:
    """Validate every ``accepts[]`` entry of the 402 payload is complete.

    Per entry: scheme, network, payTo (or pay_to), resource, and an atomic-unit
    amount (``amount`` v2 or ``maxAmountRequired`` v1) as a digit string —
    decimal points mean dollars, not atomic units. Top-level ``x402Version``
    must be 1 or 2 and ``resource.url`` must match the probed URL.

    PASS — not 402 (not applicable), OR no findings.
    FAIL — any missing/invalid field.
    ERROR — network failure, or 402 without a decodable PaymentRequired.
    """
    response = await _safe_get(client, target_url)
    if response is None:
        return AcceptsCompletenessResult(
            status="ERROR",
            message=f"Network failure probing {target_url} — accepts[] check could not run.",
            details={"status_code": None, "applicable": None, "entries_checked": 0, "findings": []},
        )

    status = response.status_code
    if status != 402:
        return AcceptsCompletenessResult(
            status="PASS",
            message=f"Endpoint returned HTTP {status}, not 402 — accepts[] check not applicable.",
            details={"status_code": status, "applicable": False},
        )

    payload = _decode_payment_required(response)
    if payload is None:
        return AcceptsCompletenessResult(
            status="ERROR",
            message="402 but no decodable PaymentRequired (header or JSON body).",
            details={"status_code": 402, "applicable": True, "entries_checked": 0, "findings": []},
        )

    findings: list[str] = []

    version = payload.get("x402Version")
    if version not in (1, 2):
        findings.append(f"x402Version missing or unrecognized: {version!r}")

    accepts = payload.get("accepts")
    if not isinstance(accepts, list) or not accepts:
        findings.append("accepts[] missing or empty")
        accepts = []

    for i, entry in enumerate(accepts):
        if not isinstance(entry, dict):
            findings.append(f"accepts[{i}] is not an object")
            continue
        for field in ("scheme", "network", "resource"):
            if not entry.get(field):
                findings.append(f"accepts[{i}].{field} missing")
        if not (entry.get("payTo") or entry.get("pay_to")):
            findings.append(f"accepts[{i}].payTo missing")
        amount = entry.get("amount", entry.get("maxAmountRequired"))
        if amount is None:
            findings.append(f"accepts[{i}].amount missing (need 'amount' or 'maxAmountRequired')")
        elif isinstance(amount, str) and "." in amount:
            findings.append(
                f"accepts[{i}].amount looks like dollars, not atomic units:"
                f" {amount!r} (off by 10^6)"
            )
        elif not (isinstance(amount, str) and amount.isdigit()):
            findings.append(
                f"accepts[{i}].amount must be a digit string of atomic units, got {amount!r}"
            )

    resource = payload.get("resource")
    if isinstance(resource, dict) and resource.get("url"):
        url = str(resource["url"])
        if url.rstrip("/") != target_url.rstrip("/"):
            findings.append(f"resource.url '{url}' does not match probed URL")

    details = {
        "status_code": 402,
        "applicable": True,
        "entries_checked": len(accepts),
        "findings": findings,
    }

    if findings:
        return AcceptsCompletenessResult(
            status="FAIL",
            message=f"accepts[] completeness: {len(findings)} problem(s): {findings[0]}",
            details=details,
        )

    return AcceptsCompletenessResult(
        status="PASS",
        message=(
            f"All {len(accepts)} accepts[] entries complete"
            " (scheme, network, atomic amount, payTo, resource)."
        ),
        details=details,
    )


# ---------------------------------------------------------------------------
# Discovery resource listing
# ---------------------------------------------------------------------------


async def check_discovery_resource_listing(
    client: httpx.AsyncClient, target_url: str
) -> DiscoveryResourceResult:
    """Verify the paid resource is listed in ``/.well-known/x402`` so agents
    can discover it.

    PASS — not 402 (not applicable), payload declares no resource (nothing to
           verify), OR the resource URL/path appears in the catalog.
    FAIL — resource paid but absent from ``resources[]``/``products[]``.
    ERROR — network failure, or catalog unreachable/invalid while a resource
            is paid.
    """
    response = await _safe_get(client, target_url)
    if response is None:
        return DiscoveryResourceResult(
            status="ERROR",
            message=f"Network failure probing {target_url} — discovery check could not run.",
            details={"status_code": None, "applicable": None, "listed": None},
        )

    status = response.status_code
    if status != 402:
        return DiscoveryResourceResult(
            status="PASS",
            message=f"Endpoint returned HTTP {status}, not 402 — discovery check not applicable.",
            details={"status_code": status, "applicable": False},
        )

    payload = _decode_payment_required(response)

    paid_url: str | None = None
    if payload is not None:
        resource = payload.get("resource")
        if isinstance(resource, dict) and resource.get("url"):
            paid_url = str(resource["url"])
        else:
            accepts = payload.get("accepts")
            if isinstance(accepts, list):
                for entry in accepts:
                    if isinstance(entry, dict) and entry.get("resource"):
                        paid_url = str(entry["resource"])
                        break

    if not paid_url:
        return DiscoveryResourceResult(
            status="PASS",
            message="402 payload declares no resource — nothing to verify in catalog.",
            details={"applicable": True, "listed": None, "note": "no resource declared in payload"},
        )

    # The discovery catalog lives at the ORIGIN root, not under the probed
    # path — a paid product URL like /paid/x must still resolve the manifest
    # at scheme://host/.well-known/x402.
    parsed = httpx.URL(target_url)
    origin = f"{parsed.scheme}://{parsed.host}"
    if parsed.port:
        origin = f"{origin}:{parsed.port}"
    catalog_url = origin.rstrip("/") + MANIFEST_PATH_SUFFIX
    catalog_response = await _safe_get(client, catalog_url)
    manifest: dict[str, Any] | None = None
    if catalog_response is not None:
        try:
            body = catalog_response.json()
        except Exception:
            body = None
        if isinstance(body, dict):
            manifest = body

    if manifest is None:
        return DiscoveryResourceResult(
            status="ERROR",
            message=(
                f"Resource {paid_url} is paid but {catalog_url} is unreachable or"
                " not JSON — cannot verify listing."
            ),
            details={"applicable": True, "listed": None, "resource": paid_url},
        )

    origin_url = httpx.URL(target_url)
    origin = str(
        origin_url.copy_with(path="/", query=None, fragment=None)
    ).rstrip("/")

    candidates: set[str] = set()
    resources = manifest.get("resources")
    if isinstance(resources, list):
        for entry in resources:
            if isinstance(entry, dict) and entry.get("url"):
                listed = str(entry["url"]).rstrip("/")
                candidates.add(listed)
                if "://" in listed:
                    candidates.add(httpx.URL(listed).path.rstrip("/"))
    products = manifest.get("products")
    if isinstance(products, list):
        for entry in products:
            if isinstance(entry, dict) and entry.get("endpoint"):
                endpoint = str(entry["endpoint"])
                candidates.add(endpoint.rstrip("/"))
                candidates.add((origin + endpoint).rstrip("/"))

    paid_norm = paid_url.rstrip("/")
    paid_path = httpx.URL(paid_norm).path.rstrip("/") if "://" in paid_norm else paid_norm
    listed = paid_norm in candidates or paid_path in candidates

    if listed:
        return DiscoveryResourceResult(
            status="PASS",
            message=f"Paid resource {paid_url} is listed in {MANIFEST_PATH_SUFFIX}.",
            details={"applicable": True, "listed": True, "resource": paid_url},
        )

    return DiscoveryResourceResult(
        status="FAIL",
        message=(
            f"Paid resource {paid_url} is not listed in {MANIFEST_PATH_SUFFIX}"
            " — agents cannot discover it. Add it to resources[] (or products[])."
        ),
        details={
            "applicable": True,
            "listed": False,
            "resource": paid_url,
            "catalog_size": len(candidates),
        },
    )
