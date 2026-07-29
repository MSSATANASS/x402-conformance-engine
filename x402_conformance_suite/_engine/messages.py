"""Build actionable, human-readable messages for each check result.

The goal of these helpers is for every FAIL/ERROR message to tell the
endpoint operator exactly what is wrong AND what they should do about it.

Examples:
    FAIL:  "Manifest endpoint returned HTTP 404. Expected /.well-known/x402 to
           return a JSON object with an 'accepts' key. See
           https://github.com/MSSATANASS/x402-validator-tools for a fixture."
    ERROR: "Connection refused. The endpoint is unreachable. Verify the URL
           is live and accepts unauthenticated GET on the manifest path."

These are deterministic text builders (no I/O). Each returns a string; some
also bundle suggested remediation notes in a list (used in JSON output).
"""

from __future__ import annotations

from typing import Any, Iterable


# === Manifest ============================================================


# Standard x402 discovery path — override-able in ``_engine.constants`` if the
# spec ever changes. Kept here too so messages can reference it without
# importing from constants (circular-import safe).
MANIFEST_PATH: str = "/.well-known/x402"


def manifest_missing(url: str) -> str:
    return (
        f"Manifest endpoint not found at {url}. The x402 spec requires a JSON "
        f"manifest at {MANIFEST_PATH} with either an 'accepts' key (resource "
        f"pricing), a 'products' array (marketplace catalog), or a 'routes' "
        f"array (x402 v2 route catalog). "
        f"Add the file to your origin."
    )


def manifest_non_json(url: str, status: int) -> str:
    return (
        f"Manifest at {url} returned HTTP {status} but the body is not valid "
        f"JSON. The manifest must parse as JSON. "
        f"Fix: serve application/json with a valid object body."
    )


def manifest_missing_accepts(url: str, hints: dict[str, Any]) -> str:
    return (
        f"Manifest at {url} is valid JSON but lacks the required 'accepts' "
        f"key (per-resource pricing), the optional 'products' array "
        f"(marketplace catalog), and the optional 'routes' array "
        f"(x402 v2 route catalog). "
        f"Fix: include either 'accepts' (with scheme/network/amount), "
        f"'products' (each with id/endpoint/x402), or 'routes' (each with "
        f"agent/tool/endpoint/paid_execution_method). "
        f"Got keys: {sorted(list(hints.keys()))[:6]}."
    )


def manifest_ok(accepts: bool, products: int, url: str, routes: bool = False, route_count: int = 0) -> str:
    if accepts:
        return f"Manifest at {url} is valid and contains 'accepts'."
    if routes:
        return f"Manifest at {url} is an x402 v2 route catalog with {route_count} route(s)."
    return f"Manifest at {url} is a marketplace catalog with {products} product(s)."


def manifest_error(url: str, why: str) -> str:
    return f"Could not reach manifest at {url}: {why}. Verify the URL is live."


# === CAIP-2 ==============================================================


def caip2_missing() -> str:
    return (
        "No CAIP-2 network identifier found in any payment header. "
        "Headers probed: payment-required, x-402-accepts, www-authenticate. "
        "Fix: encode base64(json) of the PaymentRequired payload into one of "
        "these headers with a 'network' field in CAIP-2 form (e.g., "
        "'eip155:8453' for Base mainnet)."
    )


def caip2_invalid(header: str, value: str) -> str:
    return (
        f"Header {header} carries network '{value}' which is not a valid "
        f"CAIP-2 identifier. CAIP-2 syntax is '<namespace>:<reference>' with "
        f"lowercase namespace (e.g., 'eip155:8453' or 'solana:mainnet'). "
        f"Found an invalid value: '{value}'."
    )


def caip2_ok(header: str, value: str) -> str:
    return f"CAIP-2 network '{value}' validated in header '{header}'."


# === JSON resilience =====================================================


def json_primitive_error(payload_type: str, sample: str) -> str:
    return (
        f"HTTP 402 returned a JSON primitive ({payload_type}) instead of a "
        f"JSON object. The reference verifier requires an object body. "
        f"Sample: '{sample}'. "
        f"Fix: wrap your payment terms in an object (e.g., "
        f"'{{\"accepts\": [...]}}' or '{{\"x402Version\": 2, "
        f"\"accepts\": [...]}}')."
    )


def json_invalid_body() -> str:
    return (
        "HTTP 402 response body is not valid JSON. The x402 spec requires a "
        "JSON object body. Fix: ensure Content-Type is application/json and "
        "the body parses as JSON."
    )


def json_ok() -> str:
    return "HTTP 402 response body is a valid JSON object."


def json_not_applicable(status: int) -> str:
    return (
        f"Endpoint returned HTTP {status} (not 402). JSON resilience check "
        f"is not applicable; skipped. PASS."
    )


# === Bazaar ===============================================================
#
# Shape verified against every production capture that carries the block:
# viridis_regulatory_radar, viridis_ghg_ledger, asterpay_crypto_prices,
# asterpay_sentiment (all four agree byte-for-byte). It is an OPTIONAL
# marketplace-discovery extension, not part of the core PaymentRequired
# contract, so its absence is conformant.


def bazaar_not_present() -> str:
    return (
        "extensions.bazaar is not present. This is an optional marketplace-"
        "discovery extension, not required by the core x402 spec — PASS "
        "(not applicable)."
    )


def bazaar_malformed(missing: Iterable[str]) -> str:
    items = "; ".join(missing)
    return (
        f"extensions.bazaar is present but malformed: {items}. Fix: the "
        f"observed production shape is extensions.bazaar.info.input.type, "
        f"extensions.bazaar.info.input.method, "
        f"extensions.bazaar.info.output.type, and (recommended) "
        f"extensions.bazaar.schema as a JSON Schema object."
    )


def bazaar_ok() -> str:
    return "extensions.bazaar is present and matches the observed production shape (info.input/output, schema)."


def bazaar_skipped() -> str:
    return (
        "No HTTP 402 body available; bazaar compliance check skipped. "
        "PASS (not applicable)."
    )


# === Marketplace / product ==============================================


def marketplace_summary(conformant: int, total: int) -> str:
    if total == 0:
        return "Manifest contains no 'products' or 'routes' array; marketplace mode cannot evaluate."
    if conformant == total:
        return f"All {total} products/routes conformant."
    return (
        f"{conformant}/{total} products/routes conformant. "
        f"See product details for required fixes (scheme/network/pay_to/facilitator_url)."
    )


def product_free_pass(name: str) -> str:
    return f"Free product '{name}' resolved to HTTP 200 as expected."


def product_free_fail(name: str, status: int) -> str:
    return (
        f"Free product '{name}' returned HTTP {status} but should return 200. "
        f"Free products bypass x402 — verify the route is reachable."
    )


def product_paid_ok_no_header(name: str) -> str:
    return (
        f"Paid product '{name}' returned HTTP 402 but the Payment-Required "
        f"header is absent. Add base64(json) PaymentRequired to header "
        f"'X-Payment-Required' (or 'Payment-Required') for v2 compliance."
    )


def product_paid_ok_with_header(name: str) -> str:
    return (
        f"Paid product '{name}' returned HTTP 402 with Payment-Required "
        f"header. v2 channel detected."
    )


def product_paid_wrong(name: str, status: int) -> str:
    return (
        f"Paid product '{name}' returned HTTP {status} but should return "
        f"402 (Payment Required). Check that x402 middleware intercepts "
        f"unauthenticated requests before they reach the handler."
    )


def product_paid_needs_input(name: str, had_schema: bool) -> str:
    if had_schema:
        return (
            f"Paid route '{name}' rejected the probe with HTTP 400 "
            f"(input validation) before emitting a 402. The validator built a "
            f"body from the advertised input_schema but it was not accepted — "
            f"the schema in the manifest is incomplete for reaching the "
            f"paywall. Publish a complete Bazaar input_schema (or a 402 "
            f"challenge that precedes input validation) so buyers can preflight."
        )
    return (
        f"Paid route '{name}' validates its request body BEFORE emitting the "
        f"402 challenge and returned HTTP 400 (input validation) to the probe. "
        f"No input_schema is advertised in the manifest, so the validator "
        f"cannot construct a valid body to reach the paywall. Add a Bazaar "
        f"input_schema to the route, or return the 402 challenge prior to "
        f"input validation."
    )


def product_endpoint_no_endpoint(pid: str) -> str:
    return f"Product '{pid}' has no 'endpoint' field; cannot probe."


def product_timeout(name: str) -> str:
    return f"Product '{name}' timed out before HTTP response."


def product_connect_error(name: str, error: str) -> str:
    return f"Product '{name}' connection error: {error}"


def product_unexpected(name: str, status: int) -> str:
    return (
        f"Product '{name}' returned unexpected HTTP {status}. Expected 200 "
        f"(free) or 402 (paid)."
    )


# === Bot wall =============================================================
#
# A bot-protection layer answering in place of the origin is the most common
# silent x402 failure: the agent buyer is turned away with a challenge page
# and never reaches the paywall, so the merchant sees no error at all.


def bot_wall_blocked(signals: Iterable[str], status: int) -> str:
    detected = ", ".join(signals)
    return (
        f"Bot-protection ({detected}) answered with HTTP {status} — agent "
        f"buyers are blocked before they ever see your paywall. Fix: allowlist "
        f"agent user-agents, or disable the challenge for your API paths."
    )


def bot_wall_clear(status: int) -> str:
    return f"No bot-protection detected (HTTP {status})."


def bot_wall_error(url: str, why: str) -> str:
    return (
        f"Could not probe {url} for bot-protection: {why}. "
        f"Verify the endpoint is reachable."
    )


# === accepts[] completeness ===============================================
#
# x402 v2 carries payment options in accepts[]. A missing field, or an amount
# quoted in dollars instead of atomic units, breaks the buying agent's parse
# in exactly the same way — so both are reported per entry, with the index.


def accepts_not_applicable(status: int) -> str:
    return (
        f"Endpoint returned HTTP {status}, not 402 — accepts[] completeness "
        f"check not applicable. PASS (not applicable)."
    )


def accepts_undecodable() -> str:
    return (
        "HTTP 402 returned but no decodable PaymentRequired payload was found "
        "in the PAYMENT-REQUIRED header or the response body. Fix: emit "
        "base64(JSON) in the header, or a JSON object body."
    )


def accepts_version_bad(value: Any) -> str:
    return f"x402Version missing or unrecognized: {value!r} (expected 1 or 2)."


def accepts_list_missing() -> str:
    return "accepts[] missing or empty — the payload advertises no payment option."


def accepts_entry_not_object(index: int) -> str:
    return f"accepts[{index}] is not an object."


def accepts_field_missing(index: int, field: str) -> str:
    return f"accepts[{index}].{field} missing."


def accepts_amount_missing(index: int) -> str:
    return (
        f"accepts[{index}].amount missing (need 'amount' or the legacy "
        f"'maxAmountRequired')."
    )


def accepts_amount_dollars(index: int, value: str) -> str:
    return (
        f"accepts[{index}].amount looks like dollars, not atomic units: "
        f"{value!r} (off by 10^6). Fix: USDC has 6 decimals, so $0.005 is "
        f'"5000".'
    )


def accepts_amount_not_digits(index: int, value: Any) -> str:
    return (
        f"accepts[{index}].amount must be a digit string of atomic units, "
        f"got {value!r}."
    )


def accepts_resource_mismatch(url: str, probed: str) -> str:
    return (
        f"resource.url {url!r} does not match the probed URL {probed!r} — the "
        f"quote signs for a resource this endpoint does not serve."
    )


def accepts_problems(count: int, first: str) -> str:
    return f"accepts[] completeness: {count} problem(s): {first}"


def accepts_ok(entries: int) -> str:
    return (
        f"All {entries} accepts[] entries complete (scheme, network, atomic "
        f"amount, payTo, resource)."
    )


def accepts_error(url: str, why: str) -> str:
    return (
        f"Could not probe {url} for accepts[] completeness: {why}. "
        f"Verify the endpoint is reachable."
    )


# === Discovery resource listing ==========================================
#
# A paid resource that is absent from /.well-known/x402 is invisible to the
# agents that would pay for it, however conformant its 402 response is.


def discovery_not_applicable(status: int) -> str:
    return (
        f"Endpoint returned HTTP {status}, not 402 — discovery listing check "
        f"not applicable. PASS (not applicable)."
    )


def discovery_no_resource() -> str:
    return "402 payload declares no resource — nothing to verify in the catalog."


def discovery_listed(url: str) -> str:
    return f"Paid resource {url} is listed in {MANIFEST_PATH}."


def discovery_not_listed(url: str) -> str:
    return (
        f"Paid resource {url} is not listed in {MANIFEST_PATH} — agents cannot "
        f"discover it. Fix: add it to resources[] (or products[]) in your "
        f"manifest."
    )


def discovery_catalog_unreachable(url: str, catalog_url: str) -> str:
    return (
        f"Resource {url} is paid but {catalog_url} is unreachable or not a "
        f"JSON object, so its listing cannot be verified. Fix: serve a JSON "
        f"manifest at {MANIFEST_PATH}."
    )


def discovery_error(url: str, why: str) -> str:
    return (
        f"Could not probe {url} for discovery listing: {why}. "
        f"Verify the endpoint is reachable."
    )


# === Network errors ======================================================


def network_timeout() -> str:
    return "Request timed out. Default timeout is 10s; pass --timeout to raise."


def network_connect(error: str) -> str:
    return f"Connection error: {error}. Verify the endpoint is reachable."


def network_unexpected(error: str) -> str:
    return f"Unexpected error: {error}."
