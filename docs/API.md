# x402 Validator — API Reference

The conformance engine has a single public surface:

```
async with X402Auditor() as auditor:
    report = await auditor.run_full_audit(url, mode="standard")
```

This document is the **ground truth** for every public function, every result type, and every status value. If behaviour here disagrees with code, **fix the code** or **fix this doc** — never both silently.

---

## Audit modes

| Mode            | Checks run                                                                                                                   | When to use                     |
|-----------------|------------------------------------------------------------------------------------------------------------------------------|---------------------------------|
| `"standard"`    | manifest, CAIP-2, JSON resilience, bazaar, bot-wall, accepts completeness, discovery listing                                  | Single-endpoint audit (default) |
| `"marketplace"` | the seven above + `marketplace_products` + per-product `product_check` + per-product bazaar                                    | Multi-product catalog audit     |

A `mode` value not in this set raises `ValueError`.

---

## Result hierarchy

Every check returns a `CheckResult` subclass. The discriminator `check_name`
lets callers route by type without string checks on `details`.

### `CheckResult` (base)

| Field        | Type                              | Meaning                                         |
|--------------|-----------------------------------|-------------------------------------------------|
| `check_name` | `str`                             | Stable identifier, e.g. `"manifest_discovery"`  |
| `status`     | `Literal["PASS","FAIL","CRITICAL_FAIL","ERROR"]` | One word summary                       |
| `message`    | `str`                             | Human-readable, actionable summary              |
| `details`    | `Optional[dict[str, Any]]`        | Typed payload for programmatic consumers        |

#### Status precedence (`X402Auditor._worst_status`)

```
CRITICAL_FAIL  >  FAIL  >  ERROR  >  PASS
```

When aggregating checks for an `AuditReport`, the highest-precedence status wins.

### `ManifestResult` (`check_name = "manifest_discovery"`)

Probes `GET {base_url}/.well-known/x402`.

| `status`           | When                                                          |
|--------------------|---------------------------------------------------------------|
| `PASS`             | 200, valid JSON object, has `accepts` or non-empty `products` |
| `FAIL`             | 404, non-JSON, primitive body, missing both keys              |
| `ERROR`            | Timeout, connection refused, or other transport failure        |

### `Caip2Result` (`check_name = "caip2_compliance"`)

Probes payment headers on the target URL:

- `payment-required`
- `x-payment-required` (alias)
- `x-402-accepts`
- `www-authenticate` (only when prefixed with `X402 `)

Each is expected to be `base64(JSON)` with a `network` field in
CAIP-2 form. The first header that decodes AND pattern-matches wins.

| `status` | When                                                |
|----------|-----------------------------------------------------|
| `PASS`   | At least one valid CAIP-2 network found             |
| `FAIL`   | None found, or all found headers malformed/invalid  |

CAIP-2 regex (from `_engine.constants`):

```
^[a-z0-9-]+:[a-zA-Z0-9_-]+$
```

Examples accepted: `eip155:1`, `eip155:8453`, `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`.
Examples rejected: `8453` (no namespace), `EIP155:8453` (uppercase), `eip155:` (empty chain).

### `JsonResilienceResult` (`check_name = "json_resilience"`)

Probes the endpoint itself.

| `status`         | When                                                                  |
|------------------|-----------------------------------------------------------------------|
| `PASS`           | Endpoint returns non-402 OR 402 body is a JSON object                 |
| `CRITICAL_FAIL`  | 402 body is a JSON primitive (string/number/array/null) or non-JSON   |
| `ERROR`          | Timeout, connection refused, or other transport failure               |

### `BazaarResult` (`check_name = "bazaar_compliance"`)

Static check on the HTTP 402 response body for the `extensions.bazaar` block.

The block is an **optional** marketplace-discovery extension, not part of the
core PaymentRequired contract, so its absence is conformant. The shape below
was verified against every production capture that carries it
(`viridis_regulatory_radar`, `viridis_ghg_ledger`, `asterpay_crypto_prices`,
`asterpay_sentiment` — all four agree byte-for-byte).

| Field                        | Type   | Constraint                                    |
|------------------------------|--------|-----------------------------------------------|
| `info.input.type`            | `str`  | Present, e.g. `"http"`                        |
| `info.input.method`          | `str`  | Present, e.g. `"GET"` / `"POST"`              |
| `info.output.type`           | `str`  | Present, e.g. `"json"`                        |
| `schema`                     | `dict` | Optional; when present must be a JSON object  |

| `status` | When                                                                    |
|----------|-------------------------------------------------------------------------|
| `PASS`   | Block valid, block absent, or no 402 body available (skip = pass)       |
| `FAIL`   | Block present but malformed (missing `info`, `input`/`output`, bad type) |

> **Historical note.** Before `c98311d` this check required `method == "POST"`,
> `serviceName`, and `tags` — a shape no real merchant emits. It failed 4/4
> conformant Bazaar merchants. If you are following an older copy of this
> document, disregard those three fields.

### `BotWallResult` (`check_name = "bot_wall"`)

Detects a bot-protection layer answering in place of the origin. This is the
most common silent x402 failure: the buying agent is served a challenge page
and walks away, while the merchant's own browser sees a perfectly healthy site.

Signals: `cf-mitigated`, `cf-ray`, `x-sucuri-id`/`x-sucuri-block`,
`x-distil-cs`, `x-cdn: incapsula`, `x-iinfo`; a `server` header naming
Cloudflare/Sucuri/Incapsula; and challenge-page body markers
(`cf_chl_`, `g-recaptcha`, `hcaptcha.com`, `just a moment...`, …).

| `status` | When                                                                        |
|----------|-----------------------------------------------------------------------------|
| `PASS`   | No bot-wall signal                                                          |
| `FAIL`   | HTTP 403 with any signal, or HTTP 403/503 with two or more body markers     |
| `ERROR`  | Transport failure (message distinguishes timeout from connection error)     |

`details`: `status_code`, `signals` (list of what matched), `blocked` (bool).

### `AcceptsCompletenessResult` (`check_name = "accepts_completeness"`)

Validates the decoded PaymentRequired payload — from the `payment-required`
header first, then a JSON body.

Per `accepts[]` entry, all of the following must be present: `scheme`,
`network`, `payTo` (or legacy `pay_to`), `resource`, and `amount` (or legacy
`maxAmountRequired`). The amount must be a **digit string of atomic units**: a
value containing `.` is reported as dollars quoted by mistake (off by 10⁶ for
USDC). The payload's `x402Version` must be `1` or `2`, and a top-level
`resource.url`, when present, must match the probed URL.

| `status` | When                                                        |
|----------|-------------------------------------------------------------|
| `PASS`   | No findings, or endpoint is not 402 (`applicable: false`)   |
| `FAIL`   | One or more findings                                        |
| `ERROR`  | Transport failure, or 402 with no decodable payload         |

`details`: `status_code`, `applicable`, `entries_checked`, `findings` (list of
operator-actionable strings, each naming the offending index and field).

### `DiscoveryResourceResult` (`check_name = "discovery_resource_listing"`)

A paid resource absent from the catalog is invisible to the agents that would
pay for it, however conformant its 402 response is. The paid URL is taken from
the payload's `resource.url` or the first `accepts[].resource`, then looked up
in the **origin's** `/.well-known/x402` (`resources[]` or `products[]`) — the
catalog is always resolved at the origin root, never under the probed path.

| `status` | When                                                                     |
|----------|--------------------------------------------------------------------------|
| `PASS`   | Resource listed; not 402; or payload declares no resource to verify      |
| `FAIL`   | Paid resource absent from the catalog                                    |
| `ERROR`  | Transport failure, or catalog unreachable/not JSON while a resource is paid |

`details`: `applicable`, `listed` (`True`/`False`/`None`), `resource`,
`catalog_size`.

### `MarketplaceResult` (`check_name = "marketplace_products"`)

Catalog-level check (only in `marketplace` mode). For each product in
`manifest["products"]`, validates:

- `x402.scheme == "exact"`
- `x402.network` matches CAIP-2
- `x402.pay_to` or `payTo` is set
- `x402.facilitator_url` is set
- `method` (if specified) is `"GET"`

| `status` | When                                |
|----------|-------------------------------------|
| `PASS`   | All products conformant             |
| `FAIL`   | One or more products non-conformant |

### `ProductResult` (`check_name = "product_check"`)

Per-endpoint probe inside marketplace mode.

| `status` | Case                                                            |
|----------|-----------------------------------------------------------------|
| `PASS`   | Free product returns 200 OR paid returns 402 with header        |
| `FAIL`   | Paid returns non-402, or 402 missing `Payment-Required` header  |
| `ERROR`  | Transport failure                                               |

### `AuditReport` (top-level)

Aggregate result of all checks for one target.

| Field            | Type     | Notes                                                      |
|------------------|----------|------------------------------------------------------------|
| `target_url`     | `str`    | The URL audited                                            |
| `timestamp`      | `datetime` | UTC, when audit finished                                 |
| `overall_status` | `AuditReport.status` | Worst check status                              |
| `checks`         | `list[CheckResult]`  | All results (7 in standard, more in marketplace) |
| `summary`        | `str`    | One-line summary like `"6/7 checks passed. Overall: FAIL"` |

---

## Functions

### `check_manifest(client, base_url) -> ManifestResult`

GET `base_url/.well-known/x402`. Verifies:

1. HTTP 200
2. Body parses as JSON object
3. Body has `accepts` (list) or non-empty `products` (list)

Network failures → `status=ERROR` (never raises).

### `check_caip2(client, target_url) -> Caip2Result`

Probes `target_url` for payment headers. Decodes each candidate as
`base64(JSON)` and validates the `network` field against the CAIP-2 regex.
First match wins.

### `check_json_resilience(client, endpoint_url) -> JsonResilienceResult`

GET `endpoint_url`. If status is 402, verifies the body is a JSON object
(not a primitive or non-JSON text).

### `check_bazaar(response_body) -> BazaarResult`

Pure function (no I/O). Validates an HTTP 402 body for the `extensions.bazaar` block.

Pass `None` to skip the check (returns `PASS` with "skipped" message).

### `check_bazaar_for_url(client, target_url) -> BazaarResult`

Convenience wrapper: `GET target_url`, extract 402 body, run `check_bazaar`.

### `check_bot_wall(client, target_url) -> BotWallResult`

GET `target_url` and inspect status, headers, and body for bot-protection
fingerprints. FAILs on HTTP 403 with any signal, or HTTP 403/503 with two or
more challenge-body markers.

### `check_accepts_completeness(client, target_url) -> AcceptsCompletenessResult`

GET `target_url`; when it returns 402, decode the PaymentRequired payload and
validate `x402Version` plus every `accepts[]` entry — required fields present
and `amount` expressed in atomic units. Non-402 responses return PASS with
`applicable: false`.

### `check_discovery_resource_listing(client, target_url) -> DiscoveryResourceResult`

GET `target_url`; when it returns 402, resolve the paid resource URL and verify
it appears in the origin's `/.well-known/x402` catalog. The catalog is fetched
from the origin root even when `target_url` points at a nested product path.

### `check_marketplace(client, base_url, manifest_payload) -> MarketplaceResult`

Validate each product in `manifest_payload["products"]`.

### `check_product_endpoint(client, base_url, product) -> ProductResult`

Probe `{base_url}{product["endpoint"]}`. Free products should return 200,
paid products should return 402 + `Payment-Required` header.

### `run_audit(url, *, timeout=10.0, mode="standard", transport=None) -> AuditReport`

One-shot entry point.

```python
import asyncio
from x402_conformance_suite.conformance import run_audit

async def main():
    report = await run_audit("https://observer.137-184-67-179.sslip.io")
    print(report.summary)

asyncio.run(main())
```

### `X402Auditor` class

Use as an async context manager:

```python
async with X402Auditor(timeout=15.0, default_headers={"User-Agent": "x402-conformance-suite"}) as auditor:
    report = await auditor.run_full_audit("https://example.com", mode="marketplace")
```

Constructor parameters:

| Parameter           | Type                          | Default | Purpose                                  |
|---------------------|-------------------------------|---------|------------------------------------------|
| `timeout`           | `float`                       | `10.0`  | Per-request timeout (seconds)            |
| `default_headers`   | `Optional[dict[str, str]]`    | `None`  | Headers applied to every request         |
| `follow_redirects`  | `bool`                        | `True`  | Whether httpx follows 3xx                |
| `transport`         | `Optional[httpx.AsyncBaseTransport]` | `None` | Inject custom transport (testing)  |

Public methods:

| Method                            | Returns       | Notes                                       |
|-----------------------------------|---------------|---------------------------------------------|
| `__aenter__` / `__aexit__`        | —             | Manages the underlying `httpx.AsyncClient`  |
| `run_full_audit(url, mode=...)`   | `AuditReport` | Aggregates all relevant checks              |

---

## Constants

```python
from x402_conformance_suite.conformance import (
    CAIP2_PATTERN,    # re.Pattern[str] — CAIP-2 regex
    PAYMENT_HEADERS,  # tuple[str, ...] — probed in priority order
    CheckMode,        # class with .STANDARD, .MARKETPLACE, .ALL
)
```

---

## Import surface

| Import path                              | Contains                                                        |
|------------------------------------------|-----------------------------------------------------------------|
| `x402_conformance_suite`                 | `X402Auditor`, `run_audit`, `AuditReport`, `__version__`         |
| `x402_conformance_suite.conformance`     | **Everything public** — all result models, all `check_*`, constants |
| `x402_conformance_suite._engine`         | Implementation detail; layout may change without a major bump    |

Import from `conformance` unless you have a reason not to.

---

## Error semantics

| Network class             | Handling                                         |
|---------------------------|--------------------------------------------------|
| `httpx.TimeoutException`  | Resolved to `status=ERROR` (or `status=FAIL` for `check_caip2`) |
| `httpx.ConnectError`      | Same                                            |
| `httpx.HTTPError` and subclasses | Same (for `_safe_get` consumers)        |
| Any other `Exception`     | Caught and surfaced as `status=ERROR`            |

No check function ever raises — all exceptions become typed results.
