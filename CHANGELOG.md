# Changelog

All notable changes to x402-conformance-suite are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com). This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.5.2] - 2026-07-29

### Fixed

- **Marketplace mode mis-graded x402 v2 `routes[]` catalogs.** Manifests that
  advertise a route catalog via a top-level `routes[]` array (x402 v2, e.g.
  the Viridis Conservation gateway) were walked, but every route was treated
  as a *free* product — the walker expected HTTP 200 and probed with GET.
  Paid routes (those carrying `price_minor` / `x402_version` / `v2_enabled`)
  are now recognized as paid, probed with their declared
  `paid_execution_method` (POST), and expected to return 402.

- **Paid POST routes that gate input before the paywall now report honestly.**
  Endpoints that validate the request body against their Bazaar `input_schema`
  *before* emitting the 402 challenge returned HTTP 400 to an empty-body probe.
  The engine now builds a schema-valid minimal body from the route's advertised
  `input_schema` (first `enum` value / type-appropriate default) to reach the
  challenge. When no `input_schema` is published, the route is reported with a
  clear, operator-actionable message explaining that the validator cannot
  construct a valid body to reach the paywall — instead of the misleading
  "free product should return 200" failure.

### Added

- `_build_min_body()` / `_placeholder_for()` helpers for JSON-schema-driven
  request synthesis, and `product_paid_needs_input()` message. 10 new tests
  covering routes[] normalization, body synthesis, and the 400 input-gate path
  (226 tests total).

## [0.5.1] - 2026-07-28

### Fixed

- **CSV writer silently dropped three v0.5.0 checks.** `report_to_row()`
  hardcoded the old four check names; `bot_wall`,
  `accepts_completeness`, `discovery_resource_listing` never appeared in
  the output. A report could show `overall_status=FAIL` with four `PASS`
  columns and no clue why. `write_csv` also froze the header from row 0,
  so fixing `report_to_row` alone would crash with `ValueError` on the
  second row. Now both are fully dynamic: every check in the report
  becomes a column, repeated checks get `_N` suffixes, and the header is
  the union of all row keys.

- **New result types were unimportable.** `BotWallResult`,
  `AcceptsCompletenessResult`, `DiscoveryResourceResult` were missing from
  `_engine/__init__.py` and `conformance.py`. Both now export them plus
  the three check functions (`check_bot_wall`, `check_accepts_completeness`,
  `check_discovery_resource_listing`) so library consumers can pattern-match
  and type-annotate against them. Top-level `__init__.py` gained
  `__version__` from package metadata.

- **Three checks bypassed `messages.py`, violating the project rule.** ~25
  inline f-strings migrated to `messages.py` with proper sections:
  `=== Bot wall ===`, `=== accepts[] completeness ===`, `=== Discovery
  resource listing ===`. Network error granularity (timeout vs connect
  vs other) preserved in the new checks, matching the original four.

- **CI blind spot.** The workflow ran `pytest test_*.py` — silently
  skipping the entire `tests/` engine suite. Fixed to run
  `tests/ test_cli.py test_mcp_server.py` explicitly. Added a `package`
  job that builds, validates with `twine check`, installs the wheel in a
  clean venv, and verifies the public surface exports all 26 public names.

## [0.5.0] - 2026-07-27

### Added

Standard audit grows from 4 to 7 checks (additive only — no existing
check renamed, removed, or reordered).

- `bot_wall` — detects bot-protection layers (Cloudflare challenge,
  Sucuri, Incapsula/Distil, reCAPTCHA/hCaptcha challenge pages)
  answering with 403/503 instead of the origin. Bot-walls block agent
  buyers before they ever see the paywall; this is the #1 silent
  killer of x402 integrations in the wild.
- `accepts_completeness` — every `accepts[]` entry must carry `scheme`,
  `network`, `payTo`, `resource`, and an `amount` (or legacy
  `maxAmountRequired`) that is a digit string of atomic units — a
  decimal value like `"0.005"` is flagged as dollars (off by 10⁶).
  `x402Version` must be present and recognized (1 or 2), and a
  top-level `resource.url` must match the probed URL. Covers the four
  "silent first-integration mistakes" documented across the ecosystem.
- `discovery_resource_listing` — a paid resource (from the 402
  payload's `resource.url` or `accepts[].resource`) must appear in the
  origin's `/.well-known/x402` catalog (`resources[]` or `products[]`),
  otherwise agents cannot discover it.

### Notes

- 18 new tests (6 per check). 203/203 pass.
- `tests/test_engine.py` audit-level mocks updated: previously
  incomplete mock payloads now exercise all 7 checks.
- API consumers: the `checks[]` array in audit reports now contains
  seven entries in standard mode. Additive change, but any consumer
  asserting an exact count of 4 must be updated.

## [0.4.1] - 2026-07-27

### Fixed

- `check_caip2` only read the network identifier at the top level of the
  decoded payment payload (`network` / `chainId`). x402 v2 PaymentRequired
  carries the network per payment option at `accepts[].network`, so every
  strict-v2 endpoint was falsely reported as CAIP-2 non-compliant. The
  parser now collects candidates from both locations (top-level first,
  then each `accepts[]` entry in order) and PASSes on the first valid
  CAIP-2 value. Confirmed live against a production merchant whose 402
  payload was valid v2 (`accepts[0].network = eip155:8453`) yet audited
  FAIL before this fix.
- Marketplace mode ran `check_caip2` against the catalog root URL only.
  Merchants with an intentionally free discovery page (HTTP 200, no
  payment headers) auto-failed CAIP-2 even when every paid product
  returned a conformant 402. When the root probe finds no payment header,
  the audit now falls back to the networks declared in each paid
  product's own 402 PaymentRequired payload (captured during the
  per-product walk, no extra requests) and the product-derived result
  supersedes the root "header missing" FAIL in place, so the aggregate
  verdict reflects the networks the products actually enforce.
- The manifest-declared network fallback only read a top-level
  `manifest.network` string and only ran in marketplace mode. Manifests
  like AsterPay's declare the enforced network at `accepts[].network`
  (or `resources[].accepts[].network`), and standard-mode audits (what
  the API serves) had no fallback at all. The fallback now collects
  candidates from all three manifest locations and runs in both modes,
  superseding the root "header missing" FAIL in place. Verified live:
  AsterPay standard audit 4/4 PASS (was caip2_compliance FAIL).
- Reported by a merchant via Discord after the 0.4.0 outreach round;
  both failure modes reproduced live before fixing.

### Added

- 14 regression tests: v2 `accepts[].network` pass/invalid/second-entry/
  top-level-priority cases for `check_caip2`, `_network_candidates` unit
  tests, a marketplace-mode auditor test proving the free-root +
  paid-product layout aggregates PASS, and three manifest-fallback tests
  (`accepts[]`, `resources[].accepts[]`, root-header-wins).

## [0.3.1] - 2026-07-27

### Fixed

- `check_bazaar` validated `extensions.bazaar` against an assumed shape
  (`method == "POST"`, `serviceName`, `tags`) that does not match any real
  x402 capture. Corrected against the four production captures that
  actually carry the block — all agree on
  `info.input.type`/`info.input.method`/`info.output.type`/`schema`.
  The block is also now correctly treated as OPTIONAL (absence is PASS,
  not FAIL). The previous check would FAIL every real Bazaar-conformant
  merchant tested (AsterPay, Viridis) on this specific check; confirmed
  live on the deployed API before this fix shipped.
- `project.urls` in `pyproject.toml` pointed at
  `smartflowproai-lang/x402-endpoint-validator` (the upstream repo this
  package forked from) instead of this package's own repository. Fixed to
  point at `MSSATANASS/x402-conformance-engine`.

### Project

- Same bazaar-check correction submitted upstream as
  `smartflowproai-lang/x402-endpoint-validator#16`, built independently
  against the same four production captures, scoped to just the check +
  tests + two negative fixtures (no package/CLI/MCP — per upstream
  maintainer's review on PR #9).

## [0.4.0] - 2026-07-27

### Quality refactor

The conformance engine was split from a single 670-line file into a
focused package of single-responsibility modules. No behaviour change
intended; observable output and CLI are identical.

- Engine refactored into the `x402_conformance_suite._engine` *package* with:
  - `auditor.py` — `X402Auditor` and `run_audit` orchestration.
  - `checks.py` — one async function per check (`check_manifest`,
    `check_caip2`, `check_json_resilience`, `check_bazaar`,
    `check_marketplace`, `check_product_endpoint`).
  - `constants.py` — `CAIP2_PATTERN`, `PAYMENT_HEADERS`, `CheckMode`.
  - `models.py` — Pydantic result classes (`CheckResult`,
    `ManifestResult`, `Caip2Result`, `JsonResilienceResult`,
    `BazaarResult`, `ProductResult`, `MarketplaceResult`, `AuditReport`).
  - `messages.py` — centralised, actionable human-readable strings.
- Legacy `x402_conformance_engine.py` removed (was a 428-line duplicate of
  the published engine structure).
- `tests/test_engine.py` introduced (60 kB, 118 tests). 100 % line
  coverage of `x402_conformance_suite/_engine/`.
- `tests/test_bazaar_checker.py`, `tests/test_marketplace.py`,
  `tests/test_ecosystem_checks.py`,
  `tests/test_x402_conformance_engine.py` removed (tested the legacy
  module that no longer exists).
- `docs/API.md` — exhaustive specification of every public function and
  result type.
- `docs/DESIGN.md` — what the engine does, what it doesn't, and why.
- `docs/VALIDATION_REPORT_v0.3.md` — 27 endpoints audited in 5.2 s.
- `CONTRIBUTING.md` rewritten in English with explicit rules for adding
  checks without breaking the contract.
- `x402_conformance_suite/cli.py::audit_command` now accepts `output` as either
  `list[str]` or `str` (backward compatible with previous single-string
  callers).
- `X402Auditor` constructor accepts an optional `transport=` for
  `httpx.MockTransport` (used in tests).
- Error messages now include operator-actionable remediation text in
  every `FAIL` and `CRITICAL_FAIL`.

## [0.2.0] — 2026-07-25

Initial PyPI release. Manifest discovery, CAIP-2 compliance, JSON
resilience, bazaar compliance; `--mode marketplace` for multi-product
catalogs; MCP server and CLI.
