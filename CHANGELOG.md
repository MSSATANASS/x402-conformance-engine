# Changelog

All notable changes to x402-conformance-suite are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com). This project adheres to
[Semantic Versioning](https://semver.org/).

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
- Reported by a merchant via Discord after the 0.4.0 outreach round;
  both failure modes reproduced live before fixing.

### Added

- 11 regression tests: v2 `accepts[].network` pass/invalid/second-entry/
  top-level-priority cases for `check_caip2`, `_network_candidates` unit
  tests, and a marketplace-mode auditor test proving the free-root +
  paid-product layout now aggregates PASS.

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
