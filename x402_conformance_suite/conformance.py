"""Flat public API for the x402 conformance engine.

This module is the supported import surface. Everything below is re-exported
from ``_engine`` so callers never need to reach into a private package::

    from x402_conformance_suite.conformance import X402Auditor, BotWallResult

``_engine`` is an implementation detail and its layout may change; the names
exported here will not, without a major version bump.
"""

from x402_conformance_suite._engine import (
    CAIP2_PATTERN,
    PAYMENT_HEADERS,
    AcceptsCompletenessResult,
    AuditReport,
    BazaarResult,
    BotWallResult,
    Caip2Result,
    CheckMode,
    CheckResult,
    DiscoveryResourceResult,
    JsonResilienceResult,
    ManifestResult,
    MarketplaceResult,
    ProductResult,
    X402Auditor,
    check_accepts_completeness,
    check_bazaar,
    check_bazaar_for_url,
    check_bot_wall,
    check_caip2,
    check_discovery_resource_listing,
    check_json_resilience,
    check_manifest,
    check_marketplace,
    check_product_endpoint,
    run_audit,
)


__all__ = [
    # Orchestration
    "X402Auditor",
    "run_audit",
    # Result models
    "AuditReport",
    "CheckResult",
    "ManifestResult",
    "Caip2Result",
    "JsonResilienceResult",
    "BazaarResult",
    "BotWallResult",
    "AcceptsCompletenessResult",
    "DiscoveryResourceResult",
    "ProductResult",
    "MarketplaceResult",
    # Check functions
    "check_manifest",
    "check_caip2",
    "check_json_resilience",
    "check_bazaar",
    "check_bazaar_for_url",
    "check_bot_wall",
    "check_accepts_completeness",
    "check_discovery_resource_listing",
    "check_marketplace",
    "check_product_endpoint",
    # Constants
    "CAIP2_PATTERN",
    "PAYMENT_HEADERS",
    "CheckMode",
]
