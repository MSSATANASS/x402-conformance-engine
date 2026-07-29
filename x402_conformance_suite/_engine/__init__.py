"""Public package exports for the x402 conformance engine.

Layout:
    _engine.models     — Pydantic result types
    _engine.constants  — Module-level constants (regex patterns, header names)
    _engine.messages   — Actionable, human-readable error/warning messages
    _engine.checks     — Single-responsibility check functions
    _engine.auditor    — X402Auditor class (orchestrator)
"""

from x402_conformance_suite._engine.auditor import X402Auditor, run_audit
from x402_conformance_suite._engine.checks import (
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
)
from x402_conformance_suite._engine.constants import (
    CAIP2_PATTERN,
    PAYMENT_HEADERS,
    CheckMode,
)
from x402_conformance_suite._engine.models import (
    AcceptsCompletenessResult,
    AuditReport,
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
