"""x402 strict-v2 conformance engine.

Quick start::

    from x402_conformance_suite import run_audit
    report = await run_audit("https://merchant.example")

For the full surface — every result model and check function — import from
``x402_conformance_suite.conformance``.
"""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

from ._engine import AuditReport, X402Auditor, run_audit

try:
    __version__ = _pkg_version("x402-conformance-suite")
except PackageNotFoundError:  # running from a source tree without install
    __version__ = "0.0.0+unknown"

__all__ = ["X402Auditor", "run_audit", "AuditReport", "__version__"]
