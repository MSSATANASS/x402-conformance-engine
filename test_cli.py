import json
import os
import pytest

from x402_conformance_suite.cli import (
    read_urls_from_file,
    report_to_row,
    write_csv,
    write_json,
    write_html,
    audit_command,
)
from x402_conformance_suite._engine import (
    AcceptsCompletenessResult,
    AuditReport,
    BazaarResult,
    BotWallResult,
    Caip2Result,
    DiscoveryResourceResult,
    JsonResilienceResult,
    ManifestResult,
    MarketplaceResult,
    ProductResult,
)
from datetime import datetime, timezone


def make_report(
    url: str,
    status: str = "PASS",
    manifest: str = "PASS",
    caip2: str = "PASS",
    json_res: str = "PASS",
    bazaar: str = "PASS",
    bot_wall: str = "PASS",
    accepts: str = "PASS",
    discovery: str = "PASS",
) -> AuditReport:
    """Build a full standard-mode report — all seven checks.

    The fixture mirrors what ``run_full_audit`` actually returns. It used to
    stop at four, which is precisely why the CSV writer could silently drop
    the other three without a single test noticing.
    """
    return AuditReport(
        target_url=url,
        timestamp=datetime.now(timezone.utc),
        overall_status=status,
        checks=[
            ManifestResult(status=manifest, message="ok"),
            Caip2Result(status=caip2, message="ok"),
            JsonResilienceResult(status=json_res, message="ok"),
            BazaarResult(status=bazaar, message="ok"),
            BotWallResult(status=bot_wall, message="ok"),
            AcceptsCompletenessResult(status=accepts, message="ok"),
            DiscoveryResourceResult(status=discovery, message="ok"),
        ],
        summary="",
    )


def make_marketplace_report(url: str, products: int = 2) -> AuditReport:
    """Standard checks plus catalog + repeated per-product results."""
    checks = [
        ManifestResult(status="PASS", message="ok"),
        Caip2Result(status="PASS", message="ok"),
        JsonResilienceResult(status="PASS", message="ok"),
        BazaarResult(status="PASS", message="ok"),
        BotWallResult(status="PASS", message="ok"),
        AcceptsCompletenessResult(status="PASS", message="ok"),
        DiscoveryResourceResult(status="PASS", message="ok"),
        MarketplaceResult(status="PASS", message="ok"),
    ]
    for i in range(products):
        checks.append(ProductResult(status="PASS", message=f"product {i}"))
    return AuditReport(
        target_url=url,
        timestamp=datetime.now(timezone.utc),
        overall_status="PASS",
        checks=checks,
        summary="",
    )


class TestReadUrlsFromFile:
    def test_reads_urls(self, tmp_path):
        f = tmp_path / "urls.txt"
        f.write_text("https://a.com\nhttps://b.com\n")
        urls = read_urls_from_file(str(f))
        assert urls == ["https://a.com", "https://b.com"]

    def test_skips_blanks_and_comments(self, tmp_path):
        f = tmp_path / "urls.txt"
        f.write_text("# comentario\nhttps://a.com\n\nhttps://b.com\n")
        urls = read_urls_from_file(str(f))
        assert urls == ["https://a.com", "https://b.com"]

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        urls = read_urls_from_file(str(f))
        assert urls == []


class TestReportToRow:
    def test_converts_report(self):
        r = make_report("https://test.com", status="PASS")
        row = report_to_row(r)
        assert row["url"] == "https://test.com"
        assert row["overall_status"] == "PASS"
        assert row["manifest_discovery"] == "PASS"
        assert row["bazaar_compliance"] == "PASS"

    def test_failed_report(self):
        r = make_report("https://fail.com", status="FAIL", manifest="FAIL")
        row = report_to_row(r)
        assert row["overall_status"] == "FAIL"
        assert row["manifest_discovery"] == "FAIL"

    def test_carries_every_check_in_the_report(self):
        """Regression: the row was a hardcoded allow-list of four names, so
        v0.5.0's three new checks vanished from CSV output entirely."""
        r = make_report("https://test.com")
        row = report_to_row(r)
        for name in (
            "manifest_discovery",
            "caip2_compliance",
            "json_resilience",
            "bazaar_compliance",
            "bot_wall",
            "accepts_completeness",
            "discovery_resource_listing",
        ):
            assert name in row, f"{name} missing from CSV row"

    def test_failing_check_is_visible_not_just_overall(self):
        """The whole point of the CSV: overall=FAIL must be explainable by a
        column. Previously a report could show FAIL with every visible column
        PASS, because the failing check had no column."""
        r = make_report("https://fail.com", status="FAIL", accepts="FAIL")
        row = report_to_row(r)
        assert row["overall_status"] == "FAIL"
        assert row["accepts_completeness"] == "FAIL"
        assert any(v == "FAIL" for k, v in row.items() if k != "overall_status")

    def test_unknown_future_check_still_round_trips(self):
        """Nothing is hardcoded: a check the CLI has never heard of appears."""
        from x402_conformance_suite._engine.models import CheckResult

        r = make_report("https://test.com")
        r.checks.append(CheckResult(check_name="some_future_check", status="FAIL", message="x"))
        row = report_to_row(r)
        assert row["some_future_check"] == "FAIL"

    def test_repeated_product_checks_do_not_overwrite(self):
        r = make_marketplace_report("https://market.com", products=3)
        row = report_to_row(r)
        assert row["product_check"] == "PASS"
        assert row["product_check_2"] == "PASS"
        assert row["product_check_3"] == "PASS"

    def test_timestamp_stays_last(self):
        row = report_to_row(make_report("https://test.com"))
        assert list(row.keys())[-1] == "timestamp"


class TestWriteCsv:
    def test_writes_csv(self, tmp_path):
        reports = [make_report("https://a.com"), make_report("https://b.com", status="FAIL")]
        p = str(tmp_path / "out.csv")
        write_csv(reports, p)
        with open(p) as f:
            content = f.read()
        assert "https://a.com" in content
        assert "https://b.com" in content
        assert "overall_status" in content

    def test_header_covers_all_seven_checks(self, tmp_path):
        p = str(tmp_path / "out.csv")
        write_csv([make_report("https://a.com")], p)
        header = open(p).readline()
        for name in ("bot_wall", "accepts_completeness", "discovery_resource_listing"):
            assert name in header

    def test_mixed_modes_do_not_raise_and_pad_missing_cells(self, tmp_path):
        """Regression: fieldnames came from rows[0] only, so a later row with
        extra columns (marketplace after standard) raised ValueError."""
        import csv as _csv

        reports = [
            make_report("https://standard.com"),
            make_marketplace_report("https://market.com", products=2),
        ]
        p = str(tmp_path / "mixed.csv")
        write_csv(reports, p)  # must not raise

        with open(p, newline="") as f:
            rows = list(_csv.DictReader(f))
        assert len(rows) == 2
        assert rows[0]["marketplace_products"] == ""  # padded, not missing
        assert rows[1]["marketplace_products"] == "PASS"
        assert rows[1]["product_check_2"] == "PASS"


class TestWriteJson:
    def test_writes_json(self, tmp_path):
        reports = [make_report("https://a.com")]
        p = str(tmp_path / "out.json")
        write_json(reports, p)
        with open(p) as f:
            data = json.load(f)
        assert data["total"] == 1
        assert data["results"][0]["target_url"] == "https://a.com"


class TestWriteHtml:
    def test_writes_html(self, tmp_path):
        reports = [make_report("https://a.com"), make_report("https://b.com", status="FAIL")]
        p = str(tmp_path / "out.html")
        write_html(reports, p)
        with open(p) as f:
            content = f.read()
        assert "<table>" in content
        assert "https://a.com" in content
        assert "PASS" in content
        assert "FAIL" in content


class TestAuditCommand:
    """``audit_command`` accepts both ``list[str]`` and ``str`` for ``output``."""

    def test_list_output(self, tmp_path):
        urls_file = tmp_path / "urls.txt"
        urls_file.write_text("https://a.com\nhttps://b.com\n")
        mock_reports = [make_report("https://a.com"), make_report("https://b.com")]
        audit_command(
            str(urls_file),
            output=["csv"],
            output_path=str(tmp_path / "res.csv"),
            results=mock_reports,
        )
        assert os.path.exists(str(tmp_path / "res.csv"))

    def test_string_output_backward_compat(self, tmp_path):
        """Single string is treated as one-element list — keeps old test contracts working."""
        urls_file = tmp_path / "urls.txt"
        urls_file.write_text("https://a.com\n")
        mock_reports = [make_report("https://a.com")]
        audit_command(
            str(urls_file),
            output="csv",
            output_path=str(tmp_path / "res.csv"),
            results=mock_reports,
        )
        assert os.path.exists(str(tmp_path / "res.csv"))

    def test_multi_format(self, tmp_path):
        urls_file = tmp_path / "urls.txt"
        urls_file.write_text("https://a.com\n")
        mock_reports = [make_report("https://a.com")]
        audit_command(
            str(urls_file),
            output=["csv", "json"],
            output_path=None,
            results=mock_reports,
        )
        # Without a single-format output_path the writers use <base>.<ext> names
        expected_csv = tmp_path / "urls_results.csv"
        expected_json = tmp_path / "urls_results.json"
        assert expected_csv.exists()
        assert expected_json.exists()

    def test_unknown_format_rejected(self, tmp_path):
        urls_file = tmp_path / "urls.txt"
        urls_file.write_text("https://a.com\n")
        mock_reports = [make_report("https://a.com")]
        with pytest.raises(SystemExit) as exc_info:
            audit_command(
                str(urls_file),
                output=["bogus"],
                output_path=None,
                results=mock_reports,
            )
        assert exc_info.value.code == 2
