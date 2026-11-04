"""Semgrep JSON normalization tests."""

import pytest

from bughunter.core.enums import Severity, Tool
from bughunter.core.errors import ScannerError
from bughunter.scanners.normalize import make_dedup_key, normalize_semgrep


def test_normalize_sample_report(conftest_sample):
    result = normalize_semgrep(conftest_sample)

    assert result.tool == Tool.SEMGREP.value
    assert result.tool_version == "1.120.0"
    assert result.stats.results_count == 2
    assert result.stats.errors_count == 1
    assert result.stats.skipped_count == 1

    first, second = result.findings
    assert first.rule_id == "bughunter.python.eval-exec"
    assert first.severity == Severity.HIGH.value  # ERROR -> high
    assert first.cwe_id == "CWE-95"
    assert first.owasp_category == "A03:2021 - Injection"
    assert first.file_path == "app.py"  # leading src/ stripped
    assert first.line == 10
    assert first.source_ref.startswith("https://docs.python.org")
    assert first.dedup_key == "semgrep|bughunter.python.eval-exec|app.py|10"

    assert second.severity == Severity.MEDIUM.value  # WARNING -> medium
    assert second.cwe_id == "CWE-295"
    assert second.file_path == "lib/net.py"  # /src prefix stripped
    assert second.source_ref == ""  # no references in metadata


def test_dedup_key_is_stable():
    key1 = make_dedup_key("semgrep", "rule.x", "a/b.py", 12)
    key2 = make_dedup_key("semgrep", "rule.x", "a/b.py", 12)
    key3 = make_dedup_key("semgrep", "rule.x", "a/b.py", 13)
    assert key1 == key2
    assert key1 != key3


def test_malformed_json_raises():
    with pytest.raises(ScannerError):
        normalize_semgrep("{not valid json")


def test_non_object_top_level_raises():
    with pytest.raises(ScannerError):
        normalize_semgrep("[1, 2, 3]")


def test_empty_results_report():
    result = normalize_semgrep('{"version": "1.0", "results": []}')
    assert result.findings == []
    assert result.stats.results_count == 0
