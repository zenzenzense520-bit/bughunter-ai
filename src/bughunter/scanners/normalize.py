"""Normalize Semgrep JSON output into tool-independent findings.

Semgrep severities are INFO / WARNING / ERROR; we map them to our five-level
scale. Container paths (/src/...) are stripped back to repo-relative paths.
"""

import json
import re

from ..core.enums import Severity, Tool
from ..core.errors import ScannerError
from .base import NormalizedFinding, RawScanResult, ScanStats

# Semgrep severity -> our scale.
SEVERITY_MAP: dict[str, str] = {
    "INFO": Severity.INFO.value,
    "WARNING": Severity.MEDIUM.value,
    "ERROR": Severity.HIGH.value,
}

_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)
_LEADING_SRC = re.compile(r"^(?:/)?src/")
# Loading a rules *directory* prefixes each check_id with the config path
# (e.g. "/rules" -> "rules.<id>"). Recover the id declared in the YAML.
_CUSTOM_RULE_RE = re.compile(r"(bughunter\..*)")


def canonical_rule_id(check_id: str) -> str:
    """Strip a config-directory prefix; leave third-party ids untouched."""
    match = _CUSTOM_RULE_RE.search(check_id)
    return match.group(1) if match else check_id


def make_dedup_key(tool: str, rule_id: str, rel_path: str, line: int) -> str:
    """Stable, human-readable dedup key for one rule hit."""
    return f"{tool}|{rule_id}|{rel_path}|{line}"


def _first_str(value: object) -> str:
    if isinstance(value, list) and value:
        return str(value[0])
    if isinstance(value, str):
        return value
    return ""


def _extract_cwe(metadata: dict) -> str:
    cwe = metadata.get("cwe", "")
    items = cwe if isinstance(cwe, list) else [cwe]
    for item in items:
        match = _CWE_RE.search(str(item))
        if match:
            return f"CWE-{match.group(1)}"
    return ""


def _repo_relative_path(path: str) -> str:
    path = path.replace("\\", "/").lstrip("/")
    return _LEADING_SRC.sub("", path)


def _title_from_rule(rule_id: str) -> str:
    tail = rule_id.split(".")[-1]
    return tail.replace("-", " ").strip() or rule_id


def _normalize_one(result: dict) -> NormalizedFinding:
    extra = result.get("extra") or {}
    metadata = extra.get("metadata") or {}
    rule_id = canonical_rule_id(str(result.get("check_id", "")))
    rel_path = _repo_relative_path(str(result.get("path", "")))
    start = result.get("start") or {}
    end = result.get("end") or {}
    line = int(start.get("line", 0) or 0)
    end_line = int(end.get("line", line) or line)
    severity_raw = str(extra.get("severity", "INFO")).upper()
    references = [
        str(item)
        for item in metadata.get("references", [])
        if isinstance(item, str)
    ]
    return NormalizedFinding(
        rule_id=rule_id,
        title=_title_from_rule(rule_id),
        severity=SEVERITY_MAP.get(severity_raw, Severity.INFO.value),
        file_path=rel_path,
        line=line,
        end_line=end_line,
        message=str(extra.get("message", "")),
        cwe_id=_extract_cwe(metadata),
        owasp_category=_first_str(metadata.get("owasp", "")),
        references=references,
        source_ref=references[0] if references else "",
        dedup_key=make_dedup_key(Tool.SEMGREP.value, rule_id, rel_path, line),
    )


def normalize_semgrep(raw_text: str) -> RawScanResult:
    """Parse Semgrep --json text. Raises ScannerError on malformed JSON."""
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ScannerError(f"Semgrep JSON 报告解析失败: {exc}") from exc
    if not isinstance(data, dict):
        raise ScannerError("Semgrep 报告顶层不是对象")

    results = data.get("results") or []
    findings = [
        _normalize_one(item) for item in results if isinstance(item, dict)
    ]

    errors = data.get("errors") or []
    hard_errors = [
        item
        for item in errors
        if isinstance(item, dict)
        and str(item.get("level", "")).lower() == "error"
    ]
    paths = data.get("paths") or {}
    skipped = paths.get("skipped") or []

    return RawScanResult(
        tool=Tool.SEMGREP.value,
        tool_version=str(data.get("version", "")),
        raw_text=raw_text,
        findings=findings,
        stats=ScanStats(
            results_count=len(findings),
            errors_count=len(hard_errors),
            skipped_count=len(skipped),
        ),
    )
