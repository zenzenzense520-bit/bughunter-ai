"""Scanner runner protocol and strongly typed result models.

Tool-native JSON is kept only as ``raw_text`` for archival; every value the
application reasons about is carried by a NormalizedFinding (no loose dicts).
"""

from abc import ABC, abstractmethod
from pathlib import Path

from pydantic import BaseModel, Field


class NormalizedFinding(BaseModel):
    """One finding in a tool-independent shape."""

    rule_id: str
    title: str
    severity: str  # Severity value
    file_path: str = ""
    line: int = 0
    end_line: int = 0
    message: str = ""
    cwe_id: str = ""
    owasp_category: str = ""
    references: list[str] = Field(default_factory=list)
    source_ref: str = ""
    dedup_key: str = ""


class ScanStats(BaseModel):
    results_count: int = 0
    errors_count: int = 0
    skipped_count: int = 0


class RawScanResult(BaseModel):
    tool: str
    tool_version: str
    raw_text: str
    findings: list[NormalizedFinding] = Field(default_factory=list)
    stats: ScanStats = Field(default_factory=ScanStats)


class ToolRunner(ABC):
    """Common interface for all scanner backends."""

    @property
    @abstractmethod
    def tool(self) -> str:
        """Tool identifier (matches core.enums.Tool)."""

    @abstractmethod
    def run(self, code_path: Path) -> RawScanResult:
        """Execute the tool against a local code path and return normalized output."""
