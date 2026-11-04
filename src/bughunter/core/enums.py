"""Domain enumerations. Values are stored as strings in SQLite."""

from enum import Enum


class TargetStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    EXPIRED = "expired"
    ARCHIVED = "archived"


class ScopeKind(str, Enum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


class ScopeRuleType(str, Enum):
    """Include rules only allow host/host_suffix; excludes only allow path_regex."""

    HOST = "host"
    HOST_SUFFIX = "host_suffix"
    PATH_REGEX = "path_regex"


class TaskKind(str, Enum):
    SAST = "sast"
    PASSIVE_SCAN = "passive_scan"
    ACTIVE_SCAN = "active_scan"  # hard-disabled in v1


class TaskStatus(str, Enum):
    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"


class ScanStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Tool(str, Enum):
    SEMGREP = "semgrep"
    ZAP_BASELINE = "zap_baseline"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    NEW = "new"
    AI_TRIAGED = "ai_triaged"
    TRIAGE_FAILED = "triage_failed"
    PENDING_REVIEW = "pending_review"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"
    OUT_OF_SCOPE = "out_of_scope"
    REPORT_DRAFTED = "report_drafted"
    REPORT_REVIEWED = "report_reviewed"
    PACK_READY = "pack_ready"
    SUBMITTED = "submitted"


class AuditAction(str, Enum):
    TARGET_CREATED = "target_created"
    TARGET_ARCHIVED = "target_archived"
    AUTHORIZATION_ADDED = "authorization_added"
    AUTHORIZATION_CONFIRMED = "authorization_confirmed"
    SCOPE_ENTRY_ADDED = "scope_entry_added"
    GATE_BLOCKED = "gate_blocked"
    SCOPE_BLOCKED = "scope_blocked"
    RATE_LIMIT_BLOCKED = "rate_limit_blocked"
    TASK_CREATED = "task_created"
    SCAN_STARTED = "scan_started"
    SCAN_FINISHED = "scan_finished"
    SCAN_FAILED = "scan_failed"
    ACTIVE_SCAN_BLOCKED = "active_scan_blocked"
    FINDING_RECORDED = "finding_recorded"
    FINDING_DEDUPED = "finding_deduped"
