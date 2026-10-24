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


class AuditAction(str, Enum):
    TARGET_CREATED = "target_created"
    TARGET_ARCHIVED = "target_archived"
    AUTHORIZATION_ADDED = "authorization_added"
    AUTHORIZATION_CONFIRMED = "authorization_confirmed"
    SCOPE_ENTRY_ADDED = "scope_entry_added"
    GATE_BLOCKED = "gate_blocked"
    SCOPE_BLOCKED = "scope_blocked"
    RATE_LIMIT_BLOCKED = "rate_limit_blocked"
    SCAN_STARTED = "scan_started"
    SCAN_FINISHED = "scan_finished"
