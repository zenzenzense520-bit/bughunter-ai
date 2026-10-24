"""Typed error hierarchy.

All business failures raise a BugHunterError subclass with a human-readable
reason. Errors are never silently swallowed (project rule).
"""


class BugHunterError(Exception):
    """Base error for all expected business failures."""


class AuthorizationError(BugHunterError):
    """Missing, unconfirmed, expired authorization or archived target."""


class ScopeViolationError(BugHunterError):
    """URL/host/path is outside the authorized scope."""


class BudgetExceededError(BugHunterError):
    """Per-second rate limit or daily request budget exceeded."""


class FeatureDisabledError(BugHunterError):
    """Feature hard-disabled in v1 (e.g. active scanning)."""


class ConfigurationError(BugHunterError):
    """Invalid local configuration or environment."""
