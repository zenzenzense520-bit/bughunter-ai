"""Finding lifecycle state machine (whitelist-gated transitions).

    new
     |- ai_triaged -> pending_review
     |- triage_failed -> ai_triaged (retry) | pending_review (human skips AI)
     |- pending_review (AI unavailable)
    pending_review
     |- confirmed -> report_drafted -> report_reviewed -> pack_ready -> submitted
     |- false_positive / duplicate / out_of_scope (terminal)

Only humans may confirm a finding or enter the submitted terminal state.
"""

from .enums import FindingStatus
from .errors import IllegalTransitionError

# Whitelist of legal transitions. Terminal states are absent from the keys.
ALLOWED_TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.NEW: frozenset(
        {
            FindingStatus.AI_TRIAGED,
            FindingStatus.TRIAGE_FAILED,
            FindingStatus.PENDING_REVIEW,
        }
    ),
    FindingStatus.AI_TRIAGED: frozenset(
        {FindingStatus.PENDING_REVIEW, FindingStatus.TRIAGE_FAILED}
    ),
    FindingStatus.TRIAGE_FAILED: frozenset(
        {FindingStatus.AI_TRIAGED, FindingStatus.PENDING_REVIEW}
    ),
    FindingStatus.PENDING_REVIEW: frozenset(
        {
            FindingStatus.CONFIRMED,
            FindingStatus.FALSE_POSITIVE,
            FindingStatus.DUPLICATE,
            FindingStatus.OUT_OF_SCOPE,
        }
    ),
    FindingStatus.CONFIRMED: frozenset({FindingStatus.REPORT_DRAFTED}),
    FindingStatus.REPORT_DRAFTED: frozenset(
        {FindingStatus.REPORT_REVIEWED, FindingStatus.CONFIRMED}
    ),
    FindingStatus.REPORT_REVIEWED: frozenset(
        {FindingStatus.PACK_READY, FindingStatus.REPORT_DRAFTED}
    ),
    FindingStatus.PACK_READY: frozenset(
        {FindingStatus.SUBMITTED, FindingStatus.REPORT_REVIEWED}
    ),
}

TERMINAL_STATES: frozenset[FindingStatus] = frozenset(
    {
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.DUPLICATE,
        FindingStatus.OUT_OF_SCOPE,
        FindingStatus.SUBMITTED,
    }
)


def can_transition(current: str, target: str) -> bool:
    """Return True if moving from current to target is whitelisted."""
    try:
        current_state = FindingStatus(current)
        target_state = FindingStatus(target)
    except ValueError:
        return False
    return target_state in ALLOWED_TRANSITIONS.get(current_state, frozenset())


def is_terminal(state: str) -> bool:
    try:
        return FindingStatus(state) in TERMINAL_STATES
    except ValueError:
        return False


def assert_transition(current: str, target: str) -> None:
    """Raise IllegalTransitionError unless the move is whitelisted."""
    if not can_transition(current, target):
        raise IllegalTransitionError(
            f"Finding 状态非法迁移: {current} -> {target}"
        )
