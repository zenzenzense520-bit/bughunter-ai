"""Finding state machine tests."""

import pytest

from bughunter.core.enums import FindingStatus
from bughunter.core.errors import IllegalTransitionError
from bughunter.core.state import assert_transition, can_transition, is_terminal


def test_happy_path_to_submitted():
    path = [
        FindingStatus.NEW,
        FindingStatus.AI_TRIAGED,
        FindingStatus.PENDING_REVIEW,
        FindingStatus.CONFIRMED,
        FindingStatus.REPORT_DRAFTED,
        FindingStatus.REPORT_REVIEWED,
        FindingStatus.PACK_READY,
        FindingStatus.SUBMITTED,
    ]
    for current, target in zip(path, path[1:]):
        assert_transition(current.value, target.value)


def test_human_can_skip_ai_when_unavailable():
    assert can_transition(FindingStatus.NEW.value, FindingStatus.PENDING_REVIEW.value)


def test_triage_failed_can_retry_or_go_to_human():
    assert can_transition(
        FindingStatus.TRIAGE_FAILED.value, FindingStatus.AI_TRIAGED.value
    )
    assert can_transition(
        FindingStatus.TRIAGE_FAILED.value, FindingStatus.PENDING_REVIEW.value
    )


def test_new_cannot_jump_straight_to_confirmed():
    assert not can_transition(
        FindingStatus.NEW.value, FindingStatus.CONFIRMED.value
    )
    with pytest.raises(IllegalTransitionError):
        assert_transition(FindingStatus.NEW.value, FindingStatus.CONFIRMED.value)


def test_terminal_states_cannot_move():
    for state in (
        FindingStatus.FALSE_POSITIVE,
        FindingStatus.DUPLICATE,
        FindingStatus.OUT_OF_SCOPE,
        FindingStatus.SUBMITTED,
    ):
        assert is_terminal(state.value)
        assert not can_transition(
            state.value, FindingStatus.PENDING_REVIEW.value
        )


def test_review_rejection_returns_to_confirmed():
    assert can_transition(
        FindingStatus.REPORT_DRAFTED.value, FindingStatus.CONFIRMED.value
    )


def test_unknown_state_is_rejected():
    assert not can_transition("nope", "new")
    assert not is_terminal("nope")
