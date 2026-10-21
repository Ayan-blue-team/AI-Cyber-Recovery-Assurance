import pytest

from assurance.engine import (
    AccountDisabledInvariant,
    MockEvidenceProvider,
    ScheduledTaskAbsentInvariant,
)
from assurance.invariant_registry import (
    UnknownInvariantError,
    build_invariant,
    registered_invariant_names,
)


def test_build_known_invariant_returns_correct_type():
    inv = build_invariant("AccountDisabledInvariant", {"account": "user123"})
    assert isinstance(inv, AccountDisabledInvariant)
    assert inv.account == "user123"


def test_build_invariant_is_actually_usable():
    # Prove the built invariant isn't just the right type — it must work
    # exactly like one constructed directly.
    inv = build_invariant(
        "ScheduledTaskAbsentInvariant", {"host": "WIN-01", "task_name": "EvilTask"}
    )
    evidence = MockEvidenceProvider()
    evidence.set_scheduled_tasks("WIN-01", ["WindowsUpdate"])  # EvilTask absent
    result = inv.check(evidence)
    assert result.status.value == "PASS"


def test_unknown_invariant_name_raises():
    with pytest.raises(UnknownInvariantError, match="No invariant registered"):
        build_invariant("TotallyMadeUpInvariant", {})


def test_missing_required_param_raises_keyerror():
    with pytest.raises(KeyError):
        build_invariant("ScheduledTaskAbsentInvariant", {"host": "WIN-01"})  # missing task_name


def test_registered_invariant_names_is_sorted_and_nonempty():
    names = registered_invariant_names()
    assert names == sorted(names)
    assert "AccountDisabledInvariant" in names
