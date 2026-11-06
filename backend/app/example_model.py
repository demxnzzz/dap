"""A worked state-model example so the invariant page can be explored immediately.

The model is a simplified node session lifecycle with two deliberate design
gaps: re-initialisation from RUNNING and a teardown that returns to
UNINITIALIZED from RUNNING. The engine is expected to reproduce both, and to
report PROVISIONED as unreachable.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from .models import AnalysisRun, Invariant, ModelState, ModelTransition, Repository

EXAMPLE_STATES = [
    {
        "name": "UNINITIALIZED",
        "kind": "initial",
        "trust": "untrusted",
        "notes": "No key material loaded yet.",
    },
    {
        "name": "AUTHENTICATED",
        "kind": "normal",
        "trust": "trusted",
        "notes": "Keys loaded and identity verified.",
    },
    {
        "name": "RUNNING",
        "kind": "normal",
        "trust": "trusted",
        "notes": "Serving work.",
    },
    {
        "name": "PROVISIONED",
        "kind": "normal",
        "trust": "unknown",
        "notes": "Appears in the design doc; no transition reaches it.",
    },
    {
        "name": "LOCKED",
        "kind": "terminal",
        "trust": "trusted",
        "notes": "Shut down after a lock event.",
    },
]

EXAMPLE_TRANSITIONS = [
    {
        "event": "initialize",
        "from_state": "UNINITIALIZED",
        "to_state": "AUTHENTICATED",
        "cross_boundary": True,
        "notes": "Key material generated once on first boot.",
    },
    {
        "event": "start",
        "from_state": "AUTHENTICATED",
        "to_state": "RUNNING",
        "cross_boundary": False,
        "notes": "Normal startup.",
    },
    {
        "event": "initialize",
        "from_state": "RUNNING",
        "to_state": "AUTHENTICATED",
        "cross_boundary": False,
        "notes": "Hot-reload path: re-keys without clearing the previous key state.",
    },
    {
        "event": "reset",
        "from_state": "RUNNING",
        "to_state": "UNINITIALIZED",
        "cross_boundary": True,
        "notes": "Teardown reachable while running.",
    },
    {
        "event": "lock",
        "from_state": "RUNNING",
        "to_state": "LOCKED",
        "cross_boundary": False,
        "notes": "Operator lock.",
    },
]

EXAMPLE_INVARIANTS = [
    {
        "name": "Key initialization happens once",
        "statement": "initialize may only happen once",
        "rule_type": "at_most_once",
        "event": "initialize",
        "severity": "critical",
        "notes": "Re-keying must be an explicit rotate step, not a second initialize.",
    },
    {
        "name": "A running node never returns to uninitialized",
        "statement": "RUNNING must never transition to UNINITIALIZED",
        "rule_type": "forbidden_transition",
        "from_state": "RUNNING",
        "to_state": "UNINITIALIZED",
        "severity": "critical",
        "notes": "Teardown from RUNNING leaves loaded keys behind.",
    },
    {
        "name": "Reset only from an authenticated node",
        "statement": "reset may only happen in AUTHENTICATED",
        "rule_type": "requires_state",
        "event": "reset",
        "from_state": "AUTHENTICATED",
        "severity": "high",
        "notes": "The teardown path is reachable from RUNNING.",
    },
    {
        "name": "Start requires key initialization",
        "statement": "start requires initialize first",
        "rule_type": "requires_prior",
        "event": "start",
        "requires_event": "initialize",
        "severity": "high",
        "notes": "Checked as an ordering invariant over the whole trace.",
    },
]


def has_model(db: Session, repository_id: int) -> bool:
    return (
        db.query(ModelState.id)
        .filter(ModelState.repository_id == repository_id)
        .first()
        is not None
    )


def apply_example(db: Session, repository: Repository) -> None:
    """Install the example model. Only called when the target has no model yet."""
    if has_model(db, repository.id):
        return

    for state in EXAMPLE_STATES:
        db.add(ModelState(repository_id=repository.id, **state))
    for transition in EXAMPLE_TRANSITIONS:
        db.add(ModelTransition(repository_id=repository.id, **transition))
    for invariant in EXAMPLE_INVARIANTS:
        db.add(
            Invariant(
                repository_id=repository.id,
                name=invariant["name"],
                statement=invariant["statement"],
                rule_type=invariant["rule_type"],
                event=invariant.get("event", ""),
                from_state=invariant.get("from_state", ""),
                to_state=invariant.get("to_state", ""),
                requires_event=invariant.get("requires_event", ""),
                severity=invariant["severity"],
                status="active",
                notes=invariant.get("notes", ""),
            )
        )
    db.flush()
