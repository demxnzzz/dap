from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import invariants as engine
from ..db import get_db
from ..example_model import apply_example, has_model
from ..models import (
    AnalysisRun,
    Finding,
    Invariant,
    ModelState,
    ModelTransition,
    Repository,
)
from ..serializers import (
    finding_out,
    invariant_out,
    run_out,
    state_out,
    transition_out,
)

router = APIRouter(prefix="/api", tags=["invariants"])

STATE_KINDS = {"initial", "normal", "terminal"}
TRUST_LEVELS = {"trusted", "untrusted", "unknown"}
INVARIANT_STATUSES = {"draft", "active", "retired"}
SEVERITIES = {"critical", "high", "medium", "low"}


class StateIn(BaseModel):
    name: str
    kind: str = "normal"
    trust: str = "unknown"
    notes: str = ""


class TransitionIn(BaseModel):
    event: str
    from_state: str
    to_state: str
    cross_boundary: bool = False
    notes: str = ""


class ModelIn(BaseModel):
    states: list[StateIn] = []
    transitions: list[TransitionIn] = []


class InterpretIn(BaseModel):
    statement: str = ""


class InvariantIn(BaseModel):
    name: str = ""
    statement: str = ""
    rule_type: str = ""
    event: str = ""
    from_state: str = ""
    to_state: str = ""
    requires_event: str = ""
    severity: str = "medium"
    status: str = "draft"
    notes: str = ""


class InvariantPatch(BaseModel):
    name: str | None = None
    statement: str | None = None
    rule_type: str | None = None
    event: str | None = None
    from_state: str | None = None
    to_state: str | None = None
    requires_event: str | None = None
    severity: str | None = None
    status: str | None = None
    notes: str | None = None


class AnalyzeIn(BaseModel):
    invariant_id: int | None = None
    depth: int = 8


def _repo(db: Session, repo_id: int) -> Repository:
    repository = db.get(Repository, repo_id)
    if not repository:
        raise HTTPException(404, "Target not found")
    return repository


def _rule(invariant: Invariant) -> dict:
    return {
        "rule_type": invariant.rule_type,
        "event": invariant.event,
        "from_state": invariant.from_state,
        "to_state": invariant.to_state,
        "requires_event": invariant.requires_event,
    }


def _invariant_dict(invariant: Invariant) -> dict:
    data = invariant_out(invariant)
    data.update(_rule(invariant))
    data["formal"] = engine.formal_rule(_rule(invariant))
    return data


def _model(db: Session, repository: Repository) -> dict:
    states = (
        db.query(ModelState)
        .filter(ModelState.repository_id == repository.id)
        .order_by(ModelState.id)
        .all()
    )
    transitions = (
        db.query(ModelTransition)
        .filter(ModelTransition.repository_id == repository.id)
        .order_by(ModelTransition.id)
        .all()
    )
    invariants = (
        db.query(Invariant)
        .filter(Invariant.repository_id == repository.id)
        .order_by(Invariant.id)
        .all()
    )
    runs = (
        db.query(AnalysisRun)
        .filter(AnalysisRun.repository_id == repository.id)
        .order_by(AnalysisRun.created_at.desc(), AnalysisRun.id.desc())
        .all()
    )

    latest: dict[int, AnalysisRun] = {}
    for run in runs:
        if run.invariant_id is not None and run.invariant_id not in latest:
            latest[run.invariant_id] = run

    invariant_items = []
    for invariant in invariants:
        data = _invariant_dict(invariant)
        last = latest.get(invariant.id)
        data["last_run"] = run_out(last) if last else None
        invariant_items.append(data)

    state_items = [state_out(state) for state in states]
    transition_items = [transition_out(transition) for transition in transitions]
    gaps = engine.coverage_gaps(state_items, transition_items, invariant_items)

    active = [item for item in invariant_items if item["status"] == "active"]
    outcomes = [item["last_run"]["outcome"] for item in invariant_items if item["last_run"]]

    return {
        "repository_id": repository.id,
        "repository_name": repository.name,
        "states": state_items,
        "transitions": transition_items,
        "invariants": invariant_items,
        "gaps": gaps,
        "events": sorted({transition["event"] for transition in transition_items}),
        "summary": {
            "states": len(state_items),
            "transitions": len(transition_items),
            "invariants": len(invariant_items),
            "active_invariants": len(active),
            "violations": sum(1 for outcome in outcomes if outcome == "violation"),
            "inconclusive": sum(1 for outcome in outcomes if outcome == "inconclusive"),
            "last_run_at": max((run.created_at for run in runs), default=None),
            "gaps": len(gaps),
        },
    }


@router.get("/models/{repo_id}")
def get_model(repo_id: int, db: Session = Depends(get_db)):
    repository = _repo(db, repo_id)
    return _model(db, repository)


@router.put("/models/{repo_id}")
def save_model(repo_id: int, payload: ModelIn, db: Session = Depends(get_db)):
    repository = _repo(db, repo_id)

    cleaned: list[dict] = []
    seen: set[str] = set()
    for state in payload.states:
        name = state.name.strip()
        if not name:
            raise HTTPException(422, "Every state needs a name")
        if name.lower() in seen:
            raise HTTPException(422, f"State '{name}' is declared twice")
        seen.add(name.lower())
        if state.kind not in STATE_KINDS:
            raise HTTPException(422, f"Unknown state kind '{state.kind}'")
        if state.trust not in TRUST_LEVELS:
            raise HTTPException(422, f"Unknown trust level '{state.trust}'")
        cleaned.append(
            {
                "name": name,
                "kind": state.kind,
                "trust": state.trust,
                "notes": state.notes.strip(),
            }
        )

    transitions: list[dict] = []
    names = {state["name"].lower(): state["name"] for state in cleaned}
    for transition in payload.transitions:
        event = transition.event.strip()
        if not event:
            raise HTTPException(422, "Every transition needs an event name")
        if transition.from_state.lower() not in names:
            raise HTTPException(422, f"Transition '{event}' starts from an undeclared state")
        if transition.to_state.lower() not in names:
            raise HTTPException(422, f"Transition '{event}' ends in an undeclared state")
        transitions.append(
            {
                "event": event,
                "from_state": names[transition.from_state.lower()],
                "to_state": names[transition.to_state.lower()],
                "cross_boundary": transition.cross_boundary,
                "notes": transition.notes.strip(),
            }
        )

    db.query(ModelTransition).filter(
        ModelTransition.repository_id == repository.id
    ).delete()
    db.query(ModelState).filter(ModelState.repository_id == repository.id).delete()
    db.flush()

    for state in cleaned:
        db.add(ModelState(repository_id=repository.id, **state))
    for transition in transitions:
        db.add(ModelTransition(repository_id=repository.id, **transition))
    db.commit()
    return _model(db, repository)


@router.post("/models/{repo_id}/example")
def load_example(repo_id: int, db: Session = Depends(get_db)):
    repository = _repo(db, repo_id)
    created = not has_model(db, repository.id)
    apply_example(db, repository)
    db.commit()
    return {"created": created, "model": _model(db, repository)}


@router.post("/models/{repo_id}/interpret")
def interpret_statement(
    repo_id: int, payload: InterpretIn, db: Session = Depends(get_db)
):
    repository = _repo(db, repo_id)
    states = [
        state.name
        for state in db.query(ModelState).filter(
            ModelState.repository_id == repository.id
        )
    ]
    events = [
        row[0]
        for row in db.query(ModelTransition.event)
        .filter(ModelTransition.repository_id == repository.id)
        .distinct()
    ]
    return engine.interpret(payload.statement, states, events)


@router.post("/models/{repo_id}/invariants", status_code=201)
def create_invariant(
    repo_id: int, payload: InvariantIn, db: Session = Depends(get_db)
):
    repository = _repo(db, repo_id)
    if payload.rule_type not in engine.RULE_TYPES:
        raise HTTPException(422, "Pick a supported rule type before saving")
    if payload.status not in INVARIANT_STATUSES:
        raise HTTPException(422, "Unknown invariant status")
    if payload.severity not in SEVERITIES:
        raise HTTPException(422, "Unknown severity")
    statement = payload.statement.strip()
    name = payload.name.strip() or (statement[:90] if statement else "Untitled invariant")

    invariant = Invariant(
        repository_id=repository.id,
        name=name,
        statement=statement,
        rule_type=payload.rule_type,
        event=payload.event.strip(),
        from_state=payload.from_state.strip(),
        to_state=payload.to_state.strip(),
        requires_event=payload.requires_event.strip(),
        severity=payload.severity,
        status=payload.status,
        notes=payload.notes.strip(),
    )
    db.add(invariant)
    db.commit()
    db.refresh(invariant)
    return _invariant_dict(invariant)


@router.patch("/invariants/{invariant_id}")
def update_invariant(
    invariant_id: int, payload: InvariantPatch, db: Session = Depends(get_db)
):
    invariant = db.get(Invariant, invariant_id)
    if not invariant:
        raise HTTPException(404, "Invariant not found")
    changes = payload.model_dump(exclude_unset=True)
    if "status" in changes and changes["status"] not in INVARIANT_STATUSES:
        raise HTTPException(422, "Unknown invariant status")
    if "severity" in changes and changes["severity"] not in SEVERITIES:
        raise HTTPException(422, "Unknown severity")
    if "rule_type" in changes and changes["rule_type"] not in engine.RULE_TYPES:
        raise HTTPException(422, "Pick a supported rule type")
    for field, value in changes.items():
        setattr(invariant, field, value.strip() if isinstance(value, str) else value)
    db.commit()
    db.refresh(invariant)
    return _invariant_dict(invariant)


@router.delete("/invariants/{invariant_id}", status_code=204)
def delete_invariant(invariant_id: int, db: Session = Depends(get_db)):
    invariant = db.get(Invariant, invariant_id)
    if not invariant:
        raise HTTPException(404, "Invariant not found")
    db.delete(invariant)
    db.commit()
    return None


@router.post("/models/{repo_id}/analyze")
def analyze_model(repo_id: int, payload: AnalyzeIn, db: Session = Depends(get_db)):
    repository = _repo(db, repo_id)
    model = _model(db, repository)
    depth = max(1, min(int(payload.depth or 8), 16))

    invariants = [item for item in model["invariants"] if item["status"] == "active"]
    if payload.invariant_id is not None:
        invariants = [
            item for item in model["invariants"] if item["id"] == payload.invariant_id
        ]
        if not invariants:
            raise HTTPException(404, "Invariant not found for this target")
    if not invariants:
        raise HTTPException(422, "No active invariants to analyze. Activate a rule first.")

    result = engine.analyze(
        model["states"], model["transitions"], invariants, depth
    )

    runs = []
    for entry in result["runs"]:
        run = AnalysisRun(
            repository_id=repository.id,
            invariant_id=entry["invariant_id"],
            depth=entry["depth"],
            outcome=entry["outcome"],
            reason=entry["reason"],
            trace=entry["trace"],
            traces_explored=entry["traces_explored"],
        )
        db.add(run)
        runs.append((entry, run))
    db.commit()

    created = []
    for entry, run in runs:
        db.refresh(run)
        data = run_out(run)
        data["reason"] = entry["reason"]
        created.append(data)

    return {
        "runs": created,
        "gaps": result["gaps"],
        "depth": depth,
        "summary": {
            "violations": sum(1 for run in created if run["outcome"] == "violation"),
            "held": sum(1 for run in created if run["outcome"] == "held"),
            "inconclusive": sum(1 for run in created if run["outcome"] == "inconclusive"),
        },
        "model": _model(db, repository),
    }


@router.post("/invariants/{invariant_id}/promote")
def promote_invariant(invariant_id: int, db: Session = Depends(get_db)):
    invariant = db.get(Invariant, invariant_id)
    if not invariant:
        raise HTTPException(404, "Invariant not found")

    run = (
        db.query(AnalysisRun)
        .filter(
            AnalysisRun.invariant_id == invariant.id,
            AnalysisRun.outcome == "violation",
        )
        .order_by(AnalysisRun.created_at.desc(), AnalysisRun.id.desc())
        .first()
    )
    if not run:
        raise HTTPException(
            422, "Run the analysis first — no reproduced violation to promote."
        )

    trace_lines = []
    for step in run.trace or []:
        if step.get("event"):
            trace_lines.append(
                f"{step['step']}. {step['event']}: {step['from_state']} → {step['to_state']}"
                + ("  [boundary crossing]" if step.get("cross_boundary") else "")
                + ("  ← invariant broken here" if step.get("violates") else "")
            )

    description = (
        f"Invariant: {invariant.statement or invariant.name}\n"
        f"Formal rule: {engine.formal_rule(_rule(invariant))}\n"
        f"Search bound: {run.depth} steps, {run.traces_explored} trace prefixes explored\n\n"
        f"Why it fails: {run.reason}\n\n"
        f"Reproduced trace:\n" + ("\n".join(trace_lines) or "(no trace recorded)")
    )

    finding = Finding(
        repository_id=invariant.repository_id,
        title=f"{invariant.name} (invariant violation)",
        description=description,
        source="invariant",
        rule_id=f"invariant:{invariant.id}",
        severity=invariant.severity,
        status="new",
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return {"finding": finding_out(finding)}
