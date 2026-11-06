"""Invariant and state-model analysis.

Everything here is deterministic: a small phrase parser turns plain English into
one of four rule shapes, and a bounded breadth-first search over the declared
transition graph looks for a trace that breaks the rule. The parser always
returns the formal rule it derived so an analyst can review or correct it —
an interpretation is never treated as authoritative on its own.

Outcomes are deliberately explicit:

* ``violation``     — a concrete trace reproduces the breach.
* ``held``          — no violating trace inside the declared model and depth.
* ``inconclusive``  — the model cannot answer the question (missing state,
                      missing event, no initial state, or a truncated search).

"No violation found" is never reported as "secure".
"""

from __future__ import annotations

import re
from collections import deque

MAX_PATHS = 20000

RULE_TYPES = {
    "at_most_once": "Event occurs at most once on a trace",
    "requires_state": "Event may only fire from one state",
    "forbidden_transition": "A state-to-state move must never happen",
    "requires_prior": "Event requires an earlier event on the same trace",
}

OUTCOME_LABEL = {
    "violation": "Violation reproduced",
    "held": "No violation in bounds",
    "inconclusive": "Inconclusive",
}

MODAL_SPLIT = re.compile(
    r"\b(can|may|must|should|will|shall|is|are|only|happens?|occurs?|allowed)\b",
    re.IGNORECASE,
)

ONCE_PHRASES = re.compile(
    r"\b(only|at most|exactly)\b(?:\s+\w+){0,4}\s+once\b"
    r"|\b(a single time|once only|single initialization|happens once|occurs once)\b",
    re.IGNORECASE,
)
NEVER_PHRASES = re.compile(
    r"\b(never|must not|must never|should never|is forbidden|are forbidden|forbidden)\b",
    re.IGNORECASE,
)

ARTICLE = re.compile(r"^(the|a|an|any|each|every|one)\s+", re.IGNORECASE)


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip())


def _hits(lowered: str, terms: list[str]) -> list[str]:
    """Terms mentioned in the statement, matched as whole words."""
    found = []
    for term in terms:
        if not term:
            continue
        pattern = r"(?<![a-z0-9_])" + re.escape(term.lower()) + r"(?![a-z0-9_])"
        if re.search(pattern, lowered):
            found.append(term)
    return found


def _leading_subject(text: str, states: list[str], events: list[str]) -> str:
    """Best-effort event name when the statement names something not in the model."""
    cut = MODAL_SPLIT.split(text, maxsplit=1)[0]
    subject = _norm(cut).strip(" .,:;")
    subject = ARTICLE.sub("", subject).strip()
    if not subject:
        return ""
    candidate = subject.lower().replace(" ", "_").replace("-", "_")
    known = {name.lower(): name for name in states + events}
    return known.get(candidate, candidate)


def formal_rule(rule: dict) -> str:
    kind = rule.get("rule_type")
    event = rule.get("event") or "?"
    if kind == "at_most_once":
        return f"count({event}) ≤ 1 per trace"
    if kind == "requires_state":
        return f"∀ {event}: from_state = {rule.get('from_state') or '?'}"
    if kind == "forbidden_transition":
        return f"¬({rule.get('from_state') or '?'} → {rule.get('to_state') or '?'})"
    if kind == "requires_prior":
        return f"∀ {event}: ∃ earlier {rule.get('requires_event') or '?'}"
    return "unformalized"


def _review(rule: dict, states: list[str], events: list[str]) -> tuple[str, list[str]]:
    """Flag references the declared model cannot resolve yet."""
    notes: list[str] = []
    kind = rule.get("rule_type")
    state_set = {name.lower() for name in states}
    event_set = {name.lower() for name in events}

    if not kind:
        notes.append("That wording did not map to a supported rule. Pick a rule type and fill the fields.")

    if kind in ("at_most_once", "requires_state", "requires_prior"):
        if not rule.get("event"):
            notes.append("No event was identified for this rule.")
        elif rule["event"].lower() not in event_set:
            notes.append(f"Event '{rule['event']}' is not in the model yet.")

    if kind in ("requires_state", "forbidden_transition"):
        for field, label in (("from_state", "Source state"), ("to_state", "Target state")):
            value = rule.get(field)
            if kind == "requires_state" and field == "to_state":
                continue
            if not value:
                notes.append(f"{label} is missing.")
            elif value.lower() not in state_set:
                notes.append(f"{label} '{value}' is not declared in the model.")

    if kind == "requires_prior" and rule.get("requires_event"):
        if rule["requires_event"].lower() not in event_set:
            notes.append(f"Prior event '{rule['requires_event']}' is not in the model yet.")

    return ("parsed" if not notes else "needs_review"), notes


def interpret(statement: str, states: list[str], events: list[str]) -> dict:
    """Map a plain-English rule onto a supported rule shape.

    The returned ``formal`` string is the rule that would be enforced, and
    ``confidence`` is ``needs_review`` whenever a referenced state or event is
    not present in the model.
    """
    text = _norm(statement)
    lowered = text.lower()
    state_hits = _hits(lowered, states)
    event_hits = _hits(lowered, events)

    ordered_states = sorted(state_hits, key=lambda term: lowered.index(term.lower()))
    ordered_events = sorted(event_hits, key=lambda term: lowered.index(term.lower()))

    rule: dict = {
        "rule_type": "",
        "event": "",
        "from_state": "",
        "to_state": "",
        "requires_event": "",
    }

    if not text:
        rule["formal"] = formal_rule(rule)
        rule["confidence"] = "needs_review"
        rule["notes"] = ["Describe the rule in a sentence first."]
        return rule

    if ONCE_PHRASES.search(lowered):
        rule["rule_type"] = "at_most_once"
        rule["event"] = (
            ordered_events[0] if ordered_events else _leading_subject(text, states, events)
        )
    elif NEVER_PHRASES.search(lowered) and len(ordered_states) >= 2:
        rule["rule_type"] = "forbidden_transition"
        rule["from_state"] = ordered_states[0]
        rule["to_state"] = ordered_states[1]
    elif re.search(r"\bonly\b", lowered) and len(ordered_states) == 1:
        rule["rule_type"] = "requires_state"
        rule["event"] = (
            ordered_events[0] if ordered_events else _leading_subject(text, states, events)
        )
        rule["from_state"] = ordered_states[0]
    elif re.search(r"\b(requires?|after|before|preceded by)\b", lowered) and len(ordered_events) >= 2:
        rule["rule_type"] = "requires_prior"
        if re.search(r"\bbefore\b", lowered):
            rule["event"] = ordered_events[1]
            rule["requires_event"] = ordered_events[0]
        else:
            rule["event"] = ordered_events[0]
            rule["requires_event"] = ordered_events[1]

    confidence, notes = _review(rule, states, events)
    rule["formal"] = formal_rule(rule)
    rule["confidence"] = confidence
    rule["notes"] = notes
    return rule


def _undefined_references(rule: dict, states: list[str], events: list[str]) -> list[str]:
    kind = rule.get("rule_type")
    state_set = {name.lower() for name in states}
    event_set = {name.lower() for name in events}
    missing: list[str] = []

    if kind not in RULE_TYPES:
        return ["the rule has no supported rule type"]

    if kind in ("at_most_once", "requires_state", "requires_prior"):
        if not rule.get("event"):
            missing.append("no event is set")
        elif rule["event"].lower() not in event_set:
            missing.append(f"event '{rule['event']}' is not declared")

    if kind in ("requires_state", "forbidden_transition"):
        if not rule.get("from_state") or rule["from_state"].lower() not in state_set:
            missing.append(f"state '{rule.get('from_state')}' is not declared")
    if kind == "forbidden_transition":
        if not rule.get("to_state") or rule["to_state"].lower() not in state_set:
            missing.append(f"state '{rule.get('to_state')}' is not declared")

    if kind == "requires_prior":
        if not rule.get("requires_event"):
            missing.append("no prior event is set")
        elif rule["requires_event"].lower() not in event_set:
            missing.append(f"prior event '{rule['requires_event']}' is not declared")

    return missing


def _check(rule: dict, path: list[dict]) -> dict | None:
    """Look at the last step of a trace prefix for a rule breach."""
    kind = rule["rule_type"]
    last = path[-1]

    if kind == "at_most_once":
        if last["event"] == rule["event"]:
            seen = sum(1 for step in path if step["event"] == rule["event"])
            if seen > 1:
                return {
                    "step": len(path),
                    "detail": f"'{rule['event']}' occurs {seen} times on this trace.",
                }

    elif kind == "requires_state":
        if last["event"] == rule["event"] and last["from_state"] != rule["from_state"]:
            return {
                "step": len(path),
                "detail": (
                    f"'{rule['event']}' fired from {last['from_state']}, "
                    f"but the rule allows it only from {rule['from_state']}."
                ),
            }

    elif kind == "forbidden_transition":
        if last["from_state"] == rule["from_state"] and last["to_state"] == rule["to_state"]:
            return {
                "step": len(path),
                "detail": f"The transition {rule['from_state']} → {rule['to_state']} is declared forbidden.",
            }

    elif kind == "requires_prior":
        if last["event"] == rule["event"]:
            earlier = any(step["event"] == rule["requires_event"] for step in path[:-1])
            if not earlier:
                return {
                    "step": len(path),
                    "detail": (
                        f"'{rule['event']}' fired without an earlier "
                        f"'{rule['requires_event']}' on the same trace."
                    ),
                }

    return None


def _trace(steps: list[dict], violation: dict | None = None) -> list[dict]:
    base = steps[0]["from_state"] if steps else ""
    trace = [{"step": 0, "event": None, "from_state": None, "to_state": base}]
    for index, step in enumerate(steps, start=1):
        trace.append(
            {
                "step": index,
                "event": step["event"],
                "from_state": step["from_state"],
                "to_state": step["to_state"],
                "cross_boundary": step.get("cross_boundary", False),
                "violates": bool(violation and violation["step"] == index),
            }
        )
    return trace


def explore(
    rule: dict,
    states: list[dict],
    transitions: list[dict],
    depth: int,
) -> dict:
    """Breadth-first search for the shortest trace that breaks ``rule``."""
    initial = [state["name"] for state in states if state["kind"] == "initial"]
    if not initial:
        return {
            "outcome": "inconclusive",
            "reason": "The model has no initial state, so no trace can start.",
            "trace": [],
            "traces_explored": 0,
            "depth": depth,
        }

    missing = _undefined_references(rule, [s["name"] for s in states], list({t["event"] for t in transitions}))
    if missing:
        return {
            "outcome": "inconclusive",
            "reason": "Cannot evaluate: " + "; ".join(missing) + ".",
            "trace": [],
            "traces_explored": 0,
            "depth": depth,
        }

    outgoing: dict[str, list[dict]] = {}
    for transition in transitions:
        outgoing.setdefault(transition["from_state"], []).append(transition)

    queue: deque[tuple[str, list[dict]]] = deque((name, []) for name in initial)
    explored = 0
    truncated = False

    while queue:
        if truncated:
            break
        state, path = queue.popleft()
        if len(path) >= depth:
            continue
        for transition in outgoing.get(state, []):
            next_path = path + [transition]
            explored += 1
            if explored > MAX_PATHS:
                truncated = True
                break
            violation = _check(rule, next_path)
            if violation:
                return {
                    "outcome": "violation",
                    "reason": violation["detail"],
                    "trace": _trace(next_path, violation),
                    "violation_step": violation["step"],
                    "traces_explored": explored,
                    "depth": depth,
                }
            queue.append((transition["to_state"], next_path))

    if truncated:
        return {
            "outcome": "inconclusive",
            "reason": (
                f"The search hit its {MAX_PATHS}-path budget before depth {depth}. "
                "Reduce branching or lower the depth to get a verdict."
            ),
            "trace": [],
            "traces_explored": explored,
            "depth": depth,
        }

    return {
        "outcome": "held",
        "reason": (
            f"No violating trace exists within the declared model up to {depth} steps. "
            "This is not proof the system is secure — only that the model did not produce one."
        ),
        "trace": [],
        "traces_explored": explored,
        "depth": depth,
    }


def coverage_gaps(
    states: list[dict],
    transitions: list[dict],
    invariants: list[dict],
) -> list[dict]:
    """Model-level negative space: what the declared states never account for."""
    gaps: list[dict] = []
    names = {state["name"] for state in states}
    initial = [state["name"] for state in states if state["kind"] == "initial"]

    if not states:
        return gaps
    if not initial:
        gaps.append(
            {
                "kind": "no_initial_state",
                "severity": "high",
                "subject": "model",
                "detail": "No state is marked initial, so no execution trace can begin.",
            }
        )

    reachable: set[str] = set()
    if initial:
        frontier = list(initial)
        reachable.update(initial)
        while frontier:
            current = frontier.pop()
            for transition in transitions:
                if transition["from_state"] == current and transition["to_state"] not in reachable:
                    reachable.add(transition["to_state"])
                    frontier.append(transition["to_state"])

    outgoing: dict[str, int] = {}
    for transition in transitions:
        outgoing[transition["from_state"]] = outgoing.get(transition["from_state"], 0) + 1

    trust = {state["name"]: state.get("trust", "unknown") for state in states}

    for state in states:
        name = state["name"]
        if initial and name not in reachable:
            gaps.append(
                {
                    "kind": "unreachable_state",
                    "severity": "medium",
                    "subject": name,
                    "detail": "Declared as a valid state, but no transition path reaches it.",
                }
            )
        if state["kind"] == "terminal" and outgoing.get(name):
            gaps.append(
                {
                    "kind": "terminal_with_outgoing",
                    "severity": "medium",
                    "subject": name,
                    "detail": "Marked terminal yet transitions leave it — the design contradicts itself.",
                }
            )
        if state["kind"] != "terminal" and not outgoing.get(name):
            gaps.append(
                {
                    "kind": "dead_end_state",
                    "severity": "low",
                    "subject": name,
                    "detail": "No outgoing transition and not marked terminal, so the model stalls here.",
                }
            )
        if state.get("trust") == "unknown":
            gaps.append(
                {
                    "kind": "unclassified_trust",
                    "severity": "info",
                    "subject": name,
                    "detail": "Trust level is undeclared, so boundary crossings cannot be checked.",
                }
            )

    for transition in transitions:
        source, target = transition["from_state"], transition["to_state"]
        if source not in names or target not in names:
            continue
        edge_trust = {trust.get(source), trust.get(target)}
        if (
            edge_trust == {"trusted", "untrusted"}
            and not transition.get("cross_boundary")
        ):
            gaps.append(
                {
                    "kind": "unmarked_boundary",
                    "severity": "medium",
                    "subject": f"{source} → {target}",
                    "detail": (
                        f"'{transition['event']}' moves data between a trusted and an untrusted "
                        "state but is not marked as a boundary crossing."
                    ),
                }
            )

    event_names = {transition["event"] for transition in transitions}
    for invariant in invariants:
        if invariant.get("status") != "active":
            continue
        missing = _undefined_references(invariant, list(names), list(event_names))
        if missing:
            gaps.append(
                {
                    "kind": "dangling_rule",
                    "severity": "high",
                    "subject": invariant.get("name") or f"invariant {invariant.get('id')}",
                    "detail": "Active invariant cannot be evaluated: " + "; ".join(missing) + ".",
                }
            )

    return gaps


def analyze(
    states: list[dict],
    transitions: list[dict],
    invariants: list[dict],
    depth: int,
) -> dict:
    results = []
    for invariant in invariants:
        result = explore(invariant, states, transitions, depth)
        results.append({"invariant_id": invariant.get("id"), **result})
    return {"runs": results, "gaps": coverage_gaps(states, transitions, invariants)}
