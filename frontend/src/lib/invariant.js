export const RULE_TYPES = [
  ['at_most_once', 'Event happens at most once'],
  ['requires_state', 'Event only fires from one state'],
  ['forbidden_transition', 'A transition must never happen'],
  ['requires_prior', 'Event requires an earlier event'],
];

export const RULE_LABEL = Object.fromEntries(RULE_TYPES);

export const OUTCOMES = {
  violation: { tone: 'critical', label: 'Violation reproduced' },
  held: { tone: 'ok', label: 'No violation in bounds' },
  inconclusive: { tone: 'medium', label: 'Inconclusive' },
};

export const INVARIANT_STATUSES = ['draft', 'active', 'retired'];

export const STATUS_LABEL = { draft: 'Draft', active: 'Active', retired: 'Retired' };

export const STATE_KINDS = ['initial', 'normal', 'terminal'];

export const TRUST_LEVELS = ['trusted', 'untrusted', 'unknown'];

export const GAP_LABEL = {
  no_initial_state: 'No initial state',
  unreachable_state: 'Unreachable state',
  terminal_with_outgoing: 'Terminal state has exits',
  dead_end_state: 'Dead end',
  unclassified_trust: 'Trust unclassified',
  unmarked_boundary: 'Boundary not marked',
  dangling_rule: 'Rule cannot resolve',
};

/** Plain-language echo of the fields that will actually be enforced. */
export function ruleSummary(rule) {
  const event = rule.event || '?';
  if (rule.rule_type === 'at_most_once') return `${event} happens at most once on a trace.`;
  if (rule.rule_type === 'requires_state')
    return `${event} may only fire from ${rule.from_state || '?'}.`;
  if (rule.rule_type === 'forbidden_transition')
    return `${rule.from_state || '?'} must never transition to ${rule.to_state || '?'}.`;
  if (rule.rule_type === 'requires_prior')
    return `${event} requires an earlier ${rule.requires_event || '?'} on the same trace.`;
  return 'No rule selected yet.';
}
