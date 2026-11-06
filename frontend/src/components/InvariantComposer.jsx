import { useState } from 'react';
import { api } from '../lib/api.js';
import { RULE_TYPES, ruleSummary } from '../lib/invariant.js';
import { Badge, Field, Icon, Modal } from './ui.jsx';

const EMPTY_RULE = {
  rule_type: '',
  event: '',
  from_state: '',
  to_state: '',
  requires_event: '',
};

function Choice({ value, onChange, options, placeholder }) {
  if (!options.length) {
    return (
      <input
        className="input mono"
        value={value}
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
      />
    );
  }
  return (
    <select className="select" value={value} onChange={(event) => onChange(event.target.value)}>
      <option value="">{placeholder}</option>
      {options.map((option) => (
        <option key={option} value={option}>
          {option}
        </option>
      ))}
    </select>
  );
}

export default function InvariantComposer({ targetId, model, onClose, onSaved }) {
  const [statement, setStatement] = useState('');
  const [name, setName] = useState('');
  const [severity, setSeverity] = useState('high');
  const [rule, setRule] = useState(EMPTY_RULE);
  const [interpretation, setInterpretation] = useState(null);
  const [interpreting, setInterpreting] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const states = (model.states || []).map((state) => state.name);
  const events = model.events || [];

  const update = (patch) => setRule((current) => ({ ...current, ...patch }));

  const interpret = async (event) => {
    event.preventDefault();
    if (!statement.trim()) {
      setError('Describe the rule in a sentence first.');
      return;
    }
    setInterpreting(true);
    setError(null);
    try {
      const result = await api(`/models/${targetId}/interpret`, {
        method: 'POST',
        body: { statement },
      });
      setInterpretation(result);
      setRule({
        rule_type: result.rule_type || '',
        event: result.event || '',
        from_state: result.from_state || '',
        to_state: result.to_state || '',
        requires_event: result.requires_event || '',
      });
      if (!name.trim()) setName(statement.trim().slice(0, 90));
    } catch (err) {
      setError(err.message);
    } finally {
      setInterpreting(false);
    }
  };

  const save = async (status) => {
    if (!rule.rule_type) {
      setError('Pick a rule type so the engine knows what to check.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api(`/models/${targetId}/invariants`, {
        method: 'POST',
        body: { name, statement, severity, status, ...rule },
      });
      await onSaved();
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  };

  return (
    <Modal
      title="New invariant"
      wide
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            type="button"
            className="btn"
            disabled={busy}
            onClick={() => save('draft')}
          >
            Save as draft
          </button>
          <button
            type="button"
            className="btn primary"
            disabled={busy}
            onClick={() => save('active')}
          >
            {busy ? 'Saving…' : 'Save & activate'}
          </button>
        </>
      }
    >
      <form className="stack" onSubmit={interpret}>
        <Field
          label="Rule in plain words"
          hint="The interpreter recognizes a small set of phrasings. Review the rule it derives before activating."
        >
          <textarea
            className="textarea"
            value={statement}
            placeholder="reset may only happen in AUTHENTICATED"
            onChange={(event) => setStatement(event.target.value)}
          />
        </Field>
        <div className="row spread">
          <button type="submit" className="btn" disabled={interpreting}>
            <Icon name="code" size={14} />
            {interpreting ? 'Interpreting…' : 'Interpret rule'}
          </button>
          {interpretation ? (
            <Badge tone={interpretation.confidence === 'parsed' ? 'ok' : 'medium'}>
              {interpretation.confidence === 'parsed' ? 'Interpreted' : 'Needs review'}
            </Badge>
          ) : null}
        </div>
      </form>

      {interpretation ? (
        <div className="interpret-box">
          <span className="label">Rule the engine will enforce</span>
          <span className="rule">{ruleSummary(rule)}</span>
          {interpretation.notes?.length ? (
            <ul className="tiny muted" style={{ margin: '2px 0 0', paddingLeft: 18 }}>
              {interpretation.notes.map((note) => (
                <li key={note}>{note}</li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}

      <div className="form-grid">
        <Field label="Name" className="span-2">
          <input
            className="input"
            value={name}
            placeholder="Reset only from an authenticated node"
            onChange={(event) => setName(event.target.value)}
          />
        </Field>
        <Field label="Rule type">
          <select
            className="select"
            value={rule.rule_type}
            onChange={(event) => update({ rule_type: event.target.value })}
          >
            <option value="">Choose a rule type…</option>
            {RULE_TYPES.map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Severity">
          <select
            className="select"
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
          >
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </Field>

        {rule.rule_type === 'at_most_once' ? (
          <Field label="Event" hint="Must exist in the state model." className="span-2">
            <Choice
              value={rule.event}
              onChange={(value) => update({ event: value })}
              options={events}
              placeholder="Choose an event…"
            />
          </Field>
        ) : null}

        {rule.rule_type === 'requires_state' ? (
          <>
            <Field label="Event">
              <Choice
                value={rule.event}
                onChange={(value) => update({ event: value })}
                options={events}
                placeholder="Choose an event…"
              />
            </Field>
            <Field label="Allowed source state">
              <Choice
                value={rule.from_state}
                onChange={(value) => update({ from_state: value })}
                options={states}
                placeholder="Choose a state…"
              />
            </Field>
          </>
        ) : null}

        {rule.rule_type === 'forbidden_transition' ? (
          <>
            <Field label="From state">
              <Choice
                value={rule.from_state}
                onChange={(value) => update({ from_state: value })}
                options={states}
                placeholder="Choose a state…"
              />
            </Field>
            <Field label="To state">
              <Choice
                value={rule.to_state}
                onChange={(value) => update({ to_state: value })}
                options={states}
                placeholder="Choose a state…"
              />
            </Field>
          </>
        ) : null}

        {rule.rule_type === 'requires_prior' ? (
          <>
            <Field label="Event">
              <Choice
                value={rule.event}
                onChange={(value) => update({ event: value })}
                options={events}
                placeholder="Choose an event…"
              />
            </Field>
            <Field label="Must be preceded by">
              <Choice
                value={rule.requires_event}
                onChange={(value) => update({ requires_event: value })}
                options={events}
                placeholder="Choose an event…"
              />
            </Field>
          </>
        ) : null}
      </div>

      {error ? <div className="error-banner">{error}</div> : null}
    </Modal>
  );
}
