import { useState } from 'react';
import { api } from '../lib/api.js';
import { STATE_KINDS, TRUST_LEVELS } from '../lib/invariant.js';
import { Icon, Modal } from './ui.jsx';

const BLANK_STATE = { name: '', kind: 'normal', trust: 'unknown', notes: '' };

export default function ModelEditor({ targetId, model, onClose, onSaved }) {
  const [states, setStates] = useState(() =>
    (model.states || []).map((state) => ({
      name: state.name,
      kind: state.kind,
      trust: state.trust,
      notes: state.notes,
    }))
  );
  const [transitions, setTransitions] = useState(() =>
    (model.transitions || []).map((transition) => ({
      event: transition.event,
      from_state: transition.from_state,
      to_state: transition.to_state,
      cross_boundary: transition.cross_boundary,
      notes: transition.notes,
    }))
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const names = states.map((state) => state.name).filter(Boolean);

  const patchState = (index, patch) =>
    setStates((current) =>
      current.map((state, position) => (position === index ? { ...state, ...patch } : state))
    );

  const patchTransition = (index, patch) =>
    setTransitions((current) =>
      current.map((transition, position) =>
        position === index ? { ...transition, ...patch } : transition
      )
    );

  const addTransition = () =>
    setTransitions((current) => [
      ...current,
      {
        event: '',
        from_state: names[0] || '',
        to_state: names[0] || '',
        cross_boundary: false,
        notes: '',
      },
    ]);

  const save = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api(`/models/${targetId}`, {
        method: 'PUT',
        body: { states, transitions },
      });
      await onSaved();
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  };

  return (
    <Modal
      title="State model"
      wide
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn ghost" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form="model-form" className="btn primary" disabled={busy}>
            {busy ? 'Saving…' : 'Save model'}
          </button>
        </>
      }
    >
      <form id="model-form" className="stack" onSubmit={save}>
        <div className="row spread">
          <span className="label">States</span>
          <button
            type="button"
            className="btn small"
            onClick={() => setStates((current) => [...current, { ...BLANK_STATE }])}
          >
            <Icon name="plus" size={12} />
            Add state
          </button>
        </div>
        <div className="editor-scroll">
          {states.map((state, index) => (
            <div className="editor-row" key={`state-${index}`}>
              <input
                className="input mono"
                value={state.name}
                placeholder="STATE_NAME"
                onChange={(event) => patchState(index, { name: event.target.value })}
              />
              <select
                className="select"
                value={state.kind}
                onChange={(event) => patchState(index, { kind: event.target.value })}
                aria-label="State kind"
              >
                {STATE_KINDS.map((kind) => (
                  <option key={kind} value={kind}>
                    {kind}
                  </option>
                ))}
              </select>
              <select
                className="select"
                value={state.trust}
                onChange={(event) => patchState(index, { trust: event.target.value })}
                aria-label="Trust level"
              >
                {TRUST_LEVELS.map((trust) => (
                  <option key={trust} value={trust}>
                    {trust}
                  </option>
                ))}
              </select>
              <button
                type="button"
                className="icon-btn"
                aria-label={`Remove ${state.name || 'state'}`}
                onClick={() =>
                  setStates((current) => current.filter((_, position) => position !== index))
                }
              >
                <Icon name="trash" size={13} />
              </button>
            </div>
          ))}
          {!states.length ? (
            <p className="tiny muted" style={{ margin: 0 }}>
              No states yet. Add the states the design claims to have.
            </p>
          ) : null}
        </div>

        <div className="divider" />

        <div className="row spread">
          <span className="label">Transitions</span>
          <button type="button" className="btn small" onClick={addTransition} disabled={!names.length}>
            <Icon name="plus" size={12} />
            Add transition
          </button>
        </div>
        <div className="editor-scroll">
          {transitions.map((transition, index) => (
            <div className="editor-row transition" key={`transition-${index}`}>
              <input
                className="input mono"
                value={transition.event}
                placeholder="event_name"
                onChange={(event) => patchTransition(index, { event: event.target.value })}
              />
              <select
                className="select"
                value={transition.from_state}
                onChange={(event) => patchTransition(index, { from_state: event.target.value })}
                aria-label="From state"
              >
                <option value="">from…</option>
                {names.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </select>
              <select
                className="select"
                value={transition.to_state}
                onChange={(event) => patchTransition(index, { to_state: event.target.value })}
                aria-label="To state"
              >
                <option value="">to…</option>
                {names.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </select>
              <label className="checkline" title="Crosses a trust boundary">
                <input
                  type="checkbox"
                  checked={transition.cross_boundary}
                  onChange={(event) =>
                    patchTransition(index, { cross_boundary: event.target.checked })
                  }
                />
                boundary
              </label>
              <button
                type="button"
                className="icon-btn"
                aria-label="Remove transition"
                onClick={() =>
                  setTransitions((current) => current.filter((_, position) => position !== index))
                }
              >
                <Icon name="trash" size={13} />
              </button>
            </div>
          ))}
          {!transitions.length ? (
            <p className="tiny muted" style={{ margin: 0 }}>
              No transitions yet. Declare the moves the design permits.
            </p>
          ) : null}
        </div>

        {error ? <div className="error-banner">{error}</div> : null}
      </form>
    </Modal>
  );
}
