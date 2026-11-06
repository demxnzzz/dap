import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api, useApi } from '../lib/api.js';
import { useWorkspace } from '../lib/workspace.jsx';
import { GAP_LABEL, INVARIANT_STATUSES, OUTCOMES, STATUS_LABEL } from '../lib/invariant.js';
import {
  Badge,
  EmptyState,
  ErrorBanner,
  Icon,
  Loading,
  Panel,
  SeverityBadge,
  Stat,
} from '../components/ui.jsx';
import InvariantComposer from '../components/InvariantComposer.jsx';
import ModelEditor from '../components/ModelEditor.jsx';

function Trace({ trace }) {
  if (!trace?.length) return null;
  return (
    <div className="trace">
      {trace.map((step) =>
        step.event ? (
          <span
            key={step.step}
            className={`trace-step${step.violates ? ' violates' : ''}`}
            title={step.cross_boundary ? 'Crosses a trust boundary' : undefined}
          >
            <span className="trace-event">{step.event}</span>
            <span className="trace-arrow">→</span>
            <span className="trace-state">{step.to_state}</span>
          </span>
        ) : (
          <span key={step.step} className="trace-state">
            {step.to_state}
          </span>
        )
      )}
    </div>
  );
}

export default function Invariants() {
  const { repos, repoId, setRepoId } = useWorkspace();
  const [composerOpen, setComposerOpen] = useState(false);
  const [editorOpen, setEditorOpen] = useState(false);
  const [running, setRunning] = useState(null);
  const [runSummary, setRunSummary] = useState(null);
  const [notice, setNotice] = useState(null);
  const [error, setError] = useState(null);

  const targetId = repoId;
  const list = useApi(targetId ? `/models/${targetId}` : null, [targetId]);
  const model = list.data;

  const runAnalysis = async (invariantId = null) => {
    setRunning(invariantId || 'all');
    setError(null);
    setNotice(null);
    try {
      const result = await api(`/models/${targetId}/analyze`, {
        method: 'POST',
        body: { invariant_id: invariantId, depth: 8 },
      });
      setRunSummary(result);
      list.reload();
    } catch (err) {
      setError(err.message);
    } finally {
      setRunning(null);
    }
  };

  const loadExample = async () => {
    setError(null);
    try {
      const result = await api(`/models/${targetId}/example`, { method: 'POST' });
      setNotice(
        result.created
          ? 'Example model installed. Run the analysis to reproduce its violations.'
          : 'This target already had a model, so nothing was added.'
      );
      list.reload();
    } catch (err) {
      setError(err.message);
    }
  };

  const promote = async (invariant) => {
    setError(null);
    try {
      const result = await api(`/invariants/${invariant.id}/promote`, { method: 'POST' });
      setNotice({
        text: `Finding #${result.finding.id} created from the reproduced trace.`,
        findingId: result.finding.id,
      });
      list.reload();
    } catch (err) {
      setError(err.message);
    }
  };

  const setStatus = async (invariant, status) => {
    try {
      await api(`/invariants/${invariant.id}`, { method: 'PATCH', body: { status } });
      list.reload();
    } catch (err) {
      setError(err.message);
    }
  };

  const remove = async (invariant) => {
    if (!window.confirm(`Delete "${invariant.name}" and its analysis history?`)) return;
    try {
      await api(`/invariants/${invariant.id}`, { method: 'DELETE' });
      list.reload();
    } catch (err) {
      setError(err.message);
    }
  };

  const closeModals = () => {
    setComposerOpen(false);
    setEditorOpen(false);
  };

  const saved = async () => {
    closeModals();
    list.reload();
  };

  const summary = model?.summary;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Invariants</h1>
          <p className="page-sub">
            Declare the states and transitions the design claims to have, then state the rules
            that must always hold. Analysis searches every declared trace up to a fixed depth and
            reports a reproduced trace, a bounded “not found”, or an honest inconclusive.
          </p>
        </div>
        <div className="page-actions">
          <button
            type="button"
            className="btn"
            onClick={() => setEditorOpen(true)}
            disabled={!model || !model.states.length}
          >
            <Icon name="code" size={14} />
            Edit model
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => setComposerOpen(true)}
            disabled={!model || !model.states.length}
          >
            <Icon name="plus" size={14} />
            New invariant
          </button>
          <button
            type="button"
            className="btn primary"
            onClick={() => runAnalysis()}
            disabled={!summary?.active_invariants || Boolean(running)}
          >
            <Icon name="play" size={13} />
            {running === 'all' ? 'Analyzing…' : 'Run analysis'}
          </button>
        </div>
      </div>

      {notice ? (
        <div className="success-banner" style={{ marginBottom: 14 }}>
          {typeof notice === 'string' ? notice : notice.text}{' '}
          {typeof notice === 'object' ? <Link to="/findings">Review in Findings →</Link> : null}
        </div>
      ) : null}
      {error ? (
        <div className="error-banner" style={{ marginBottom: 14 }}>
          {error}
        </div>
      ) : null}

      {!repos.length ? (
        <div className="panel">
          <EmptyState
            icon="target"
            title="Add a target first"
            description="Invariant analysis runs against a target's declared state model."
            actions={
              <Link className="btn primary" to="/targets">
                Go to targets
              </Link>
            }
          />
        </div>
      ) : !targetId ? (
        <div className="panel">
          <EmptyState
            icon="target"
            title="Choose a target"
            description="Each target carries its own state model, invariant set and analysis history."
            actions={
              <>
                {repos.map((repo) => (
                  <button
                    key={repo.id}
                    type="button"
                    className="btn"
                    onClick={() => setRepoId(String(repo.id))}
                  >
                    {repo.name}
                  </button>
                ))}
              </>
            }
          />
        </div>
      ) : list.error ? (
        <ErrorBanner onRetry={list.reload}>{list.error}</ErrorBanner>
      ) : list.loading && !model ? (
        <Loading label="Loading state model…" />
      ) : !model?.states.length ? (
        <div className="panel">
          <EmptyState
            icon="shield"
            title="No state model yet"
            description="Describe the states and transitions first. The engine can only reason about behaviour the model actually declares — anything it never mentions stays invisible."
            actions={
              <>
                <button type="button" className="btn primary" onClick={loadExample}>
                  Load the example model
                </button>
                <button type="button" className="btn" onClick={() => setEditorOpen(true)}>
                  Define states
                </button>
              </>
            }
          />
        </div>
      ) : (
        <>
          <div className="stat-grid">
            <Stat label="States" value={summary.states} foot={`${summary.transitions} transitions`} />
            <Stat
              label="Active invariants"
              value={summary.active_invariants}
              foot={`${summary.invariants} defined`}
            />
            <Stat
              label="Reproduced"
              value={summary.violations}
              foot="violations on record"
            />
            <Stat label="Model gaps" value={summary.gaps} foot="unmodeled or contradictory" />
          </div>

          {runSummary ? (
            <div className="card" style={{ marginBottom: 14 }}>
              <div className="row spread">
                <div className="row" style={{ gap: 8 }}>
                  <Badge tone={runSummary.summary.violations ? 'critical' : 'ok'}>
                    {runSummary.summary.violations
                      ? `${runSummary.summary.violations} reproduced`
                      : 'No violation in bounds'}
                  </Badge>
                  <span className="tiny muted">
                    This run: {runSummary.summary.held} held ·{' '}
                    {runSummary.summary.inconclusive} inconclusive · every declared trace up to{' '}
                    {runSummary.depth} steps
                  </span>
                </div>
                <button
                  type="button"
                  className="icon-btn"
                  aria-label="Dismiss summary"
                  onClick={() => setRunSummary(null)}
                >
                  <Icon name="close" size={14} />
                </button>
              </div>
            </div>
          ) : null}

          <div className="grid-2">
            <Panel title="Invariants" bodyClass="list">
              {model.invariants.map((invariant) => {
                const outcome = invariant.last_run
                  ? OUTCOMES[invariant.last_run.outcome]
                  : null;
                return (
                  <article className="invariant-row" key={invariant.id}>
                    <span className={`severity-rail ${invariant.severity}`} />
                    <div className="finding-main">
                      <div className="row" style={{ gap: 8 }}>
                        <span className="finding-title">{invariant.name}</span>
                        <SeverityBadge value={invariant.severity} />
                        <Badge tone={invariant.status === 'active' ? 'info' : 'neutral'}>
                          {STATUS_LABEL[invariant.status] || invariant.status}
                        </Badge>
                        {outcome ? (
                          <Badge tone={outcome.tone}>{outcome.label}</Badge>
                        ) : (
                          <Badge tone="neutral">Not run</Badge>
                        )}
                      </div>
                      <span className="rule">{invariant.formal}</span>
                      {invariant.statement && invariant.statement !== invariant.formal ? (
                        <p className="tiny muted" style={{ margin: 0 }}>
                          “{invariant.statement}”
                        </p>
                      ) : null}
                      <Trace trace={invariant.last_run?.trace} />
                      {invariant.last_run ? (
                        <p className="tiny muted" style={{ margin: 0 }}>
                          {invariant.last_run.reason}
                        </p>
                      ) : null}
                    </div>
                    <div className="finding-actions">
                      <button
                        type="button"
                        className="btn small"
                        onClick={() => runAnalysis(invariant.id)}
                        disabled={Boolean(running) || invariant.status !== 'active'}
                      >
                        <Icon name="play" size={11} />
                        {running === invariant.id ? 'Running…' : 'Run'}
                      </button>
                      {invariant.last_run?.outcome === 'violation' ? (
                        <button
                          type="button"
                          className="btn small"
                          onClick={() => promote(invariant)}
                        >
                          Promote
                        </button>
                      ) : null}
                      <select
                        className="status-select"
                        value={invariant.status}
                        onChange={(event) => setStatus(invariant, event.target.value)}
                        aria-label={`Status for ${invariant.name}`}
                      >
                        {INVARIANT_STATUSES.map((status) => (
                          <option key={status} value={status}>
                            {STATUS_LABEL[status]}
                          </option>
                        ))}
                      </select>
                      <button
                        type="button"
                        className="icon-btn"
                        aria-label={`Delete ${invariant.name}`}
                        onClick={() => remove(invariant)}
                      >
                        <Icon name="trash" size={14} />
                      </button>
                    </div>
                  </article>
                );
              })}
              {!model.invariants.length ? (
                <EmptyState
                  icon="shield"
                  title="No invariants yet"
                  description="State a rule in plain words. The interpreter shows the rule it derived so you can correct it before activating."
                  actions={
                    <button
                      type="button"
                      className="btn primary"
                      onClick={() => setComposerOpen(true)}
                    >
                      New invariant
                    </button>
                  }
                />
              ) : null}
            </Panel>

            <div className="stack">
              <Panel
                title="State model"
                action={
                  <button type="button" className="btn small" onClick={() => setEditorOpen(true)}>
                    Edit
                  </button>
                }
              >
                <div className="state-flow">
                  {model.states.map((state) => (
                    <div
                      className={`state-chip ${state.kind}`}
                      key={state.id}
                      title={state.notes || undefined}
                    >
                      <span className="state-name">{state.name}</span>
                      <span className="state-meta">
                        {state.kind} · {state.trust}
                      </span>
                    </div>
                  ))}
                </div>
                <div className="transition-list">
                  {model.transitions.map((transition) => (
                    <div className="transition-row" key={transition.id}>
                      <span className="ev">{transition.event}</span>
                      <span className="st">{transition.from_state}</span>
                      <span className="trace-arrow">→</span>
                      <span className="st">{transition.to_state}</span>
                      {transition.cross_boundary ? (
                        <span className="transition-flag">boundary</span>
                      ) : null}
                    </div>
                  ))}
                </div>
              </Panel>

              <Panel
                title="Coverage gaps"
                action={<Badge tone="neutral">{model.gaps.length}</Badge>}
              >
                {model.gaps.length ? (
                  model.gaps.map((gap, index) => (
                    <div className="gap-row" key={`${gap.kind}-${gap.subject}-${index}`}>
                      <Badge tone={gap.severity}>{GAP_LABEL[gap.kind] || gap.kind}</Badge>
                      <div className="list-main">
                        <div className="tiny mono">{gap.subject}</div>
                        <div className="tiny muted">{gap.detail}</div>
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="tiny muted" style={{ margin: 0, padding: '14px 16px' }}>
                    No structural gaps in the declared model. This says nothing about behaviour the
                    model does not describe.
                  </p>
                )}
              </Panel>
            </div>
          </div>
        </>
      )}

      {composerOpen && model ? (
        <InvariantComposer
          targetId={targetId}
          model={model}
          onClose={closeModals}
          onSaved={saved}
        />
      ) : null}
      {editorOpen && model ? (
        <ModelEditor
          targetId={targetId}
          model={model}
          onClose={closeModals}
          onSaved={saved}
        />
      ) : null}
    </div>
  );
}
