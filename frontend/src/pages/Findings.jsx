import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, useApi } from '../lib/api.js';
import { useWorkspace } from '../lib/workspace.jsx';
import {
  SEVERITIES,
  SEVERITY_LABEL,
  STATUSES,
  STATUS_LABEL,
  timeAgo,
} from '../lib/format.js';
import {
  Badge,
  EmptyState,
  Icon,
  Loading,
  Modal,
  SeverityBadge,
} from '../components/ui.jsx';

export default function Findings() {
  const { repoId, repos, refreshRepos } = useWorkspace();
  const navigate = useNavigate();
  const list = useApi(repoId ? `/findings?repository_id=${repoId}` : '/findings', [repoId]);
  const [severity, setSeverity] = useState('all');
  const [status, setStatus] = useState('all');
  const [sarifOpen, setSarifOpen] = useState(false);
  const [newOpen, setNewOpen] = useState(false);
  const [targetId, setTargetId] = useState('');
  const [sarifText, setSarifText] = useState('');
  const [sarifName, setSarifName] = useState('');
  const [sarifResult, setSarifResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState(null);
  const [form, setForm] = useState({
    title: '',
    severity: 'medium',
    file_path: '',
    line: '',
    description: '',
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  });

  const findings = list.data || [];

  useEffect(() => {
    if (sarifOpen || newOpen) {
      setTargetId(repoId || (repos[0] ? String(repos[0].id) : ''));
      setFormError(null);
    }
    if (sarifOpen) {
      setSarifText('');
      setSarifName('');
      setSarifResult(null);
    }
  }, [sarifOpen, newOpen, repoId, repos]);

  const filtered = useMemo(
    () =>
      findings.filter(
        (finding) =>
          (severity === 'all' || finding.severity === severity) &&
          (status === 'all' || finding.status === status)
      ),
    [findings, severity, status]
  );

  const severityCounts = useMemo(() => {
    const counts = { all: findings.length };
    findings.forEach((finding) => {
      counts[finding.severity] = (counts[finding.severity] || 0) + 1;
    });
    return counts;
  }, [findings]);

  const readSarif = async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setSarifName(file.name);
    setSarifText(await file.text());
    setFormError(null);
  };

  const submitSarif = async (event) => {
    event.preventDefault();
    if (!targetId) {
      setFormError('Choose a target first.');
      return;
    }
    if (!sarifText.trim()) {
      setFormError('Attach or paste a SARIF file.');
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(sarifText);
    } catch {
      setFormError('That file is not valid JSON.');
      return;
    }
    setBusy(true);
    setFormError(null);
    try {
      const result = await api('/sarif', {
        method: 'POST',
        body: { repository_id: Number(targetId), sarif: parsed },
      });
      setSarifResult(result);
      setSarifText('');
      setSarifName('');
      await refreshRepos();
      list.reload();
    } catch (err) {
      setFormError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const submitFinding = async (event) => {
    event.preventDefault();
    if (!targetId) {
      setFormError('Choose a target first.');
      return;
    }
    if (!form.title.trim()) {
      setFormError('Give the finding a title.');
      return;
    }
    setBusy(true);
    setFormError(null);
    try {
      await api('/findings', {
        method: 'POST',
        body: {
          repository_id: Number(targetId),
          title: form.title,
          severity: form.severity,
          description: form.description,
          file_path: form.file_path,
          line: form.line ? Number(form.line) : null,
          cvss_vector: form.cvss_vector,
        },
      });
      setNewOpen(false);
      setForm({
        title: '',
        severity: 'medium',
        file_path: '',
        line: '',
        description: '',
        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      });
      await refreshRepos();
      list.reload();
    } catch (err) {
      setFormError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const setFindingStatus = async (finding, nextStatus) => {
    try {
      await api(`/findings/${finding.id}`, {
        method: 'PATCH',
        body: { status: nextStatus },
      });
      list.reload();
      await refreshRepos();
    } catch (err) {
      setFormError(err.message);
    }
  };

  const remove = async (finding) => {
    if (!window.confirm(`Delete "${finding.title}"?`)) return;
    try {
      await api(`/findings/${finding.id}`, { method: 'DELETE' });
      list.reload();
      await refreshRepos();
    } catch (err) {
      setFormError(err.message);
    }
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Findings</h1>
          <p className="page-sub">
            SARIF candidates and manual notes, deduplicated by rule and location. Triage
            here, then draft the writeup with the CVSS calculator.
          </p>
        </div>
        <div className="page-actions">
          <button
            type="button"
            className="btn"
            onClick={() => setSarifOpen(true)}
            disabled={!repos.length}
          >
            <Icon name="upload" size={14} />
            Upload SARIF
          </button>
          <button
            type="button"
            className="btn primary"
            onClick={() => setNewOpen(true)}
            disabled={!repos.length}
          >
            <Icon name="plus" size={14} />
            New finding
          </button>
        </div>
      </div>

      {formError && !sarifOpen && !newOpen ? (
        <div className="error-banner" style={{ marginBottom: 14 }}>{formError}</div>
      ) : null}

      <div className="row spread" style={{ marginBottom: 14, gap: 12 }}>
        <div className="row" style={{ gap: 6 }}>
          <button
            type="button"
            className={`chip${severity === 'all' ? ' active' : ''}`}
            onClick={() => setSeverity('all')}
          >
            All severities <span className="count">{severityCounts.all || 0}</span>
          </button>
          {SEVERITIES.map((value) => (
            <button
              key={value}
              type="button"
              className={`chip${severity === value ? ' active' : ''}`}
              onClick={() => setSeverity(value)}
            >
              {SEVERITY_LABEL[value]} <span className="count">{severityCounts[value] || 0}</span>
            </button>
          ))}
        </div>
        <select
          className="select"
          style={{ width: 190 }}
          value={status}
          onChange={(event) => setStatus(event.target.value)}
          aria-label="Filter by status"
        >
          <option value="all">All statuses</option>
          {STATUSES.map((value) => (
            <option key={value} value={value}>
              {STATUS_LABEL[value]}
            </option>
          ))}
        </select>
      </div>

      {list.error ? (
        <div className="error-banner">{list.error}</div>
      ) : list.loading && !findings.length ? (
        <Loading label="Loading findings…" />
      ) : !findings.length ? (
        <div className="panel">
          <EmptyState
            icon="findings"
            title="No findings yet"
            description="Upload a Semgrep, CodeQL or SonarQube SARIF export to triage candidates, or write one up by hand."
            actions={
              <>
                <button
                  type="button"
                  className="btn primary"
                  onClick={() => setSarifOpen(true)}
                  disabled={!repos.length}
                >
                  Upload SARIF
                </button>
                <button type="button" className="btn" onClick={() => setNewOpen(true)} disabled={!repos.length}>
                  New finding
                </button>
              </>
            }
          />
        </div>
      ) : (
        <div className="panel">
          {filtered.map((finding) => (
            <article className="finding-card" key={finding.id}>
              <span className={`severity-rail ${finding.severity}`} />
              <div className="finding-main">
                <div className="row" style={{ gap: 8 }}>
                  <SeverityBadge value={finding.severity} />
                  <span className="finding-title">{finding.title}</span>
                </div>
                <div className="finding-meta">
                  <span className="mono">{finding.rule_id || 'manual'}</span>
                  {finding.file_path ? (
                    <span className="mono">
                      {finding.file_path}
                      {finding.line ? `:${finding.line}` : ''}
                    </span>
                  ) : null}
                  <Badge tone="neutral">{finding.source}</Badge>
                  {finding.cvss_score != null ? (
                    <Badge tone={finding.severity}>CVSS {finding.cvss_score}</Badge>
                  ) : null}
                  {finding.occurrences > 1 ? (
                    <span>×{finding.occurrences} occurrences</span>
                  ) : null}
                  <span>{finding.repository_name}</span>
                  <span>{timeAgo(finding.created_at)}</span>
                </div>
                {finding.description ? (
                  <p className="tiny muted" style={{ margin: 0, maxWidth: '95ch' }}>
                    {finding.description.length > 220
                      ? `${finding.description.slice(0, 220)}…`
                      : finding.description}
                  </p>
                ) : null}
              </div>
              <div className="finding-actions">
                <select
                  className="status-select"
                  value={finding.status}
                  onChange={(event) => setFindingStatus(finding, event.target.value)}
                  aria-label={`Status for ${finding.title}`}
                >
                  {STATUSES.map((value) => (
                    <option key={value} value={value}>
                      {STATUS_LABEL[value]}
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  className="btn small"
                  onClick={() => navigate(`/reports/new?finding=${finding.id}`)}
                >
                  <Icon name="reports" size={13} />
                  Draft report
                </button>
                <button
                  type="button"
                  className="icon-btn"
                  title="Delete finding"
                  onClick={() => remove(finding)}
                >
                  <Icon name="trash" size={14} />
                </button>
              </div>
            </article>
          ))}
          {!filtered.length ? (
            <div className="empty" style={{ padding: 26 }}>
              <p>No findings match those filters.</p>
            </div>
          ) : null}
        </div>
      )}

      {sarifOpen ? (
        <Modal
          title="Ingest SARIF results"
          wide
          onClose={() => setSarifOpen(false)}
          footer={
            <>
              <button type="button" className="btn ghost" onClick={() => setSarifOpen(false)}>
                Close
              </button>
              <button type="submit" form="sarif-form" className="btn primary" disabled={busy}>
                {busy ? 'Ingesting…' : 'Ingest results'}
              </button>
            </>
          }
        >
          <form id="sarif-form" onSubmit={submitSarif} className="stack">
            <label className="field">
              <span className="label">Target</span>
              <select
                className="select"
                value={targetId}
                onChange={(event) => setTargetId(event.target.value)}
              >
                <option value="">Choose a target…</option>
                {repos.map((repo) => (
                  <option key={repo.id} value={repo.id}>
                    {repo.name}
                  </option>
                ))}
              </select>
            </label>
            <div className="dropzone">
              <input
                type="file"
                className="file-input"
                accept=".sarif,.json,application/json"
                onChange={readSarif}
              />
              <span className="hint">
                Semantic results from Semgrep, CodeQL, SonarQube or any SARIF 2.1.0 tool.
                {sarifName ? ` Selected: ${sarifName}` : ''}
              </span>
            </div>
            <label className="field">
              <span className="label">…or paste SARIF JSON</span>
              <textarea
                className="textarea"
                style={{ minHeight: 150, fontFamily: 'var(--mono)', fontSize: 11.5 }}
                placeholder={'{ "version": "2.1.0", "runs": [ … ] }'}
                value={sarifText}
                onChange={(event) => {
                  setSarifText(event.target.value);
                  setSarifName('pasted SARIF');
                }}
              />
            </label>
            {sarifResult ? (
              <div className="success-banner">
                Parsed {sarifResult.results} result(s): {sarifResult.created} new,{' '}
                {sarifResult.merged} merged into existing findings.
              </div>
            ) : null}
            {formError ? <div className="error-banner">{formError}</div> : null}
          </form>
        </Modal>
      ) : null}

      {newOpen ? (
        <Modal
          title="New finding"
          onClose={() => setNewOpen(false)}
          footer={
            <>
              <button type="button" className="btn ghost" onClick={() => setNewOpen(false)}>
                Cancel
              </button>
              <button type="submit" form="finding-form" className="btn primary" disabled={busy}>
                {busy ? 'Saving…' : 'Create finding'}
              </button>
            </>
          }
        >
          <form id="finding-form" onSubmit={submitFinding} className="stack">
            <div className="form-grid">
              <label className="field span-2">
                <span className="label">Target</span>
                <select
                  className="select"
                  value={targetId}
                  onChange={(event) => setTargetId(event.target.value)}
                >
                  <option value="">Choose a target…</option>
                  {repos.map((repo) => (
                    <option key={repo.id} value={repo.id}>
                      {repo.name}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field span-2">
                <span className="label">Title</span>
                <input
                  className="input"
                  value={form.title}
                  placeholder="IDOR in order lookup"
                  onChange={(event) => setForm({ ...form, title: event.target.value })}
                />
              </label>
              <label className="field">
                <span className="label">Severity</span>
                <select
                  className="select"
                  value={form.severity}
                  onChange={(event) => setForm({ ...form, severity: event.target.value })}
                >
                  {SEVERITIES.map((value) => (
                    <option key={value} value={value}>
                      {SEVERITY_LABEL[value]}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span className="label">File</span>
                <input
                  className="input"
                  value={form.file_path}
                  placeholder="src/routes/orders.js"
                  onChange={(event) => setForm({ ...form, file_path: event.target.value })}
                />
              </label>
              <label className="field">
                <span className="label">Line</span>
                <input
                  className="input"
                  value={form.line}
                  inputMode="numeric"
                  onChange={(event) => setForm({ ...form, line: event.target.value })}
                />
              </label>
              <label className="field">
                <span className="label">CVSS v3.1 vector (optional)</span>
                <input
                  className="input mono"
                  value={form.cvss_vector}
                  onChange={(event) => setForm({ ...form, cvss_vector: event.target.value })}
                />
              </label>
              <label className="field span-2">
                <span className="label">Notes</span>
                <textarea
                  className="textarea"
                  value={form.description}
                  placeholder="What did you observe, and why does it matter?"
                  onChange={(event) => setForm({ ...form, description: event.target.value })}
                />
              </label>
            </div>
            {formError ? <div className="error-banner">{formError}</div> : null}
          </form>
        </Modal>
      ) : null}
    </div>
  );
}
