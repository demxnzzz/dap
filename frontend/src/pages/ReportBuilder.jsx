import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { api, useApi } from '../lib/api.js';
import { useWorkspace } from '../lib/workspace.jsx';
import { REPORT_STATUSES, STATUS_LABEL } from '../lib/format.js';
import {
  Badge,
  EmptyState,
  ErrorBanner,
  Icon,
  Loading,
  Panel,
  SeverityBadge,
} from '../components/ui.jsx';

const METRIC_DEFS = [
  {
    key: 'AV',
    label: 'Attack vector',
    options: [
      ['N', 'Network'],
      ['A', 'Adjacent'],
      ['L', 'Local'],
      ['P', 'Physical'],
    ],
  },
  {
    key: 'AC',
    label: 'Complexity',
    options: [
      ['L', 'Low'],
      ['H', 'High'],
    ],
  },
  {
    key: 'PR',
    label: 'Privileges',
    options: [
      ['N', 'None'],
      ['L', 'Low'],
      ['H', 'High'],
    ],
  },
  {
    key: 'UI',
    label: 'User interaction',
    options: [
      ['N', 'None'],
      ['R', 'Required'],
    ],
  },
  {
    key: 'S',
    label: 'Scope',
    options: [
      ['U', 'Unchanged'],
      ['C', 'Changed'],
    ],
  },
  {
    key: 'C',
    label: 'Confidentiality',
    options: [
      ['H', 'High'],
      ['L', 'Low'],
      ['N', 'None'],
    ],
  },
  {
    key: 'I',
    label: 'Integrity',
    options: [
      ['H', 'High'],
      ['L', 'Low'],
      ['N', 'None'],
    ],
  },
  {
    key: 'A',
    label: 'Availability',
    options: [
      ['H', 'High'],
      ['L', 'Low'],
      ['N', 'None'],
    ],
  },
];

const ORDER = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
const DEFAULT_METRICS = { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' };

const EMPTY_FORM = {
  title: '',
  target: '',
  researcher: '',
  summary: '',
  steps: '',
  root_cause: '',
  impact: '',
  remediation: '',
  references: '',
  platform: 'HackerOne',
  status: 'draft',
};

function vectorFrom(metrics) {
  return `CVSS:3.1/${ORDER.map((key) => `${key}:${metrics[key]}`).join('/')}`;
}

function metricsFromVector(vector) {
  if (!vector || !vector.startsWith('CVSS:3.1/')) return null;
  const parsed = {};
  vector
    .replace('CVSS:3.1/', '')
    .split('/')
    .forEach((part) => {
      const [key, value] = part.split(':');
      if (ORDER.includes(key) && value) parsed[key] = value;
    });
  return ORDER.every((key) => parsed[key]) ? parsed : null;
}

function MarkdownView({ text }) {
  if (!text) return <div className="md-preview muted">Start typing to build the writeup…</div>;
  return (
    <pre className="md-preview">
      {text.split('\n').map((line, index) => (
        <span key={index} className={line.startsWith('#') ? 'md-heading' : undefined}>
          {line}
          {'\n'}
        </span>
      ))}
    </pre>
  );
}

export default function ReportBuilder() {
  const { reportId } = useParams();
  const [searchParams] = useSearchParams();
  const findingId = searchParams.get('finding');
  const navigate = useNavigate();
  const { repos, repoId, refreshRepos } = useWorkspace();

  const reportApi = useApi(reportId ? `/reports/${reportId}` : null, [reportId]);
  const findingApi = useApi(
    !reportId && findingId ? `/findings/${findingId}` : null,
    [findingId]
  );

  const [form, setForm] = useState(EMPTY_FORM);
  const [metrics, setMetrics] = useState(DEFAULT_METRICS);
  const [targetId, setTargetId] = useState('');
  const [preview, setPreview] = useState({
    markdown: '',
    cvss_score: null,
    severity: 'medium',
    cvss_vector: '',
  });
  const [savedId, setSavedId] = useState(reportId || null);
  const [loadedKey, setLoadedKey] = useState(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(null);
  const [error, setError] = useState(null);
  const [previewError, setPreviewError] = useState(null);

  const vector = useMemo(() => vectorFrom(metrics), [metrics]);

  useEffect(() => {
    if (!reportId && !findingId && !targetId && repos.length) {
      const id = repoId || String(repos[0].id);
      const repo = repos.find((entry) => String(entry.id) === String(id));
      setTargetId(id);
      setForm((prev) => (prev.target ? prev : { ...prev, target: repo?.name || '' }));
    }
  }, [repos, repoId, reportId, findingId, targetId]);

  useEffect(() => {
    const report = reportApi.data;
    if (!report || loadedKey === `report-${report.id}`) return;
    setForm({
      title: report.title || '',
      target: report.target || '',
      researcher: report.researcher || '',
      summary: report.summary || '',
      steps: report.steps || '',
      root_cause: report.root_cause || '',
      impact: report.impact || '',
      remediation: report.remediation || '',
      references: report.references || '',
      platform: report.platform || 'HackerOne',
      status: report.status || 'draft',
    });
    setMetrics(metricsFromVector(report.cvss_vector) || DEFAULT_METRICS);
    setTargetId(String(report.repository_id));
    setSavedId(report.id);
    setLoadedKey(`report-${report.id}`);
  }, [reportApi.data, loadedKey]);

  useEffect(() => {
    const finding = findingApi.data;
    if (!finding || reportId || loadedKey === `finding-${finding.id}`) return;
    setForm({
      ...EMPTY_FORM,
      title: finding.title || '',
      target: finding.repository_name || '',
      summary: finding.description || '',
      references: finding.file_path
        ? `${finding.file_path}${finding.line ? `:${finding.line}` : ''}`
        : '',
    });
    setTargetId(String(finding.repository_id));
    setMetrics(metricsFromVector(finding.cvss_vector) || DEFAULT_METRICS);
    setLoadedKey(`finding-${finding.id}`);
  }, [findingApi.data, reportId, loadedKey]);

  useEffect(() => {
    const handle = setTimeout(() => {
      api('/reports/preview', {
        method: 'POST',
        body: { ...form, cvss_vector: vector },
      })
        .then((result) => {
          setPreview(result);
          setPreviewError(null);
        })
        .catch((err) => setPreviewError(err.message));
    }, 350);
    return () => clearTimeout(handle);
  }, [form, vector]);

  const update = (key, value) => setForm((prev) => ({ ...prev, [key]: value }));

  const save = async () => {
    if (!form.title.trim()) {
      setError('Give the report a title before saving.');
      return;
    }
    if (!targetId) {
      setError('Choose a target before saving.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const body = { ...form, cvss_vector: vector };
      const saved = savedId
        ? await api(`/reports/${savedId}`, { method: 'PUT', body })
        : await api('/reports', {
            method: 'POST',
            body: {
              ...body,
              repository_id: Number(targetId),
              finding_id: findingId ? Number(findingId) : null,
            },
          });
      setSavedId(saved.id);
      setPreview({
        markdown: saved.markdown,
        cvss_score: saved.cvss_score,
        severity: saved.severity,
        cvss_vector: saved.cvss_vector,
      });
      await refreshRepos();
      setNotice('Report saved.');
      if (!reportId) navigate(`/reports/${saved.id}`, { replace: true });
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(preview.markdown || '');
      setNotice('Markdown copied to clipboard.');
    } catch {
      setError('Clipboard is blocked here — use Download instead.');
    }
  };

  const download = () => {
    const blob = new Blob([preview.markdown || ''], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${
      (form.title || 'report')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '') || 'report'
    }.md`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  if (reportId && reportApi.loading && !reportApi.data) {
    return (
      <div className="page">
        <Loading label="Loading report…" />
      </div>
    );
  }

  if (reportId && reportApi.error) {
    return (
      <div className="page">
        <ErrorBanner onRetry={reportApi.reload}>{reportApi.error}</ErrorBanner>
      </div>
    );
  }

  if (!repos.length) {
    return (
      <div className="page">
        <div className="panel">
          <EmptyState
            icon="target"
            title="Add a target first"
            description="Reports are attached to a target so counts and exports stay organized."
            actions={
              <Link className="btn primary" to="/targets">
                Go to targets
              </Link>
            }
          />
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="row" style={{ gap: 10 }}>
            <h1 className="page-title" style={{ margin: 0 }}>
              {savedId ? 'Edit report' : 'New report'}
            </h1>
            {savedId ? <Badge tone="neutral">#{savedId}</Badge> : null}
          </div>
          <p className="page-sub">
            Structure the finding, score it with CVSS v3.1, export clean Markdown.
          </p>
        </div>
        <div className="page-actions">
          <Link className="btn ghost" to="/reports">
            Back
          </Link>
          <button type="button" className="btn" onClick={download}>
            <Icon name="download" size={14} />
            Download .md
          </button>
          <button type="button" className="btn primary" onClick={save} disabled={busy}>
            {busy ? 'Saving…' : savedId ? 'Save changes' : 'Save report'}
          </button>
        </div>
      </div>

      {notice ? <div className="success-banner" style={{ marginBottom: 14 }}>{notice}</div> : null}
      {error ? <div className="error-banner" style={{ marginBottom: 14 }}>{error}</div> : null}

      <div className="builder-grid">
        <div className="stack">
          <Panel title="Finding meta">
            <div className="panel-body stack" style={{ gap: 14 }}>
              <label className="field">
                <span className="label">Title</span>
                <input
                  className="input"
                  value={form.title}
                  placeholder="IDOR exposes any customer's orders"
                  onChange={(event) => update('title', event.target.value)}
                />
              </label>
              <div className="form-grid">
                <label className="field">
                  <span className="label">Target</span>
                  <select
                    className="select"
                    value={targetId}
                    onChange={(event) => {
                      const nextId = event.target.value;
                      const previous = repos.find(
                        (entry) => String(entry.id) === String(targetId)
                      );
                      const repo = repos.find((entry) => String(entry.id) === nextId);
                      setTargetId(nextId);
                      if (
                        repo &&
                        (!form.target.trim() || form.target === previous?.name)
                      ) {
                        update('target', repo.name);
                      }
                    }}
                  >
                    <option value="">Choose a target…</option>
                    {repos.map((repo) => (
                      <option key={repo.id} value={repo.id}>
                        {repo.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="field">
                  <span className="label">In-scope asset</span>
                  <input
                    className="input"
                    value={form.target}
                    placeholder="store.acme.test"
                    onChange={(event) => update('target', event.target.value)}
                  />
                </label>
                <label className="field">
                  <span className="label">Researcher</span>
                  <input
                    className="input"
                    value={form.researcher}
                    placeholder="you@example.com"
                    onChange={(event) => update('researcher', event.target.value)}
                  />
                </label>
                <label className="field">
                  <span className="label">Platform</span>
                  <select
                    className="select"
                    value={form.platform}
                    onChange={(event) => update('platform', event.target.value)}
                  >
                    <option>HackerOne</option>
                    <option>Bugcrowd</option>
                    <option>Intigriti</option>
                    <option>Internal</option>
                  </select>
                </label>
                <label className="field">
                  <span className="label">Report status</span>
                  <select
                    className="select"
                    value={form.status}
                    onChange={(event) => update('status', event.target.value)}
                  >
                    {REPORT_STATUSES.map((value) => (
                      <option key={value} value={value}>
                        {STATUS_LABEL[value]}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
            </div>
          </Panel>

          <Panel
            title="CVSS v3.1 calculator"
            action={
              preview.cvss_score != null ? (
                <span className="row" style={{ gap: 8 }}>
                  <SeverityBadge value={preview.severity} />
                  <span className="tiny muted">base score</span>
                </span>
              ) : null
            }
          >
            <div className="panel-body stack" style={{ gap: 14 }}>
              <div className="score-box">
                <span
                  className="score-value"
                  style={{ color: `var(--${preview.severity || 'info'})` }}
                >
                  {preview.cvss_score != null ? preview.cvss_score.toFixed(1) : '—'}
                </span>
                <div className="score-meta">
                  <span className="tiny muted">
                    {preview.severity ? `${preview.severity.toUpperCase()} severity` : 'Not scored'}
                  </span>
                  <span className="vector">{preview.cvss_vector || vector}</span>
                </div>
              </div>
              <div className="cvss-grid">
                {METRIC_DEFS.map((metric) => (
                  <label className="field cvss-metric" key={metric.key}>
                    <span className="label" style={{ fontSize: 10.5 }}>
                      {metric.label}
                    </span>
                    <select
                      className="select"
                      value={metrics[metric.key]}
                      onChange={(event) =>
                        setMetrics((prev) => ({ ...prev, [metric.key]: event.target.value }))
                      }
                    >
                      {metric.options.map(([value, label]) => (
                        <option key={value} value={value}>
                          {label} ({value})
                        </option>
                      ))}
                    </select>
                  </label>
                ))}
              </div>
              <span className="hint">
                Scope changed reweights privileges and impact per the CVSS v3.1 specification.
              </span>
            </div>
          </Panel>

          <Panel title="Writeup">
            <div className="panel-body stack" style={{ gap: 14 }}>
              <label className="field">
                <span className="label">Summary</span>
                <textarea
                  className="textarea"
                  value={form.summary}
                  placeholder="One paragraph a triager can read first."
                  onChange={(event) => update('summary', event.target.value)}
                />
              </label>
              <label className="field">
                <span className="label">Steps to reproduce</span>
                <textarea
                  className="textarea"
                  style={{ minHeight: 130, fontFamily: 'var(--mono)', fontSize: 12 }}
                  value={form.steps}
                  placeholder={'1. Sign in as user A\n2. Request /api/orders/1234\n3. Observe user B data'}
                  onChange={(event) => update('steps', event.target.value)}
                />
              </label>
              <label className="field">
                <span className="label">Root cause</span>
                <textarea
                  className="textarea"
                  value={form.root_cause}
                  placeholder="Which check is missing, and where in the code?"
                  onChange={(event) => update('root_cause', event.target.value)}
                />
              </label>
              <label className="field">
                <span className="label">Impact</span>
                <textarea
                  className="textarea"
                  value={form.impact}
                  placeholder="What can an attacker read, change or break?"
                  onChange={(event) => update('impact', event.target.value)}
                />
              </label>
              <label className="field">
                <span className="label">Remediation</span>
                <textarea
                  className="textarea"
                  value={form.remediation}
                  placeholder="Concrete fix the maintainers can apply."
                  onChange={(event) => update('remediation', event.target.value)}
                />
              </label>
              <label className="field">
                <span className="label">References</span>
                <textarea
                  className="textarea"
                  style={{ minHeight: 70 }}
                  value={form.references}
                  placeholder={'One per line — CWE links, code permalinks, docs'}
                  onChange={(event) => update('references', event.target.value)}
                />
              </label>
            </div>
          </Panel>
        </div>

        <div className="preview-col">
          <section className="panel">
            <header className="panel-head">
              <h2 className="panel-title">Markdown preview</h2>
              <div className="row" style={{ gap: 6 }}>
                <button type="button" className="btn small ghost" onClick={copy}>
                  <Icon name="copy" size={13} />
                  Copy
                </button>
              </div>
            </header>
            <MarkdownView text={preview.markdown} />
          </section>
          {previewError ? <div className="error-banner">{previewError}</div> : null}
          <p className="hint" style={{ margin: 0 }}>
            Preview regenerates as you type. Save to attach it to this target's workspace.
          </p>
        </div>
      </div>
    </div>
  );
}
