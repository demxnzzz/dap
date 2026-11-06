import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api, useApi } from '../lib/api.js';
import { useWorkspace } from '../lib/workspace.jsx';
import { SEVERITIES, SEVERITY_LABEL, severityClass, timeAgo } from '../lib/format.js';
import {
  EmptyState,
  ErrorBanner,
  Loading,
  MethodBadge,
  Panel,
  RiskBadge,
  SeverityBadge,
  Stat,
} from '../components/ui.jsx';

function Bars({ rows, total }) {
  const max = Math.max(1, ...rows.map((row) => row.count));
  if (!rows.length) return <div className="muted tiny">No data yet.</div>;
  return (
    <div>
      {rows.map((row) => (
        <div className="bar-row" key={row.label}>
          <span className="truncate" style={{ color: 'var(--muted)' }}>
            {row.label}
          </span>
          <div className="bar">
            <div
              className="bar-fill"
              style={{
                width: `${Math.max(3, (row.count / max) * 100)}%`,
                background: row.color || 'var(--accent)',
              }}
            />
          </div>
          <span className="bar-value">
            {row.count}
            {total ? <span className="muted"> / {total}</span> : null}
          </span>
        </div>
      ))}
    </div>
  );
}

export default function Dashboard() {
  const { repoId, repos, refreshRepos, setRepoId } = useWorkspace();
  const statsPath = repoId ? `/stats?repository_id=${repoId}` : '/stats';
  const { data, error, loading, reload } = useApi(statsPath, [repoId]);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(null);
  const [noticeError, setNoticeError] = useState(false);

  const loadDemo = async () => {
    setBusy(true);
    setNotice(null);
    try {
      const result = await api('/demo/load', { method: 'POST' });
      await refreshRepos();
      setRepoId(String(result.repository.id));
      reload();
      setNoticeError(false);
      setNotice(
        result.created
          ? 'Demo workspace loaded — 4 commits, 18 assets, 7 findings.'
          : 'Demo workspace is already loaded.'
      );
    } catch (err) {
      setNoticeError(true);
      setNotice(err.message);
    } finally {
      setBusy(false);
    }
  };

  if (loading && !data) {
    return (
      <div className="page">
        <Loading />
      </div>
    );
  }

  if (error) {
    return (
      <div className="page">
        <ErrorBanner onRetry={reload}>{error}</ErrorBanner>
      </div>
    );
  }

  const stats = data || {};
  const severityRows = SEVERITIES.map((severity) => ({
    label: SEVERITY_LABEL[severity],
    count: stats.severity_counts?.[severity] || 0,
    color: `var(--${severity})`,
  }));
  const totalFindings = severityRows.reduce((sum, row) => sum + row.count, 0);
  const frameworkRows = (stats.framework_counts || []).map((row) => ({
    label: row.framework,
    count: row.count,
  }));
  const untriaged = (stats.status_counts?.new || 0) + (stats.status_counts?.triaged || 0);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Hunting overview</h1>
          <p className="page-sub">
            Attack surface, risky changes and open findings across{' '}
            {stats.targets || 0} target{stats.targets === 1 ? '' : 's'}.
          </p>
        </div>
        <div className="page-actions">
          <Link className="btn" to="/changes">
            Review changes
          </Link>
          <Link className="btn primary" to="/targets">
            Add target
          </Link>
        </div>
      </div>

      {notice ? (
        <div
          className={noticeError ? 'error-banner' : 'success-banner'}
          style={{ marginBottom: 14 }}
        >
          {notice}
        </div>
      ) : null}

      {!repos.length ? (
        <div className="card" style={{ padding: 26, marginBottom: 16 }}>
          <h2 style={{ margin: '0 0 6px', fontSize: 17 }}>Start a hunting workspace</h2>
          <p className="muted" style={{ margin: '0 0 14px', maxWidth: '70ch' }}>
            Load the seeded demo target to explore commit review, endpoint inventory,
            SARIF triage and report drafting — or add a real GitHub repository and sync it.
          </p>
          <div className="row">
            <button
              type="button"
              className="btn primary"
              onClick={loadDemo}
              disabled={busy}
            >
              {busy ? 'Loading demo…' : 'Load demo workspace'}
            </button>
            <Link className="btn" to="/targets">
              Add GitHub target
            </Link>
          </div>
          <p className="hint" style={{ marginTop: 12 }}>
            Public repositories sync without credentials. Private repos and higher rate
            limits need a GITHUB_TOKEN secret.
          </p>
        </div>
      ) : null}

      <div className="stat-grid">
        <Stat
          label="Targets"
          value={stats.targets || 0}
          foot={repoId ? 'filtered view' : 'monitored repositories'}
        />
        <Stat
          label="Attack surface"
          value={stats.assets || 0}
          foot="routes + parameters indexed"
        />
        <Stat
          label="Risky changes"
          value={stats.flagged_commits || 0}
          foot={`${stats.commits || 0} commits tracked`}
        />
        <Stat
          label="Open findings"
          value={stats.open_findings || 0}
          foot={`${stats.findings || 0} total · ${untriaged} untriaged`}
        />
      </div>

      <div className="grid-2">
        <Panel
          title="Recent changes"
          action={
            <Link className="btn link" to="/changes">
              Open queue →
            </Link>
          }
        >
          {stats.recent_commits?.length ? (
            <div className="list">
              {stats.recent_commits.map((commit) => (
                <Link
                  key={commit.id}
                  to={`/changes/${commit.id}`}
                  className="list-row"
                  style={{ color: 'inherit' }}
                >
                  <span className={`sev-dot ${severityClass(commit.risk_level === 'high' ? 'critical' : commit.risk_level === 'medium' ? 'medium' : 'low')}`} />
                  <div className="list-main">
                    <div className="list-title">{commit.message}</div>
                    <div className="list-sub">
                      {commit.repository_name} · {commit.author} · {commit.short_sha} ·{' '}
                      {timeAgo(commit.committed_at)}
                    </div>
                  </div>
                  <RiskBadge value={commit.risk_level} />
                </Link>
              ))}
            </div>
          ) : (
            <EmptyState
              icon="changes"
              title="No commits tracked yet"
              description="Sync a GitHub target or import a diff to start reviewing changes."
              actions={
                <Link className="btn" to="/changes">
                  Import a diff
                </Link>
              }
            />
          )}
        </Panel>

        <div className="stack">
          <Panel title="Severity mix">
            <div className="panel-body" style={{ paddingTop: 10 }}>
              <Bars rows={severityRows} total={totalFindings} />
            </div>
          </Panel>

          <Panel title="Attack surface">
            <div className="panel-body" style={{ paddingTop: 14, paddingBottom: 10 }}>
              <Bars rows={frameworkRows} total={stats.assets || 0} />
              <div className="divider" style={{ margin: '10px 0' }} />
              <div className="row" style={{ gap: 6 }}>
                {(stats.method_counts || []).map((row) => (
                  <span key={row.method} className="row" style={{ gap: 5 }}>
                    <MethodBadge method={row.method} />
                    <span className="tiny muted">{row.count}</span>
                  </span>
                ))}
                {!(stats.method_counts || []).length ? (
                  <span className="tiny muted">No endpoints indexed.</span>
                ) : null}
              </div>
            </div>
          </Panel>
        </div>
      </div>

      <div className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head">
          <h2 className="panel-title">Latest findings</h2>
          <Link className="btn link" to="/findings">
            All findings →
          </Link>
        </div>
        {stats.recent_findings?.length ? (
          <div className="list">
            {stats.recent_findings.map((finding) => (
              <Link
                key={finding.id}
                to="/findings"
                className="list-row"
                style={{ color: 'inherit' }}
              >
                <SeverityBadge value={finding.severity} />
                <div className="list-main">
                  <div className="list-title">{finding.title}</div>
                  <div className="list-sub">
                    {finding.file_path || 'no location'} ·{' '}
                    {finding.cvss_score != null ? `CVSS ${finding.cvss_score}` : 'unscored'} ·{' '}
                    {finding.source}
                  </div>
                </div>
                <span className="tiny muted">{timeAgo(finding.created_at)}</span>
              </Link>
            ))}
          </div>
        ) : (
          <EmptyState
            icon="findings"
            title="No findings yet"
            description="Upload a SARIF report or add a finding manually, then turn it into a submission-ready writeup."
            actions={
              <Link className="btn" to="/findings">
                Open findings
              </Link>
            }
          />
        )}
      </div>
    </div>
  );
}
