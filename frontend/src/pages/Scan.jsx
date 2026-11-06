import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../lib/api.js';
import { useWorkspace } from '../lib/workspace.jsx';
import { Badge, Icon, SeverityBadge, Stat } from '../components/ui.jsx';

const STEPS = [
  'Fetching the repository archive…',
  'Indexing routes and parameters…',
  'Screening source for exploitable patterns…',
  'Scoring findings and writing PoCs…',
  'Assembling the full report…',
];

const BOUNTY = {
  critical: '$2k–$10k',
  high: '$800–$4k',
  medium: '$200–$1k',
  low: '$50–$300',
};

export default function Scan() {
  const { refreshRepos, setRepoId } = useWorkspace();
  const [url, setUrl] = useState('');
  const [researcher, setResearcher] = useState('');
  const [platform, setPlatform] = useState('HackerOne');
  const [advanced, setAdvanced] = useState(false);
  const [busy, setBusy] = useState(false);
  const [step, setStep] = useState(0);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!busy) return undefined;
    const handle = setInterval(
      () => setStep((value) => Math.min(value + 1, STEPS.length - 1)),
      1400
    );
    return () => clearInterval(handle);
  }, [busy]);

  const run = async (event) => {
    event.preventDefault();
    const target = url.trim();
    if (!target) {
      setError('Paste a GitHub or GitLab repository URL first.');
      return;
    }
    setBusy(true);
    setError(null);
    setResult(null);
    setStep(0);
    try {
      const data = await api('/scan', {
        method: 'POST',
        body: {
          url: target,
          researcher: researcher.trim(),
          platform,
          max_reports: 8,
        },
      });
      setResult(data);
      await refreshRepos();
      setRepoId(String(data.repository.id));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const scan = result?.scan;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">One-shot scan</h1>
          <p className="page-sub">
            Paste a repository. One pass builds the attack-surface inventory, scores
            candidate findings, writes a PoC for each and assembles a submission-ready
            report.
          </p>
        </div>
        <div className="page-actions">
          <Link className="btn" to="/reports">
            All reports
          </Link>
        </div>
      </div>

      <section className="scan-hero">
        <div className="row spread" style={{ alignItems: 'baseline' }}>
          <h2>Repo in, full report out</h2>
          <span className="tiny muted">static pass · no setup required</span>
        </div>
        <form onSubmit={run}>
          <div className="scan-form">
            <input
              className="input"
              placeholder="https://github.com/owner/repo"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              aria-label="Repository URL"
              autoFocus
            />
            <button type="submit" className="btn primary" disabled={busy}>
              <Icon name="search" size={14} />
              {busy ? 'Scanning…' : 'Scan & build reports'}
            </button>
          </div>
          <div className="row" style={{ marginTop: 10, gap: 10 }}>
            <button
              type="button"
              className="btn link small"
              onClick={() => setAdvanced((value) => !value)}
            >
              {advanced ? 'Hide options' : 'Report options'}
            </button>
            <span className="hint">
              Public GitHub and GitLab repos work without credentials. Private repos
              need a token secret.
            </span>
          </div>
          {advanced ? (
            <div className="inline-form" style={{ marginTop: 12 }}>
              <label className="field">
                <span className="label">Researcher handle</span>
                <input
                  className="input"
                  placeholder="you@example.com"
                  value={researcher}
                  onChange={(event) => setResearcher(event.target.value)}
                />
              </label>
              <label className="field">
                <span className="label">Bounty platform</span>
                <select
                  className="select"
                  value={platform}
                  onChange={(event) => setPlatform(event.target.value)}
                >
                  <option>HackerOne</option>
                  <option>Bugcrowd</option>
                  <option>Intigriti</option>
                  <option>Internal</option>
                </select>
              </label>
            </div>
          ) : null}
        </form>
        {busy ? (
          <div className="scan-progress">
            <span className="spinner" />
            <span>{STEPS[step]}</span>
            <span className="tiny muted">large repos can take a minute</span>
          </div>
        ) : null}
      </section>

      {error ? <div className="error-banner" style={{ marginBottom: 16 }}>{error}</div> : null}

      {result ? (
        <>
          <div className="row spread" style={{ marginBottom: 12 }}>
            <div>
              <h2 style={{ margin: 0, fontSize: 18 }}>
                Report ready — {result.repository.name}
              </h2>
              <span className="tiny muted">
                branch {scan.branch} · {scan.files_scanned} files ·{' '}
                {scan.findings_found} candidate findings ·{' '}
                {scan.reports_written} reports written
              </span>
            </div>
            <div className="row" style={{ gap: 8 }}>
              <a
                className="btn primary"
                href={`/api/reports/${result.summary_report_id}/markdown`}
                download
              >
                <Icon name="download" size={14} />
                Download full report
              </a>
              <Link className="btn" to="/findings">
                Findings
              </Link>
              <Link className="btn" to="/assets">
                Assets
              </Link>
            </div>
          </div>

          <div className="stat-grid">
            <Stat
              label="Files scanned"
              value={scan.files_scanned}
              foot={`branch ${scan.branch}`}
            />
            <Stat
              label="Endpoints"
              value={scan.routes_found}
              foot={`${scan.assets_added} new · ${scan.assets_updated} refreshed`}
            />
            <Stat
              label="Candidate findings"
              value={scan.findings_found}
              foot={Object.entries(scan.severity_counts || {})
                .filter(([, count]) => count)
                .map(([severity, count]) => `${count} ${severity}`)
                .join(' · ') || 'none matched'}
            />
            <Stat
              label="Bounty potential"
              value={scan.bounty_estimate}
              foot="rough · platform sets the real value"
            />
          </div>

          <div className="grid-2">
            <section className="panel">
              <header className="panel-head">
                <h2 className="panel-title">Full report preview</h2>
                <Link className="btn link" to={`/reports/${result.summary_report_id}`}>
                  Open in editor →
                </Link>
              </header>
              <pre className="md-preview scan-md">{result.summary_markdown}</pre>
            </section>

            <section className="panel">
              <header className="panel-head">
                <h2 className="panel-title">Prioritised findings</h2>
                <span className="tiny muted">{scan.reports_written} reports drafted</span>
              </header>
              {result.findings?.length ? (
                <div className="list">
                  {result.findings.map((finding) => (
                    <div className="list-row" key={finding.id}>
                      <SeverityBadge value={finding.severity} />
                      <div className="list-main">
                        <div className="list-title">{finding.title}</div>
                        <div className="list-sub">
                          {finding.file_path}
                          {finding.line ? `:${finding.line}` : ''} ·{' '}
                          {finding.cvss_score != null
                            ? `CVSS ${finding.cvss_score}`
                            : 'unscored'}
                        </div>
                      </div>
                      <Badge tone="neutral">{BOUNTY[finding.severity] || '—'}</Badge>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ padding: 20 }}>
                  <p className="muted" style={{ margin: 0 }}>
                    No high-signal patterns matched. The attack-surface inventory is still
                    available under Assets — pair this pass with authenticated testing.
                  </p>
                </div>
              )}
            </section>
          </div>

          <p className="hint" style={{ marginTop: 12 }}>
            Static candidates only: exercise each PoC against an authorized environment
            before submitting. Every report is saved under Reports and can be edited.
          </p>
        </>
      ) : null}

      {!result && !busy ? (
        <div className="card" style={{ padding: 22 }}>
          <h3 style={{ margin: '0 0 8px', fontSize: 15 }}>What one scan gives you</h3>
          <div className="scan-outcomes">
            <div>
              <b>Attack surface</b>
              <span>Routes, methods and parameters indexed into the asset inventory.</span>
            </div>
            <div>
              <b>Scored findings</b>
              <span>Secrets, injection, SSRF, CORS and more, ranked by CVSS v3.1.</span>
            </div>
            <div>
              <b>Working PoCs</b>
              <span>Concrete requests and payloads for each candidate, ready to verify.</span>
            </div>
            <div>
              <b>Full report</b>
              <span>Executive summary, evidence, impact, fixes and bounty estimate.</span>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
