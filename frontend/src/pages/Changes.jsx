import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { api, useApi } from '../lib/api.js';
import { useWorkspace } from '../lib/workspace.jsx';
import { timeAgo } from '../lib/format.js';
import { Badge, EmptyState, Icon, Loading, Modal, RiskBadge } from '../components/ui.jsx';

function Patch({ text }) {
  const lines = (text || '').split('\n');
  return (
    <pre className="patch">
      {lines.map((line, index) => {
        let cls = '';
        if (
          line.startsWith('+++') ||
          line.startsWith('---') ||
          line.startsWith('diff ') ||
          line.startsWith('index ')
        ) {
          cls = 'meta';
        } else if (line.startsWith('@@')) {
          cls = 'hunk';
        } else if (line.startsWith('+')) {
          cls = 'add';
        } else if (line.startsWith('-')) {
          cls = 'del';
        }
        return (
          <span className={`diff-line ${cls}`} key={index}>
            {line || ' '}
          </span>
        );
      })}
    </pre>
  );
}

export default function Changes() {
  const { repoId, repos, refreshRepos } = useWorkspace();
  const { commitId } = useParams();
  const navigate = useNavigate();
  const [riskFilter, setRiskFilter] = useState('all');
  const [importOpen, setImportOpen] = useState(false);
  const [targetId, setTargetId] = useState('');
  const [form, setForm] = useState({
    message: '',
    author: '',
    diff_text: '',
    filename: 'changes.patch',
  });
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState(null);

  const list = useApi(repoId ? `/commits?repository_id=${repoId}` : '/commits', [repoId]);
  const detail = useApi(commitId ? `/commits/${commitId}` : null, [commitId]);

  const commits = list.data || [];
  const visible = useMemo(
    () =>
      commits.filter(
        (commit) => riskFilter === 'all' || commit.risk_level === riskFilter
      ),
    [commits, riskFilter]
  );

  useEffect(() => {
    if (!commitId && commits.length) {
      navigate(`/changes/${commits[0].id}`, { replace: true });
    }
  }, [commitId, commits, navigate]);

  useEffect(() => {
    if (importOpen) {
      setTargetId(repoId || (repos[0] ? String(repos[0].id) : ''));
      setFormError(null);
    }
  }, [importOpen, repoId, repos]);

  const submitImport = async (event) => {
    event.preventDefault();
    if (!targetId) {
      setFormError('Choose a target first.');
      return;
    }
    if (!form.diff_text.trim()) {
      setFormError('Paste a unified diff to import.');
      return;
    }
    setBusy(true);
    setFormError(null);
    try {
      const created = await api(`/repositories/${targetId}/commits/import`, {
        method: 'POST',
        body: {
          message: form.message || 'Imported change set',
          author: form.author || 'manual import',
          diff_text: form.diff_text,
          filename: form.filename || 'changes.patch',
        },
      });
      setImportOpen(false);
      setForm({ message: '', author: '', diff_text: '', filename: 'changes.patch' });
      await refreshRepos();
      list.reload();
      navigate(`/changes/${created.id}`);
    } catch (err) {
      setFormError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const toggleReviewed = async () => {
    if (!detail.data) return;
    try {
      await api(`/commits/${detail.data.id}/review`, {
        method: 'POST',
        body: { reviewed: !detail.data.reviewed },
      });
      detail.reload();
      list.reload();
    } catch (err) {
      setFormError(err.message);
    }
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Commit review</h1>
          <p className="page-sub">
            New code is the freshest attack surface. Diffs are scored for sensitive files
            and risky sinks so you know which hunks to read first.
          </p>
        </div>
        <div className="page-actions">
          <button
            type="button"
            className="btn primary"
            onClick={() => setImportOpen(true)}
            disabled={!repos.length}
          >
            <Icon name="upload" size={14} />
            Import diff
          </button>
        </div>
      </div>

      <div className="row" style={{ marginBottom: 14 }}>
        {[
          ['all', 'All changes'],
          ['high', 'High risk'],
          ['medium', 'Needs review'],
          ['low', 'Low risk'],
        ].map(([value, label]) => (
          <button
            key={value}
            type="button"
            className={`chip${riskFilter === value ? ' active' : ''}`}
            onClick={() => setRiskFilter(value)}
          >
            {label}
            <span className="count">
              {value === 'all'
                ? commits.length
                : commits.filter((commit) => commit.risk_level === value).length}
            </span>
          </button>
        ))}
      </div>

      {list.error ? (
        <div className="error-banner">{list.error}</div>
      ) : list.loading && !commits.length ? (
        <Loading label="Loading changes…" />
      ) : !commits.length ? (
        <div className="panel">
          <EmptyState
            icon="changes"
            title="No changes tracked"
            description="Import a unified diff straight from a review, or add a GitHub target and sync its commit history."
            actions={
              <>
                <button
                  type="button"
                  className="btn primary"
                  onClick={() => setImportOpen(true)}
                  disabled={!repos.length}
                >
                  Import diff
                </button>
                <button type="button" className="btn" onClick={() => navigate('/targets')}>
                  Add target
                </button>
              </>
            }
          />
        </div>
      ) : (
        <div className="split">
          <div className="commit-list">
            {visible.length ? (
              visible.map((commit) => (
                <button
                  type="button"
                  key={commit.id}
                  className={`commit-card risk-${commit.risk_level}${
                    String(commit.id) === String(commitId) ? ' selected' : ''
                  }`}
                  onClick={() => navigate(`/changes/${commit.id}`)}
                >
                  <div className="commit-message">{commit.message}</div>
                  <div className="commit-meta">
                    <RiskBadge value={commit.risk_level} />
                    {commit.reviewed ? <Badge tone="neutral">reviewed</Badge> : null}
                    <span>{commit.short_sha}</span>
                    <span>·</span>
                    <span>{timeAgo(commit.committed_at)}</span>
                  </div>
                  <div className="commit-meta">
                    <span className="mono">+{commit.additions}</span>
                    <span className="mono">−{commit.deletions}</span>
                    <span>{commit.files_changed} file(s)</span>
                    <span className="truncate">{commit.repository_name}</span>
                  </div>
                </button>
              ))
            ) : (
              <div className="muted tiny" style={{ padding: 14 }}>
                No changes match that filter.
              </div>
            )}
          </div>

          <div>
            {detail.loading && !detail.data ? (
              <Loading label="Loading diff…" />
            ) : detail.error ? (
              <div className="error-banner">{detail.error}</div>
            ) : detail.data ? (
              <article className="detail">
                <header className="detail-head">
                  <div className="row spread">
                    <h2 className="detail-title">{detail.data.message}</h2>
                    <RiskBadge value={detail.data.risk_level} />
                  </div>
                  <div className="row tiny muted" style={{ gap: 12 }}>
                    <span>{detail.data.repository_name}</span>
                    <span>{detail.data.author}</span>
                    <span className="mono">{detail.data.sha.slice(0, 12)}</span>
                    <span>{timeAgo(detail.data.committed_at)}</span>
                    <span className="mono" style={{ color: 'var(--ok)' }}>
                      +{detail.data.additions}
                    </span>
                    <span className="mono" style={{ color: 'var(--critical)' }}>
                      −{detail.data.deletions}
                    </span>
                  </div>
                  {detail.data.risk_reasons?.length ? (
                    <div className="row" style={{ gap: 6 }}>
                      {detail.data.risk_reasons.map((reason) => (
                        <Badge key={reason} tone="medium">
                          {reason}
                        </Badge>
                      ))}
                    </div>
                  ) : null}
                  <div className="row">
                    <button
                      type="button"
                      className={`btn small${detail.data.reviewed ? '' : ' primary'}`}
                      onClick={toggleReviewed}
                    >
                      <Icon name="check" size={13} />
                      {detail.data.reviewed ? 'Reviewed — mark unreviewed' : 'Mark reviewed'}
                    </button>
                    <span className="tiny muted">
                      {detail.data.files.length} file(s) in this change set
                    </span>
                  </div>
                </header>

                {detail.data.files.map((file) => (
                  <div className="file-block" key={file.id}>
                    <div className="file-head">
                      <span className="mono">{file.filename}</span>
                      <Badge tone={file.status === 'removed' ? 'critical' : file.status === 'added' ? 'low' : 'neutral'}>
                        {file.status}
                      </Badge>
                      <span style={{ color: 'var(--ok)' }}>+{file.additions}</span>
                      <span style={{ color: 'var(--critical)' }}>−{file.deletions}</span>
                      {file.is_sensitive ? <Badge tone="high">sensitive</Badge> : null}
                      {file.sensitive_reasons.map((reason) => (
                        <span key={reason} className="tiny muted">
                          {reason}
                        </span>
                      ))}
                    </div>
                    <Patch text={file.patch} />
                  </div>
                ))}
              </article>
            ) : (
              <div className="panel">
                <EmptyState
                  icon="code"
                  title="Select a change"
                  description="Pick a commit on the left to inspect its files, flags and patch."
                />
              </div>
            )}
          </div>
        </div>
      )}

      {importOpen ? (
        <Modal
          title="Import a unified diff"
          wide
          onClose={() => setImportOpen(false)}
          footer={
            <>
              <button type="button" className="btn ghost" onClick={() => setImportOpen(false)}>
                Cancel
              </button>
              <button type="submit" form="diff-import" className="btn primary" disabled={busy}>
                {busy ? 'Importing…' : 'Import change set'}
              </button>
            </>
          }
        >
          <form id="diff-import" onSubmit={submitImport} className="stack">
            <div className="form-grid">
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
              <label className="field">
                <span className="label">Commit message</span>
                <input
                  className="input"
                  value={form.message}
                  placeholder="fix(auth): rotate reset tokens"
                  onChange={(event) => setForm({ ...form, message: event.target.value })}
                />
              </label>
              <label className="field">
                <span className="label">Author</span>
                <input
                  className="input"
                  value={form.author}
                  placeholder="who wrote this change"
                  onChange={(event) => setForm({ ...form, author: event.target.value })}
                />
              </label>
              <label className="field">
                <span className="label">Fallback filename</span>
                <input
                  className="input"
                  value={form.filename}
                  onChange={(event) => setForm({ ...form, filename: event.target.value })}
                />
              </label>
            </div>
            <label className="field">
              <span className="label">Unified diff</span>
              <textarea
                className="textarea"
                style={{ minHeight: 230, fontFamily: 'var(--mono)', fontSize: 12 }}
                placeholder={'diff --git a/src/routes/auth.js b/src/routes/auth.js\n@@ -1,4 +1,9 @@\n ...'}
                value={form.diff_text}
                onChange={(event) => setForm({ ...form, diff_text: event.target.value })}
              />
              <span className="hint">
                Output of git diff, a GitHub patch URL body, or a raw patch. Multi-file diffs
                are split automatically.
              </span>
            </label>
            {formError ? <div className="error-banner">{formError}</div> : null}
          </form>
        </Modal>
      ) : null}
    </div>
  );
}
