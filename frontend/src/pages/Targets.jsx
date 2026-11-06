import { useState } from 'react';
import { api } from '../lib/api.js';
import { useWorkspace } from '../lib/workspace.jsx';
import { timeAgo } from '../lib/format.js';
import { Badge, EmptyState, Field, Icon, Modal } from '../components/ui.jsx';

export default function Targets() {
  const { repos, refreshRepos, setRepoId } = useWorkspace();
  const [url, setUrl] = useState('');
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [syncing, setSyncing] = useState(null);
  const [notice, setNotice] = useState(null);
  const [error, setError] = useState(null);
  const [showTokenHelp, setShowTokenHelp] = useState(false);

  const notify = (message, isError = false) => {
    setNotice(isError ? null : message);
    setError(isError ? message : null);
  };

  const addTarget = async (event) => {
    event.preventDefault();
    if (!url.trim()) {
      notify('Paste a GitHub repository URL first.', true);
      return;
    }
    setBusy(true);
    try {
      const repo = await api('/repositories', {
        method: 'POST',
        body: { url: url.trim(), name: name.trim() || undefined },
      });
      await refreshRepos();
      setRepoId(String(repo.id));
      setUrl('');
      setName('');
      notify(`Target "${repo.name}" added. Run a sync to pull commits and endpoints.`);
    } catch (err) {
      notify(err.message, true);
    } finally {
      setBusy(false);
    }
  };

  const sync = async (repo) => {
    setSyncing(repo.id);
    setNotice(null);
    setError(null);
    try {
      const result = await api(`/repositories/${repo.id}/sync`, { method: 'POST' });
      await refreshRepos();
      const summary = result.summary;
      notify(
        `Sync complete: ${summary.commits_added} new commit(s), ${summary.assets_added} new asset(s), ${summary.assets_updated} refreshed, ${summary.files_scanned} file(s) parsed.`
      );
    } catch (err) {
      notify(err.message, true);
    } finally {
      setSyncing(null);
    }
  };

  const remove = async (repo) => {
    if (!window.confirm(`Remove "${repo.name}" and all of its commits, assets and findings?`)) {
      return;
    }
    try {
      await api(`/repositories/${repo.id}`, { method: 'DELETE' });
      await refreshRepos();
      notify(`Removed "${repo.name}".`);
    } catch (err) {
      notify(err.message, true);
    }
  };

  const loadDemo = async () => {
    setBusy(true);
    try {
      const result = await api('/demo/load', { method: 'POST' });
      await refreshRepos();
      setRepoId(String(result.repository.id));
      notify(result.created ? 'Demo workspace loaded.' : 'Demo workspace already present.');
    } catch (err) {
      notify(err.message, true);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Targets</h1>
          <p className="page-sub">
            Repositories under review. Sync pulls recent commits with diffs and parses
            source files into the asset inventory.
          </p>
        </div>
        <div className="page-actions">
          <button type="button" className="btn" onClick={loadDemo} disabled={busy}>
            Load demo workspace
          </button>
          <button type="button" className="btn ghost" onClick={() => setShowTokenHelp(true)}>
            Sync requirements
          </button>
        </div>
      </div>

      {notice ? <div className="success-banner" style={{ marginBottom: 14 }}>{notice}</div> : null}
      {error ? <div className="error-banner" style={{ marginBottom: 14 }}>{error}</div> : null}

      <form className="card" onSubmit={addTarget} style={{ marginBottom: 18 }}>
        <div className="inline-form">
          <Field label="Repository URL">
            <input
              className="input"
              placeholder="https://github.com/owner/repo"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
            />
          </Field>
          <Field label="Display name (optional)">
            <input
              className="input"
              placeholder="e.g. storefront"
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
          </Field>
          <button type="submit" className="btn primary" disabled={busy}>
            {busy ? 'Adding…' : 'Add target'}
          </button>
        </div>
      </form>

      {repos.length ? (
        <div className="repo-grid">
          {repos.map((repo) => (
            <article className="repo-card" key={repo.id}>
              <div className="row spread" style={{ alignItems: 'flex-start' }}>
                <h3>{repo.name}</h3>
                <Badge tone={repo.source_type === 'demo' ? 'medium' : 'neutral'}>
                  {repo.source_type === 'demo' ? 'demo' : repo.platform}
                </Badge>
              </div>
              <div className="repo-url">{repo.url}</div>
              <div className="row tiny muted" style={{ gap: 14 }}>
                <span>branch {repo.default_branch}</span>
                <span>synced {timeAgo(repo.last_synced_at)}</span>
              </div>
              <div className="repo-stats">
                <span>
                  <b>{repo.counts?.assets || 0}</b> assets
                </span>
                <span>
                  <b>{repo.counts?.commits || 0}</b> commits
                </span>
                <span>
                  <b>{repo.counts?.findings || 0}</b> findings
                </span>
                <span>
                  <b>{repo.counts?.reports || 0}</b> reports
                </span>
              </div>
              <div className="row">
                <button
                  type="button"
                  className="btn small"
                  onClick={() => sync(repo)}
                  disabled={repo.source_type === 'demo' || syncing === repo.id}
                  title={
                    repo.source_type === 'demo'
                      ? 'Seeded workspace — nothing to sync'
                      : 'Pull commits, diffs and source files'
                  }
                >
                  <Icon name="refresh" size={13} />
                  {syncing === repo.id ? 'Syncing…' : 'Sync now'}
                </button>
                <button
                  type="button"
                  className="btn small danger"
                  onClick={() => remove(repo)}
                >
                  <Icon name="trash" size={13} />
                  Remove
                </button>
              </div>
            </article>
          ))}
        </div>
      ) : (
        <div className="panel">
          <EmptyState
            icon="target"
            title="No targets yet"
            description="Add a GitHub repository above, or load the demo workspace to see how the modules fit together."
            actions={
              <button type="button" className="btn primary" onClick={loadDemo} disabled={busy}>
                Load demo workspace
              </button>
            }
          />
        </div>
      )}

      {showTokenHelp ? (
        <Modal
          title="How syncing works"
          onClose={() => setShowTokenHelp(false)}
          footer={
            <button type="button" className="btn" onClick={() => setShowTokenHelp(false)}>
              Got it
            </button>
          }
        >
          <p className="muted" style={{ margin: 0 }}>
            The sync job reads the GitHub REST API: recent commits with file patches, then
            the repository tree for source files it can parse into routes and parameters.
          </p>
          <dl className="kv">
            <dt>Public repos</dt>
            <dd>Works without credentials. Limited to 60 API calls per hour.</dd>
            <dt>Private repos</dt>
            <dd>
              Requires a <span className="mono">GITHUB_TOKEN</span> secret with{' '}
              <span className="mono">repo:read</span> scope.
            </dd>
            <dt>Rate limits</dt>
            <dd>Unauthenticated syncs pull 6 commits and scan 15 files; token syncs pull 10 and scan 40.</dd>
            <dt>No token?</dt>
            <dd>Paste a unified diff on the Changes page and source snippets on Assets — both work offline.</dd>
          </dl>
        </Modal>
      ) : null}
    </div>
  );
}
