import { useEffect, useMemo, useState } from 'react';
import { api, useApi } from '../lib/api.js';
import { useWorkspace } from '../lib/workspace.jsx';
import { timeAgo } from '../lib/format.js';
import {
  Badge,
  EmptyState,
  Icon,
  Loading,
  MethodBadge,
  Modal,
} from '../components/ui.jsx';

const METHODS = ['ALL', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

export default function Assets() {
  const { repoId, repos, refreshRepos } = useWorkspace();
  const list = useApi(repoId ? `/assets?repository_id=${repoId}` : '/assets', [repoId]);
  const [query, setQuery] = useState('');
  const [method, setMethod] = useState('ALL');
  const [scanOpen, setScanOpen] = useState(false);
  const [targetId, setTargetId] = useState('');
  const [files, setFiles] = useState([]);
  const [manualPath, setManualPath] = useState('pasted-routes.js');
  const [manualContent, setManualContent] = useState('');
  const [busy, setBusy] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [formError, setFormError] = useState(null);

  const assets = list.data || [];

  useEffect(() => {
    if (scanOpen) {
      setTargetId(repoId || (repos[0] ? String(repos[0].id) : ''));
      setFiles([]);
      setManualPath('pasted-routes.js');
      setManualContent('');
      setScanResult(null);
      setFormError(null);
    }
  }, [scanOpen, repoId, repos]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return assets.filter((asset) => {
      if (method !== 'ALL' && asset.method !== method) return false;
      if (!needle) return true;
      const haystack = [
        asset.path,
        asset.file_path,
        asset.framework,
        (asset.params || []).join(' '),
        asset.repository_name || '',
      ]
        .join(' ')
        .toLowerCase();
      return haystack.includes(needle);
    });
  }, [assets, method, query]);

  const methodCounts = useMemo(() => {
    const counts = { ALL: assets.length };
    assets.forEach((asset) => {
      counts[asset.method] = (counts[asset.method] || 0) + 1;
    });
    return counts;
  }, [assets]);

  const readFiles = async (event) => {
    const picked = Array.from(event.target.files || []);
    const loaded = await Promise.all(
      picked.map(async (file) => ({
        path: file.webkitRelativePath || file.name,
        content: await file.text(),
      }))
    );
    setFiles(loaded);
    setFormError(null);
  };

  const submitScan = async (event) => {
    event.preventDefault();
    if (!targetId) {
      setFormError('Choose a target to attach these assets to.');
      return;
    }
    const payload = files.slice();
    if (manualContent.trim()) {
      payload.push({ path: manualPath || 'pasted-snippet.txt', content: manualContent });
    }
    if (!payload.length) {
      setFormError('Attach files or paste a source snippet.');
      return;
    }
    setBusy(true);
    setFormError(null);
    try {
      const result = await api(`/repositories/${targetId}/scan-files`, {
        method: 'POST',
        body: { files: payload },
      });
      setScanResult(result);
      setFiles([]);
      setManualContent('');
      await refreshRepos();
      list.reload();
    } catch (err) {
      setFormError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const remove = async (asset) => {
    if (!window.confirm(`Remove ${asset.method} ${asset.path} from the inventory?`)) return;
    try {
      await api(`/assets/${asset.id}`, { method: 'DELETE' });
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
          <h1 className="page-title">Asset inventory</h1>
          <p className="page-sub">
            Routes and parameters extracted from source — the map you hunt against.
            Scans are local regex passes, no code is executed.
          </p>
        </div>
        <div className="page-actions">
          <button
            type="button"
            className="btn primary"
            onClick={() => setScanOpen(true)}
            disabled={!repos.length}
          >
            <Icon name="code" size={14} />
            Scan source
          </button>
        </div>
      </div>

      {formError && !scanOpen ? (
        <div className="error-banner" style={{ marginBottom: 14 }}>{formError}</div>
      ) : null}

      <div className="row spread" style={{ marginBottom: 14, gap: 10 }}>
        <div className="row" style={{ gap: 6 }}>
          {METHODS.map((value) => (
            <button
              key={value}
              type="button"
              className={`chip${method === value ? ' active' : ''}`}
              onClick={() => setMethod(value)}
            >
              {value === 'ALL' ? 'All' : value}
              <span className="count">{methodCounts[value] || 0}</span>
            </button>
          ))}
        </div>
        <div className="row" style={{ position: 'relative', minWidth: 260 }}>
          <span
            style={{
              position: 'absolute',
              left: 10,
              top: 10,
              color: 'var(--muted-2)',
              display: 'grid',
              placeItems: 'center',
            }}
          >
            <Icon name="search" size={14} />
          </span>
          <input
            className="input"
            style={{ paddingLeft: 32 }}
            placeholder="Filter by path, param, file…"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </div>
      </div>

      {list.error ? (
        <div className="error-banner">{list.error}</div>
      ) : list.loading && !assets.length ? (
        <Loading label="Loading assets…" />
      ) : !assets.length ? (
        <div className="panel">
          <EmptyState
            icon="assets"
            title="No endpoints indexed"
            description="Scan Express, FastAPI, Flask, Django, Spring, Rails or Go source to build the inventory — or add a GitHub target and sync."
            actions={
              <button
                type="button"
                className="btn primary"
                onClick={() => setScanOpen(true)}
                disabled={!repos.length}
              >
                Scan source
              </button>
            }
          />
        </div>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 78 }}>Method</th>
                <th>Endpoint &amp; parameters</th>
                <th style={{ width: 110 }}>Framework</th>
                <th>Source file</th>
                <th style={{ width: 120 }}>Target</th>
                <th style={{ width: 90 }}>Seen</th>
                <th style={{ width: 44 }} />
              </tr>
            </thead>
            <tbody>
              {filtered.map((asset) => (
                <tr key={asset.id}>
                  <td>
                    <MethodBadge method={asset.method} />
                  </td>
                  <td>
                    <div className="path">{asset.path}</div>
                    <div className="row" style={{ gap: 4, marginTop: 4 }}>
                      {(asset.params || []).map((param) => (
                        <span className="param" key={param}>
                          {param}
                        </span>
                      ))}
                      {!(asset.params || []).length ? (
                        <span className="tiny muted">no parameters detected</span>
                      ) : null}
                    </div>
                  </td>
                  <td>
                    <Badge tone="neutral">{asset.framework}</Badge>
                  </td>
                  <td>
                    <span className="mono tiny muted" title={asset.file_path}>
                      {asset.file_path}
                    </span>
                  </td>
                  <td className="tiny muted">{asset.repository_name}</td>
                  <td className="tiny muted nowrap">{timeAgo(asset.last_seen)}</td>
                  <td>
                    <button
                      type="button"
                      className="icon-btn"
                      title="Remove asset"
                      onClick={() => remove(asset)}
                    >
                      <Icon name="trash" size={14} />
                    </button>
                  </td>
                </tr>
              ))}
              {!filtered.length ? (
                <tr>
                  <td colSpan={7}>
                    <div className="empty" style={{ padding: 24 }}>
                      <p>No assets match that filter.</p>
                    </div>
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      )}

      {scanOpen ? (
        <Modal
          title="Scan source for endpoints"
          wide
          onClose={() => setScanOpen(false)}
          footer={
            <>
              <button type="button" className="btn ghost" onClick={() => setScanOpen(false)}>
                Close
              </button>
              <button type="submit" form="scan-form" className="btn primary" disabled={busy}>
                {busy ? 'Scanning…' : 'Scan and index'}
              </button>
            </>
          }
        >
          <form id="scan-form" onSubmit={submitScan} className="stack">
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
                multiple
                className="file-input"
                accept=".py,.js,.jsx,.ts,.tsx,.mjs,.java,.rb,.go,.php,.kt"
                onChange={readFiles}
              />
              <span className="hint">
                Route files from Express, FastAPI, Flask, Django, Spring, Rails or Go.
                {files.length ? ` ${files.length} file(s) staged: ${files.map((file) => file.path).join(', ')}` : ''}
              </span>
            </div>

            <div className="form-grid">
              <label className="field">
                <span className="label">Or paste a snippet path</span>
                <input
                  className="input"
                  value={manualPath}
                  onChange={(event) => setManualPath(event.target.value)}
                />
              </label>
              <label className="field span-2">
                <span className="label">Snippet</span>
                <textarea
                  className="textarea"
                  style={{ minHeight: 130, fontFamily: 'var(--mono)', fontSize: 12 }}
                  placeholder={"router.get('/api/orders/:orderId', auth, handler);"}
                  value={manualContent}
                  onChange={(event) => setManualContent(event.target.value)}
                />
              </label>
            </div>

            {scanResult ? (
              <div className="success-banner">
                Scanned {scanResult.files_scanned} file(s) · found {scanResult.routes_found}{' '}
                route(s) · {scanResult.assets_added} new, {scanResult.assets_updated}{' '}
                refreshed in the inventory.
              </div>
            ) : null}
            {formError ? <div className="error-banner">{formError}</div> : null}
          </form>
        </Modal>
      ) : null}
    </div>
  );
}
