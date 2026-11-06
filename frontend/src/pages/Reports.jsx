import { Link, useNavigate } from 'react-router-dom';
import { api, useApi } from '../lib/api.js';
import { useWorkspace } from '../lib/workspace.jsx';
import { STATUS_LABEL, timeAgo } from '../lib/format.js';
import { Badge, EmptyState, Icon, Loading, SeverityBadge } from '../components/ui.jsx';

export default function Reports() {
  const { repoId, refreshRepos } = useWorkspace();
  const navigate = useNavigate();
  const list = useApi(repoId ? `/reports?repository_id=${repoId}` : '/reports', [repoId]);
  const reports = list.data || [];

  const remove = async (report) => {
    if (!window.confirm(`Delete the report "${report.title}"?`)) return;
    await api(`/reports/${report.id}`, { method: 'DELETE' });
    list.reload();
    await refreshRepos();
  };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1 className="page-title">Reports</h1>
          <p className="page-sub">
            Submission-ready writeups with reproduction steps, impact and a CVSS v3.1
            vector. Export as Markdown for HackerOne, Bugcrowd or an internal ticket.
          </p>
        </div>
        <div className="page-actions">
          <Link className="btn primary" to="/reports/new">
            <Icon name="plus" size={14} />
            New report
          </Link>
        </div>
      </div>

      {list.error ? (
        <div className="error-banner">{list.error}</div>
      ) : list.loading && !reports.length ? (
        <Loading label="Loading reports…" />
      ) : !reports.length ? (
        <div className="panel">
          <EmptyState
            icon="reports"
            title="No reports drafted"
            description="Open a finding and choose “Draft report”, or start from a blank writeup and score it with the calculator."
            actions={
              <>
                <Link className="btn primary" to="/reports/new">
                  New report
                </Link>
                <Link className="btn" to="/findings">
                  Browse findings
                </Link>
              </>
            }
          />
        </div>
      ) : (
        <div className="report-list">
          {reports.map((report) => (
            <article
              key={report.id}
              className="report-card"
              role="button"
              tabIndex={0}
              onClick={() => navigate(`/reports/${report.id}`)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') navigate(`/reports/${report.id}`);
              }}
            >
              <div className="row spread" style={{ alignItems: 'flex-start' }}>
                <SeverityBadge value={report.severity} />
                <Badge tone={report.status === 'submitted' ? 'low' : report.status === 'ready' ? 'medium' : 'neutral'}>
                  {STATUS_LABEL[report.status] || report.status}
                </Badge>
              </div>
              <div className="report-title">{report.title}</div>
              <div className="row tiny muted" style={{ gap: 10 }}>
                <span>{report.platform}</span>
                <span>·</span>
                <span>{report.target || 'no target set'}</span>
                <span>·</span>
                <span>updated {timeAgo(report.updated_at)}</span>
              </div>
              <div className="row spread" style={{ marginTop: 2 }}>
                <span className="tiny muted">
                  {report.cvss_score != null ? `CVSS ${report.cvss_score}` : 'unscored'}
                </span>
                <button
                  type="button"
                  className="icon-btn"
                  title="Delete report"
                  onClick={(event) => {
                    event.stopPropagation();
                    remove(report);
                  }}
                >
                  <Icon name="trash" size={14} />
                </button>
              </div>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
