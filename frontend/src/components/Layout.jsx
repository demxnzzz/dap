import { NavLink, Outlet, useLocation } from 'react-router-dom';
import Icon from './Icon.jsx';
import { useWorkspace } from '../lib/workspace.jsx';

const NAV = [
  { to: '/scan', label: 'Scan repo', icon: 'search' },
  { to: '/', label: 'Overview', icon: 'dashboard', end: true },
  { to: '/targets', label: 'Targets', icon: 'target' },
  { to: '/changes', label: 'Changes', icon: 'changes' },
  { to: '/assets', label: 'Assets', icon: 'assets' },
  { to: '/invariants', label: 'Invariants', icon: 'invariant' },
  { to: '/findings', label: 'Findings', icon: 'findings' },
  { to: '/reports', label: 'Reports', icon: 'reports' },
];

const CRUMBS = [
  ['/scan', 'One-shot scan'],
  ['/targets', 'Targets'],
  ['/changes', 'Commit review'],
  ['/assets', 'Asset inventory'],
  ['/invariants', 'Invariants'],
  ['/findings', 'Findings'],
  ['/reports', 'Reports'],
];

export default function Layout() {
  const { repos, repoId, setRepoId } = useWorkspace();
  const location = useLocation();
  const crumb =
    CRUMBS.find(([prefix]) => location.pathname.startsWith(prefix))?.[1] || 'Overview';

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <Icon name="target" size={21} />
          </div>
          <div>
            <div className="brand-name">DAP</div>
            <div className="brand-sub">Hunting workbench</div>
          </div>
        </div>

        <nav className="nav" aria-label="Primary">
          <div className="nav-label">Workspace</div>
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
            >
              <Icon name={item.icon} className="nav-icon" size={16} />
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <span>
            <span className="dot" /> Local workspace
          </span>
          <span>Scans only touch code you add.</span>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <div className="crumb">{crumb}</div>
          <div className="topbar-actions">
            <select
              className="select"
              style={{ width: 240 }}
              value={repoId}
              onChange={(event) => setRepoId(event.target.value)}
              aria-label="Filter by target"
            >
              <option value="">All targets</option>
              {repos.map((repo) => (
                <option key={repo.id} value={repo.id}>
                  {repo.name}
                </option>
              ))}
            </select>
          </div>
        </header>
        <Outlet />
      </div>
    </div>
  );
}
