import { Link, Route, Routes } from 'react-router-dom';
import Layout from './components/Layout.jsx';
import { WorkspaceProvider } from './lib/workspace.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Targets from './pages/Targets.jsx';
import Changes from './pages/Changes.jsx';
import Assets from './pages/Assets.jsx';
import Findings from './pages/Findings.jsx';
import Reports from './pages/Reports.jsx';
import ReportBuilder from './pages/ReportBuilder.jsx';

function NotFound() {
  return (
    <div className="page">
      <div className="card" style={{ padding: 28 }}>
        <h1 className="page-title">Page not found</h1>
        <p className="page-sub">That route does not exist in this workbench.</p>
        <Link className="btn primary" to="/" style={{ marginTop: 12 }}>
          Back to overview
        </Link>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <WorkspaceProvider>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="targets" element={<Targets />} />
          <Route path="changes" element={<Changes />} />
          <Route path="changes/:commitId" element={<Changes />} />
          <Route path="assets" element={<Assets />} />
          <Route path="findings" element={<Findings />} />
          <Route path="reports" element={<Reports />} />
          <Route path="reports/new" element={<ReportBuilder />} />
          <Route path="reports/:reportId" element={<ReportBuilder />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </WorkspaceProvider>
  );
}
