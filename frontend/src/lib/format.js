export const SEVERITIES = ['critical', 'high', 'medium', 'low'];

export const SEVERITY_LABEL = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
  none: 'None',
};

export const RISK_LABEL = { high: 'High risk', medium: 'Review', low: 'Low risk' };

export const STATUSES = [
  'new',
  'triaged',
  'confirmed',
  'false_positive',
  'reported',
  'fixed',
];

export const STATUS_LABEL = {
  new: 'New',
  triaged: 'Triaged',
  confirmed: 'Confirmed',
  false_positive: 'False positive',
  reported: 'Reported',
  fixed: 'Fixed',
  draft: 'Draft',
  ready: 'Ready',
  submitted: 'Submitted',
};

export const REPORT_STATUSES = ['draft', 'ready', 'submitted'];

export function timeAgo(iso) {
  if (!iso) return 'never';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return 'unknown';
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 45) return 'just now';
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.round(days / 30);
  return `${months}mo ago`;
}

export function formatDate(iso) {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
  });
}

export function shortPath(path, max = 46) {
  if (!path) return '';
  return path.length > max ? `…${path.slice(-max)}` : path;
}

export function severityClass(value) {
  const key = (value || '').toLowerCase();
  if (SEVERITIES.includes(key)) return key;
  return 'info';
}
