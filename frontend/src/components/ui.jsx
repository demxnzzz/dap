import { useEffect } from 'react';
import { createPortal } from 'react-dom';
import Icon from './Icon.jsx';
import { SEVERITY_LABEL, STATUS_LABEL, severityClass } from '../lib/format.js';

export { Icon };

export function Badge({ tone = 'neutral', children, mono = false }) {
  return (
    <span className={`badge ${tone}${mono ? ' mono' : ''}`}>{children}</span>
  );
}

export function SeverityBadge({ value }) {
  const tone = severityClass(value);
  return <Badge tone={tone}>{SEVERITY_LABEL[value] || value || '—'}</Badge>;
}

export function StatusBadge({ value }) {
  const tone =
    value === 'confirmed' || value === 'reported' || value === 'fixed'
      ? 'low'
      : value === 'false_positive'
        ? 'neutral'
        : value === 'triaged'
          ? 'medium'
          : 'info';
  return <Badge tone={tone}>{STATUS_LABEL[value] || value}</Badge>;
}

export function RiskBadge({ value }) {
  const tone = value === 'high' ? 'critical' : value === 'medium' ? 'medium' : 'low';
  const label = value === 'high' ? 'High risk' : value === 'medium' ? 'Review' : 'Low risk';
  return <Badge tone={tone}>{label}</Badge>;
}

export function MethodBadge({ method }) {
  return <span className={`method ${method}`}>{method}</span>;
}

export function Stat({ label, value, foot }) {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {foot ? <div className="stat-foot">{foot}</div> : null}
    </div>
  );
}

export function Loading({ label = 'Loading workspace…' }) {
  return (
    <div className="loading">
      <span className="spinner" />
      {label}
    </div>
  );
}

export function ErrorBanner({ children, onRetry }) {
  return (
    <div className="error-banner">
      {children}
      {onRetry ? (
        <button type="button" className="btn link" onClick={onRetry} style={{ marginTop: 8 }}>
          Try again
        </button>
      ) : null}
    </div>
  );
}

export function EmptyState({ icon = 'shield', title, description, actions }) {
  return (
    <div className="empty">
      <div className="empty-mark">
        <Icon name={icon} size={20} />
      </div>
      <h3>{title}</h3>
      {description ? <p>{description}</p> : null}
      {actions ? <div className="row" style={{ marginTop: 6 }}>{actions}</div> : null}
    </div>
  );
}

export function Modal({ title, onClose, children, footer, wide = false }) {
  useEffect(() => {
    const handler = (event) => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  return createPortal(
    <div className="modal-backdrop" onMouseDown={onClose} role="presentation">
      <div
        className={`modal${wide ? ' wide' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="modal-head">
          <h3>{title}</h3>
          <button type="button" className="icon-btn" onClick={onClose} aria-label="Close">
            <Icon name="close" size={16} />
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer ? <div className="modal-foot">{footer}</div> : null}
      </div>
    </div>,
    document.body
  );
}

export function Field({ label, hint, children, className = '' }) {
  return (
    <label className={`field ${className}`}>
      <span className="label">{label}</span>
      {children}
      {hint ? <span className="hint">{hint}</span> : null}
    </label>
  );
}

export function Panel({ title, action, children, bodyClass = '' }) {
  return (
    <section className="panel">
      <header className="panel-head">
        <h2 className="panel-title">{title}</h2>
        {action}
      </header>
      <div className={bodyClass}>{children}</div>
    </section>
  );
}
