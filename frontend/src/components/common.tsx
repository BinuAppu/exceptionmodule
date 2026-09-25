import { AlertCircle, Inbox, LoaderCircle, RefreshCw } from 'lucide-react';
import type { ButtonHTMLAttributes, ReactNode } from 'react';
import type { RequestStatus, RiskLevel } from '../types/api';
import { riskLabels, statusLabels } from '../lib/format';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  size?: 'sm' | 'md';
  loading?: boolean;
}
export function Button({ variant = 'primary', size = 'md', loading, disabled, className = '', children, ...props }: ButtonProps) {
  return (
    <button className={`button button--${variant} button--${size} ${className}`} disabled={disabled || loading} {...props}>
      {loading ? <LoaderCircle className="spin" size={17} aria-hidden="true" /> : null}
      {children}
    </button>
  );
}

export function PageHeader({ eyebrow, title, description, actions }: { eyebrow?: string; title: string; description?: string; actions?: ReactNode }) {
  return (
    <header className="page-header">
      <div>
        {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
        <h1>{title}</h1>
        {description ? <p className="page-header__description">{description}</p> : null}
      </div>
      {actions ? <div className="page-header__actions">{actions}</div> : null}
    </header>
  );
}

export function LoadingState({ label = 'Loading…', rows = 4 }: { label?: string; rows?: number }) {
  return (
    <div className="state-view" role="status" aria-live="polite">
      <LoaderCircle className="spin state-view__icon" size={24} aria-hidden="true" />
      <span className="sr-only">{label}</span>
      <div className="skeleton-stack" aria-hidden="true">
        {Array.from({ length: rows }, (_, index) => <div className="skeleton-row" key={index} />)}
      </div>
    </div>
  );
}

export function ErrorState({ error, onRetry, title = 'We could not load this page' }: { error: unknown; onRetry?: () => void; title?: string }) {
  const message = error instanceof Error ? error.message : 'An unexpected error occurred.';
  return (
    <div className="state-view state-view--error" role="alert">
      <AlertCircle className="state-view__icon" size={28} aria-hidden="true" />
      <h2>{title}</h2>
      <p>{message}</p>
      {onRetry ? <Button variant="secondary" onClick={onRetry}><RefreshCw size={17} />Try again</Button> : null}
    </div>
  );
}

export function EmptyState({ title, description, action, icon }: { title: string; description: string; action?: ReactNode; icon?: ReactNode }) {
  return (
    <div className="state-view state-view--empty">
      <div className="state-view__icon state-view__icon--muted">{icon ?? <Inbox size={27} aria-hidden="true" />}</div>
      <h2>{title}</h2>
      <p>{description}</p>
      {action}
    </div>
  );
}

export function StatusBadge({ status }: { status: RequestStatus }) {
  const tone = status === 'approved' || status === 'active' || status === 'manager_approved' || status === 'delivery_head_approved'
    ? 'approved'
    : status === 'clarification_required' || status === 'extension_requested'
      ? 'pending_clarification'
      : ['rejected', 'manager_rejected', 'delivery_head_rejected', 'expired'].includes(status)
        ? 'rejected'
        : ['draft', 'cancelled', 'withdrawn', 'closed'].includes(status)
          ? 'draft'
          : 'pending_approval';
  return <span className={`badge badge--status-${tone}`} data-status={status}>{statusLabels[status] ?? status}</span>;
}

export function RiskBadge({ risk }: { risk: RiskLevel }) {
  return <span className={`badge badge--risk-${risk}`}><span aria-hidden="true" className="badge__dot" />{riskLabels[risk] ?? risk} risk</span>;
}

export function InlineError({ message }: { message?: string | null }) {
  if (!message) return null;
  return <p className="field-error" role="alert"><AlertCircle size={15} aria-hidden="true" />{message}</p>;
}

export function PageSection({ title, description, actions, children, className = '' }: { title?: string; description?: string; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`section ${className}`}>
      {title || actions ? (
        <div className="section__header">
          <div>{title ? <h2>{title}</h2> : null}{description ? <p>{description}</p> : null}</div>
          {actions ? <div className="section__actions">{actions}</div> : null}
        </div>
      ) : null}
      {children}
    </section>
  );
}
