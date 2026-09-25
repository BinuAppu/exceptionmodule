import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, ArrowRight, CheckCircle2, ClipboardList, Clock3, FilePlus2, Hourglass, RefreshCw, TimerReset } from 'lucide-react';
import { Link } from 'react-router-dom';
import { apiRequest } from '../lib/api';
import { percentage } from '../lib/format';
import type { DashboardSummary, Paginated, RequestSummary } from '../types/api';
import { useAuth } from '../contexts/AuthContext';
import { RequestTable } from '../components/RequestTable';
import { EmptyState, ErrorState, LoadingState, PageHeader, PageSection, StatusBadge } from '../components/common';

function Metric({ label, value, note, icon, tone = 'neutral' }: { label: string; value: number | string; note?: string; icon: React.ReactNode; tone?: 'neutral' | 'warning' | 'success' }) {
  return <div className={`metric metric--${tone}`}><span className="metric__icon">{icon}</span><div><p>{label}</p><strong>{value}</strong>{note ? <span>{note}</span> : null}</div></div>;
}

export default function DashboardPage() {
  const { user, hasRole } = useAuth();
  const summaryQuery = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => apiRequest<DashboardSummary>('/dashboard'),
  });
  const recentQuery = useQuery({
    queryKey: ['dashboard-recent-requests'],
    queryFn: () => apiRequest<Paginated<RequestSummary>>('/requests', { query: { page: 1, page_size: 5, sort: 'updated', direction: 'desc' } }),
  });

  const summary = summaryQuery.data;
  const name = user?.full_name.split(' ')[0] ?? 'there';
  const statusTotal = summary?.status_counts.reduce((sum, item) => sum + item.count, 0) ?? 0;

  if (summaryQuery.isLoading) return <div className="page"><PageHeader title={`Welcome back, ${name}`} description="Loading your current exception workload…" /><LoadingState rows={6} /></div>;
  if (summaryQuery.isError) return <div className="page"><PageHeader title={`Welcome back, ${name}`} /><ErrorState error={summaryQuery.error} onRetry={() => void summaryQuery.refetch()} /></div>;

  return (
    <div className="page dashboard-page">
      <PageHeader
        eyebrow="Overview"
        title={`Welcome back, ${name}`}
        description={hasRole('approver', 'admin') ? 'Your requests and items awaiting review are summarized here.' : 'Track requests, respond to clarifications, and stay ahead of remediation dates.'}
        actions={<Link className="button button--primary button--md" to="/requests/new"><FilePlus2 size={18} />New request</Link>}
      />

      <section className="metric-grid" aria-label="Request metrics">
        <Metric label="Total requests" value={summary?.total ?? 0} note="Within your current access scope" icon={<ClipboardList size={20} />} />
        <Metric label="In review" value={summary?.pending ?? 0} note={`${summary?.drafts ?? 0} draft${summary?.drafts === 1 ? '' : 's'} remain unsubmitted`} icon={<Hourglass size={20} />} />
        <Metric label="Active exceptions" value={summary?.active ?? 0} note="Approved and within their effective period" icon={<CheckCircle2 size={20} />} tone="success" />
        <Metric label="Expiring in 30 days" value={summary?.expiring_30_days ?? 0} note="Requires renewal planning" icon={<TimerReset size={20} />} tone="warning" />
        <Metric label="Extensions" value={summary?.extensions ?? 0} note="Requested or awaiting extension review" icon={<RefreshCw size={20} />} />
      </section>

      <div className="dashboard-grid">
        <PageSection title="Recent requests" description="Your most recently updated requests." actions={<Link className="text-link" to="/requests">View all <ArrowRight size={16} /></Link>} className="dashboard-grid__main">
          {recentQuery.isLoading ? <LoadingState label="Loading recent requests…" rows={3} /> : null}
          {recentQuery.isError ? <ErrorState error={recentQuery.error} onRetry={() => void recentQuery.refetch()} title="Recent requests unavailable" /> : null}
          {recentQuery.data ? <RequestTable requests={recentQuery.data.items} showRequester={hasRole('approver', 'admin')} emptyTitle="No requests yet" emptyDescription="Start a request to document a time-bound business exception." emptyAction={<Link className="button button--primary button--sm" to="/requests/new">Create request</Link>} /> : null}
        </PageSection>
        <PageSection title="Status distribution" description={statusTotal ? `${statusTotal} requests in the current scope.` : 'Current request distribution.'} className="dashboard-grid__side">
          {!summary?.status_counts.length ? <EmptyState title="No distribution data" description="Status totals will appear after requests are available." /> : (
            <div className="distribution-list">
              {summary.status_counts.map((row) => (
                <div className="distribution-row" key={row.status}>
                  <div><StatusBadge status={row.status} /><strong>{row.count}</strong></div>
                  <div className="progress-track" aria-label={`${row.count} requests, ${percentage(row.count, statusTotal)} percent`}><span style={{ width: `${Math.max(percentage(row.count, statusTotal), 2)}%` }} /></div>
                </div>
              ))}
            </div>
          )}
          {summary?.extensions || summary?.expired ? <div className="summary-note"><Clock3 size={18} /><span>Lifecycle records</span><strong>{summary.expired} expired</strong></div> : null}
        </PageSection>
      </div>

      {summary?.expiring_30_days || summary?.expired ? (
        <PageSection title="Items needing attention" description="Deadlines approaching or already missed.">
          <div className="attention-list">
            {summary.expired ? <div><AlertTriangle size={18} /><span><strong>{summary.expired}</strong> exception{summary.expired === 1 ? ' has' : 's have'} expired</span><Link to="/requests?status=expired">Review</Link></div> : null}
            {summary.expiring_30_days ? <div><Clock3 size={18} /><span><strong>{summary.expiring_30_days}</strong> active exception{summary.expiring_30_days === 1 ? '' : 's'} approaching expiry</span><Link to="/requests?status=active&sort=expiry&order=asc">Review</Link></div> : null}
          </div>
        </PageSection>
      ) : null}
    </div>
  );
}
