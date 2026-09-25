import { useQuery } from '@tanstack/react-query';
import { CheckCheck, Clock3, ShieldAlert } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Pagination } from '../components/Pagination';
import { EmptyState, ErrorState, LoadingState, PageHeader, RiskBadge } from '../components/common';
import { useAuth } from '../contexts/AuthContext';
import { apiRequest } from '../lib/api';
import { formatDateTime } from '../lib/format';
import type { ApprovalQueueItem, Paginated } from '../types/api';

export default function ApprovalsPage() {
  const { hasRole } = useAuth();
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const enabled = hasRole('approver', 'admin');

  const queueQuery = useQuery({
    queryKey: ['approvals', { page, pageSize }],
    queryFn: () => apiRequest<Paginated<ApprovalQueueItem>>('/approvals', { query: { page, page_size: pageSize } }),
    enabled,
  });

  if (!enabled) return <div className="page"><PageHeader title="Approvals" /><EmptyState icon={<ShieldAlert size={27} />} title="Approver access required" description="Your account does not have permission to review approval requests." action={<Link className="button button--secondary button--sm" to="/">Return to dashboard</Link>} /></div>;

  return (
    <div className="page approvals-page">
      <PageHeader eyebrow="Review workspace" title="Approvals" description="Requests currently assigned to your decision scope. Opening a request does not record a decision." />
      <section className="content-surface" aria-label="Approval requests" aria-busy={queueQuery.isLoading}>
        {queueQuery.isLoading ? <LoadingState label="Loading approval queue…" rows={6} /> : null}
        {queueQuery.isError ? <ErrorState error={queueQuery.error} onRetry={() => void queueQuery.refetch()} /> : null}
        {queueQuery.data?.items.length === 0 ? <EmptyState icon={<CheckCheck size={27} />} title="Your queue is clear" description="There are no requests currently awaiting a decision in your scope." action={<Link className="button button--secondary button--sm" to="/">Return to dashboard</Link>} /> : null}
        {queueQuery.data?.items.length ? (
          <div className="table-scroll">
            <table className="data-table request-table">
              <thead><tr><th scope="col">Request</th><th scope="col">Requester</th><th scope="col">Stage</th><th scope="col">Risk</th><th scope="col">Due</th><th scope="col"><span className="sr-only">Open</span></th></tr></thead>
              <tbody>{queueQuery.data.items.map((item) => {
                const overdue = new Date(item.due_at) < new Date();
                return (
                  <tr key={item.assignment_id}>
                    <td data-label="Request"><Link className="table-primary-link" to={`/requests/${item.request_id}`}><span className="request-reference">{item.request_id}</span>{item.title}</Link><span className="table-secondary">{item.category} · {item.application_name}</span></td>
                    <td data-label="Requester"><span className="table-primary">{item.requester_name}</span><span className="table-secondary">{item.data_classification_code}</span></td>
                    <td data-label="Stage"><span className="tag">{item.stage_name}</span>{item.delegated ? <span className="table-secondary">Delegated assignment</span> : null}</td>
                    <td data-label="Risk"><RiskBadge risk={item.risk_level} /></td>
                    <td data-label="Due"><span className={overdue ? 'due-overdue' : ''}><Clock3 size={15} aria-hidden="true" />{formatDateTime(item.due_at)}</span></td>
                    <td className="table-action"><Link className="button button--secondary button--sm" to={`/requests/${item.request_id}`}>Review</Link></td>
                  </tr>
                );
              })}</tbody>
            </table>
          </div>
        ) : null}
      </section>
      {queueQuery.data ? <Pagination page={queueQuery.data.page} pages={queueQuery.data.pages} total={queueQuery.data.total} pageSize={queueQuery.data.page_size} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} /> : null}
      <div className="human-decision-note"><Clock3 size={18} /><p><strong>Human decisions only.</strong> AI-generated assistance is advisory and never records an approval, rejection, or clarification request.</p></div>
    </div>
  );
}
