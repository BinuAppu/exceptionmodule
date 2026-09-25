import { ArrowUpRight, CalendarClock } from 'lucide-react';
import { Link } from 'react-router-dom';
import { formatDate, formatRelativeDate } from '../lib/format';
import type { RequestSummary } from '../types/api';
import { EmptyState, RiskBadge, StatusBadge } from './common';

interface RequestTableProps {
  requests: RequestSummary[];
  showRequester?: boolean;
  emptyTitle?: string;
  emptyDescription?: string;
  emptyAction?: React.ReactNode;
}

export function RequestTable({ requests, showRequester = false, emptyTitle = 'No requests found', emptyDescription = 'Requests matching these criteria will appear here.', emptyAction }: RequestTableProps) {
  if (!requests.length) return <EmptyState title={emptyTitle} description={emptyDescription} action={emptyAction} />;
  return (
    <div className="table-scroll">
      <table className="data-table request-table">
        <thead><tr><th scope="col">Request</th>{showRequester ? <th scope="col">Requester</th> : null}<th scope="col">Status</th><th scope="col">Risk</th><th scope="col">Expiry / due</th><th scope="col"><span className="sr-only">Open</span></th></tr></thead>
        <tbody>
          {requests.map((request) => {
            return (
              <tr key={request.public_id}>
                <td data-label="Request">
                  <Link className="table-primary-link" to={`/requests/${request.public_id}`}><span className="request-reference">{request.public_id}</span>{request.title}</Link>
                  <span className="table-secondary">{request.category_name} · Updated {formatRelativeDate(request.updated_at)}</span>
                </td>
                {showRequester ? <td data-label="Requester"><span className="table-primary">{request.requester_name}</span><span className="table-secondary">{request.department}</span></td> : null}
                <td data-label="Status"><StatusBadge status={request.status} /></td>
                <td data-label="Risk"><RiskBadge risk={request.risk_level} /></td>
                <td data-label="Expiry / due"><span><CalendarClock size={15} aria-hidden="true" />{formatDate(request.expiry_date, { month: 'short', day: 'numeric', year: 'numeric' })}</span></td>
                <td className="table-action"><Link className="icon-button" to={`/requests/${request.public_id}`} aria-label={`Open ${request.public_id}`}><ArrowUpRight size={18} /></Link></td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
