import { useQuery } from '@tanstack/react-query';
import { Eye, FileClock, Search, ShieldCheck } from 'lucide-react';
import { useDeferredValue, useState, type FormEvent } from 'react';
import { Dialog } from '../../components/Dialog';
import { Pagination } from '../../components/Pagination';
import { Button, EmptyState, ErrorState, LoadingState, PageHeader } from '../../components/common';
import { apiRequest, toQuery } from '../../lib/api';
import { formatDateTime, titleFromKey } from '../../lib/format';
import type { AuditLog, Paginated } from '../../types/api';

export default function AuditPage() {
  const [search, setSearch] = useState('');
  const deferredSearch = useDeferredValue(search.trim());
  const [action, setAction] = useState('');
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [selected, setSelected] = useState<AuditLog | null>(null);

  const auditQuery = useQuery({
    queryKey: ['admin-audit', { search: deferredSearch, action, fromDate, toDate, page, pageSize }],
    queryFn: () => apiRequest<Paginated<AuditLog>>('/admin/audit', { query: toQuery({ search: deferredSearch, action, start_date: fromDate, end_date: toDate, page, page_size: pageSize, sort_order: 'desc' }) }),
  });
  const applyDates = (event: FormEvent) => { event.preventDefault(); if (fromDate && toDate && new Date(toDate) < new Date(fromDate)) return; setPage(1); };

  return (
    <div className="page admin-page">
      <PageHeader eyebrow="Administration" title="Audit log" description="Review security, configuration, workflow, and request events in chronological order." />
      <section className="filter-panel filter-panel--admin">
        <div className="search-field"><Search size={18} /><label className="sr-only" htmlFor="audit-search">Search audit log</label><input id="audit-search" type="search" value={search} onChange={(event) => { setSearch(event.target.value); setPage(1); }} placeholder="Search actor, entity, IP, or event" /></div>
        <div className="field field--compact"><label htmlFor="audit-action">Event type</label><select id="audit-action" value={action} onChange={(event) => { setAction(event.target.value); setPage(1); }}><option value="">All events</option><option value="user.login">Sign-in</option><option value="user.updated">User changed</option><option value="request.created">Request created</option><option value="request.approved">Request approved</option><option value="request.rejected">Request rejected</option><option value="settings.updated">Settings changed</option><option value="workflow.updated">Workflow changed</option></select></div>
        <form className="date-range-fields" onSubmit={applyDates}><div className="field field--compact"><label htmlFor="audit-from">From</label><input id="audit-from" type="date" value={fromDate} onChange={(event) => setFromDate(event.target.value)} /></div><div className="field field--compact"><label htmlFor="audit-to">To</label><input id="audit-to" type="date" value={toDate} onChange={(event) => setToDate(event.target.value)} /></div><Button variant="secondary" size="sm" type="submit">Apply dates</Button></form>
      </section>
      <div className="audit-assurance"><ShieldCheck size={17} /><span>Audit records are read-only. Human approval events are labeled separately from AI-generated assistance.</span></div>
      <section className="content-surface" aria-label="Audit events" aria-busy={auditQuery.isLoading}>{auditQuery.isLoading ? <LoadingState label="Loading audit events…" rows={8} /> : null}{auditQuery.isError ? <ErrorState error={auditQuery.error} onRetry={() => void auditQuery.refetch()} /> : null}{auditQuery.data?.items.length === 0 ? <EmptyState icon={<FileClock size={27} />} title="No audit events found" description="No events match the selected filters and date range." /> : null}{auditQuery.data && auditQuery.data.items.length ? <div className="table-scroll"><table className="data-table"><thead><tr><th scope="col">Time</th><th scope="col">Actor</th><th scope="col">Event</th><th scope="col">Entity</th><th scope="col">IP address</th><th scope="col"><span className="sr-only">Details</span></th></tr></thead><tbody>{auditQuery.data.items.map((event) => <tr key={event.id}><td data-label="Time"><time dateTime={event.created_at}>{formatDateTime(event.created_at)}</time></td><td data-label="Actor"><strong>{event.actor?.full_name ?? 'System'}</strong>{event.actor?.email ? <span className="table-secondary">{event.actor.email}</span> : null}</td><td data-label="Event"><span className="event-label">{titleFromKey(event.action)}</span></td><td data-label="Entity">{event.entity_type ? <span>{titleFromKey(event.entity_type)}{event.entity_id ? <small className="entity-id">{event.entity_id}</small> : null}</span> : '—'}</td><td data-label="IP address"><code>{event.ip_address ?? 'Not recorded'}</code></td><td className="row-actions"><Button variant="ghost" size="sm" onClick={() => setSelected(event)}><Eye size={16} />Details</Button></td></tr>)}</tbody></table></div> : null}</section>
      {auditQuery.data ? <Pagination page={auditQuery.data.page || page} pages={auditQuery.data.pages} total={auditQuery.data.total} pageSize={auditQuery.data.page_size || pageSize} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} /> : null}
      <Dialog open={Boolean(selected)} title="Audit event details" description={selected ? formatDateTime(selected.created_at) : undefined} onClose={() => setSelected(null)} footer={<Button variant="secondary" onClick={() => setSelected(null)}>Close</Button>}>
        {selected ? <dl className="event-detail-list"><div><dt>Event</dt><dd>{titleFromKey(selected.action)}</dd></div><div><dt>Actor</dt><dd>{selected.actor?.full_name ?? 'System'}{selected.actor?.email ? <small>{selected.actor.email}</small> : null}</dd></div><div><dt>Entity</dt><dd>{selected.entity_type ? `${titleFromKey(selected.entity_type)} ${selected.entity_id ?? ''}` : 'Not recorded'}</dd></div><div><dt>IP address</dt><dd><code>{selected.ip_address ?? 'Not recorded'}</code></dd></div><div><dt>User agent</dt><dd className="table-wrap-text">{selected.user_agent ?? 'Not recorded'}</dd></div><div><dt>Recorded changes</dt><dd><pre className="json-view">{selected.changes ? JSON.stringify(selected.changes, null, 2) : 'No field-level changes recorded'}</pre></dd></div></dl> : null}
      </Dialog>
    </div>
  );
}
