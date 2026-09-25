import { useQuery } from '@tanstack/react-query';
import { Filter, Plus, RotateCcw, Search, SlidersHorizontal } from 'lucide-react';
import { useDeferredValue, useEffect, useState, type Dispatch, type SetStateAction } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Pagination } from '../components/Pagination';
import { RequestTable } from '../components/RequestTable';
import { Button, ErrorState, LoadingState, PageHeader } from '../components/common';
import { useAuth } from '../contexts/AuthContext';
import { apiRequest, toQuery } from '../lib/api';
import type { FormOptions, Paginated, RequestStatus, RequestSummary } from '../types/api';

const statuses: Array<{ value: RequestStatus; label: string }> = [
  { value: 'draft', label: 'Draft' },
  { value: 'submitted', label: 'Submitted' },
  { value: 'pending_manager_approval', label: 'Manager review' },
  { value: 'pending_delivery_head_approval', label: 'Delivery Head review' },
  { value: 'pending_approver_review', label: 'Exception review' },
  { value: 'clarification_required', label: 'Needs clarification' },
  { value: 'approved', label: 'Approved' },
  { value: 'active', label: 'Active' },
  { value: 'rejected', label: 'Rejected' },
  { value: 'expired', label: 'Expired' },
  { value: 'withdrawn', label: 'Withdrawn' },
  { value: 'closed', label: 'Closed' },
];
const allowedSorts = new Set(['created', 'updated', 'expiry', 'risk', 'title', 'status']);

export default function RequestsPage() {
  const { user } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const [search, setSearch] = useState(searchParams.get('search') ?? '');
  const deferredSearch = useDeferredValue(search.trim());
  const [status, setStatus] = useState<RequestStatus | ''>((searchParams.get('status') as RequestStatus | null) ?? '');
  const [risk, setRisk] = useState(searchParams.get('risk') ?? '');
  const [categoryId, setCategoryId] = useState(searchParams.get('category') ?? '');
  const requestedSort = searchParams.get('sort') ?? 'updated';
  const [sort, setSort] = useState(allowedSorts.has(requestedSort) ? requestedSort : 'updated');
  const [order, setOrder] = useState<'asc' | 'desc'>(searchParams.get('order') === 'asc' ? 'asc' : 'desc');
  const [page, setPage] = useState(Number(searchParams.get('page') ?? 1));
  const [pageSize, setPageSize] = useState(Number(searchParams.get('page_size') ?? 20));
  const [filtersOpen, setFiltersOpen] = useState(false);

  useEffect(() => {
    const next = new URLSearchParams();
    if (deferredSearch) next.set('search', deferredSearch);
    if (status) next.set('status', status);
    if (risk) next.set('risk', risk);
    if (categoryId) next.set('category', categoryId);
    if (sort !== 'updated') next.set('sort', sort);
    if (order !== 'desc') next.set('order', order);
    if (page !== 1) next.set('page', String(page));
    if (pageSize !== 20) next.set('page_size', String(pageSize));
    setSearchParams(next, { replace: true });
  }, [deferredSearch, status, risk, categoryId, sort, order, page, pageSize, setSearchParams]);

  const requestQuery = useQuery({
    queryKey: ['requests', { search: deferredSearch, status, risk, categoryId, sort, order, page, pageSize }],
    queryFn: () => apiRequest<Paginated<RequestSummary>>('/requests', {
      query: toQuery({ search: deferredSearch, status, risk_level_id: risk, category_id: categoryId, sort, direction: order, page, page_size: pageSize }),
    }),
  });
  const optionsQuery = useQuery({
    queryKey: ['request-form-options'],
    queryFn: () => apiRequest<FormOptions>('/request-form-options'),
  });
  const categories = optionsQuery.data?.categories.filter((category) => category.active) ?? [];
  const riskLevels = optionsQuery.data?.risk_levels ?? [];
  const hasFilters = Boolean(deferredSearch || status || risk || categoryId);

  const resetFilters = () => {
    setSearch(''); setStatus(''); setRisk(''); setCategoryId(''); setSort('updated'); setOrder('desc'); setPage(1);
  };
  function updateFilter<T>(setter: Dispatch<SetStateAction<T>>, value: T) { setter(value); setPage(1); }

  return (
    <div className="page requests-page">
      <PageHeader
        eyebrow="Exception register"
        title="Requests"
        description={user?.role === 'user' ? 'Search, review, and manage the exception requests you own.' : 'Search and review exception requests across the organization.'}
        actions={<Link className="button button--primary button--md" to="/requests/new"><Plus size={18} />New request</Link>}
      />
      <section className="filter-panel" aria-label="Request filters">
        <div className="filter-panel__top">
          <div className="search-field">
            <Search size={18} aria-hidden="true" />
            <label className="sr-only" htmlFor="request-search">Search requests</label>
            <input id="request-search" type="search" value={search} onChange={(event) => { setSearch(event.target.value); setPage(1); }} placeholder="Search by title, reference, or requester" />
          </div>
          <Button variant="secondary" className="filter-toggle" onClick={() => setFiltersOpen((open) => !open)} aria-expanded={filtersOpen} aria-controls="request-filters"><SlidersHorizontal size={17} />Filters{hasFilters ? <span className="filter-count">{[status, risk, categoryId].filter(Boolean).length}</span> : null}</Button>
        </div>
        <div id="request-filters" className={`filter-panel__controls ${filtersOpen ? 'filter-panel__controls--open' : ''}`}>
          <div className="field field--compact"><label htmlFor="status-filter">Status</label><select id="status-filter" value={status} onChange={(event) => updateFilter(setStatus, event.target.value as RequestStatus | '')}><option value="">All statuses</option>{statuses.map((item) => <option value={item.value} key={item.value}>{item.label}</option>)}</select></div>
          <div className="field field--compact"><label htmlFor="risk-filter">Risk</label><select id="risk-filter" value={risk} onChange={(event) => updateFilter(setRisk, event.target.value)}><option value="">All risk levels</option>{riskLevels.map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}</select></div>
          <div className="field field--compact"><label htmlFor="category-filter">Category</label><select id="category-filter" value={categoryId} onChange={(event) => updateFilter(setCategoryId, event.target.value)}><option value="">All categories</option>{categories.map((category) => <option value={category.id} key={category.id}>{category.name}</option>)}</select></div>
          <div className="field field--compact"><label htmlFor="sort-filter">Sort by</label><select id="sort-filter" value={sort} onChange={(event) => updateFilter(setSort, event.target.value)}><option value="updated">Last updated</option><option value="created">Created date</option><option value="expiry">Expiry date</option><option value="risk">Risk level</option><option value="title">Title</option><option value="status">Status</option></select></div>
          <div className="field field--compact"><label htmlFor="order-filter">Order</label><select id="order-filter" value={order} onChange={(event) => updateFilter(setOrder, event.target.value as 'asc' | 'desc')}><option value="desc">Descending</option><option value="asc">Ascending</option></select></div>
          {hasFilters ? <Button variant="ghost" size="sm" onClick={resetFilters}><RotateCcw size={16} />Reset</Button> : null}
        </div>
      </section>
      <div className="results-heading">
        <div><Filter size={16} aria-hidden="true" /><span>{requestQuery.data ? `${requestQuery.data.total} request${requestQuery.data.total === 1 ? '' : 's'}` : 'Request results'}</span></div>
        {hasFilters ? <span className="results-heading__hint">Filtered results reflect your current access scope</span> : null}
      </div>
      <section className="content-surface" aria-label="Requests" aria-busy={requestQuery.isLoading}>
        {requestQuery.isLoading ? <LoadingState label="Loading requests…" rows={7} /> : null}
        {requestQuery.isError ? <ErrorState error={requestQuery.error} onRetry={() => void requestQuery.refetch()} /> : null}
        {requestQuery.data ? <RequestTable requests={requestQuery.data.items} showRequester={user?.role !== 'user'} emptyTitle={hasFilters ? 'No requests match these filters' : 'No requests yet'} emptyDescription={hasFilters ? 'Try broadening your search or removing a filter.' : 'Create your first exception request to begin the approval process.'} emptyAction={hasFilters ? <Button variant="secondary" size="sm" onClick={resetFilters}>Clear filters</Button> : <Link className="button button--primary button--sm" to="/requests/new">Create request</Link>} /> : null}
      </section>
      {requestQuery.data ? <Pagination page={requestQuery.data.page || page} pages={requestQuery.data.pages} total={requestQuery.data.total} pageSize={requestQuery.data.page_size || pageSize} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} /> : null}
    </div>
  );
}
