import { useQuery } from '@tanstack/react-query';
import { BarChart3, CalendarRange, Download, FileBarChart } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Button, EmptyState, ErrorState, LoadingState, PageHeader, PageSection } from '../components/common';
import { useAuth } from '../contexts/AuthContext';
import { useToast } from '../contexts/ToastContext';
import { apiRequest, toQuery } from '../lib/api';
import { formatDate, percentage, riskLabels, statusLabels } from '../lib/format';
import type { ReportSummary } from '../types/api';

export default function ReportsPage() {
  const { hasRole } = useAuth();
  const { showToast } = useToast();
  const today = new Date();
  const thirtyDaysAgo = new Date(today); thirtyDaysAgo.setDate(today.getDate() - 30);
  const [startDate, setStartDate] = useState(localDate(thirtyDaysAgo));
  const [endDate, setEndDate] = useState(localDate(today));
  const [filters, setFilters] = useState({ startDate, endDate });
  const [exporting, setExporting] = useState(false);
  const enabled = hasRole('approver', 'admin');

  const reportQuery = useQuery({
    queryKey: ['report', filters],
    queryFn: () => apiRequest<ReportSummary>('/reports/summary', { query: toQuery({ start_date: filters.startDate, end_date: filters.endDate }) }),
    enabled,
  });

  if (!enabled) return <div className="page"><PageHeader title="Reports" /><EmptyState icon={<FileBarChart size={27} />} title="Report access required" description="Your account does not have permission to view organization reports." /></div>;

  const applyFilters = (event: FormEvent) => {
    event.preventDefault();
    if (new Date(endDate) < new Date(startDate)) { showToast('End date must be on or after the start date.', 'error'); return; }
    setFilters({ startDate, endDate });
  };
  const exportReport = async () => {
    setExporting(true);
    try {
      const response = await fetch(`/api/reports/export?start_date=${encodeURIComponent(filters.startDate)}&end_date=${encodeURIComponent(filters.endDate)}`, { credentials: 'include' });
      if (!response.ok) throw new Error('Report export failed');
      const contentType = response.headers.get('content-type') ?? '';
      if (!contentType.includes('text/csv') || !response.headers.get('content-disposition')) {
        throw new Error('The server did not return a valid CSV export.');
      }
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a'); link.href = url; link.download = `exception-report-${filters.startDate}-to-${filters.endDate}.csv`; document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(url);
      showToast('Report export downloaded.', 'success');
    } catch (error) { showToast(error instanceof Error ? error.message : 'Report export failed.', 'error'); }
    finally { setExporting(false); }
  };

  const report = reportQuery.data;
  const maxCategory = Math.max(1, ...(report?.category_breakdown ?? []).map((item) => item.count));
  const maxMonthly = Math.max(1, ...(report?.monthly_volume ?? []).map((item) => item.count));
  return (
    <div className="page reports-page">
      <PageHeader eyebrow="Governance insights" title="Reports" description="Operational exception reporting based on completed decisions and current request records." actions={<Button variant="secondary" onClick={() => void exportReport()} loading={exporting}><Download size={17} />Export CSV</Button>} />
      <form className="report-filters" onSubmit={applyFilters}><div className="report-filters__label"><CalendarRange size={19} /><span><strong>Reporting period</strong><small>Dates use your organization’s configured time zone.</small></span></div><div className="field field--compact"><label htmlFor="report-start">From</label><input id="report-start" type="date" value={startDate} max={endDate} onChange={(event) => setStartDate(event.target.value)} /></div><div className="field field--compact"><label htmlFor="report-end">To</label><input id="report-end" type="date" value={endDate} min={startDate} onChange={(event) => setEndDate(event.target.value)} /></div><Button type="submit" variant="secondary">Apply</Button></form>
      {reportQuery.isLoading ? <LoadingState label="Calculating report…" rows={7} /> : null}
      {reportQuery.isError ? <ErrorState error={reportQuery.error} onRetry={() => void reportQuery.refetch()} title="Report could not be generated" /> : null}
      {report ? <>
        <div className="report-period"><p>Showing <strong>{formatDate(report.period_start)} – {formatDate(report.period_end)}</strong></p><span>Counts reflect your report access scope</span></div>
        <section className="report-metrics" aria-label="Report totals">
          <div><span>Total requests</span><strong>{report.total_requests}</strong></div><div><span>Approved</span><strong>{report.approved}</strong></div><div><span>Rejected</span><strong>{report.rejected}</strong></div><div><span>Pending</span><strong>{report.pending}</strong></div><div><span>Overdue</span><strong className={report.overdue ? 'text-danger' : ''}>{report.overdue}</strong></div><div><span>Median decision time</span><strong>{report.median_approval_days ?? '—'}{report.median_approval_days !== null && report.median_approval_days !== undefined ? <small> days</small> : null}</strong></div>
        </section>
        {report.total_requests === 0 ? <PageSection><EmptyState icon={<BarChart3 size={27} />} title="No requests in this period" description="Choose a different reporting period or wait for exception activity to be recorded." /></PageSection> : <div className="report-grid">
          <PageSection title="Status breakdown" description="Current disposition of requests created in this period." className="report-grid__wide"><BarList data={report.status_breakdown.map((item) => ({ label: statusLabels[item.status], value: item.count }))} total={report.total_requests} /></PageSection>
          <PageSection title="Risk profile" description="Requests by inherent risk level."><BarList data={report.risk_breakdown.map((item) => ({ label: riskLabels[item.risk], value: item.count }))} total={report.total_requests} /></PageSection>
          <PageSection title="Requests by category" description="Where exceptions are being raised." className="report-grid__wide"><BarList data={report.category_breakdown.map((item) => ({ label: item.category, value: item.count }))} total={report.total_requests} max={maxCategory} /></PageSection>
          <PageSection title="Department volume" description="Distribution across business units." className="report-grid__wide"><BarList data={report.department_breakdown.map((item) => ({ label: item.department, value: item.count }))} total={report.total_requests} /></PageSection>
          <PageSection title="Monthly volume" description="Requests created and approved by month." className="report-grid__wide"><div className="monthly-bars">{report.monthly_volume.length ? report.monthly_volume.map((item) => <div className="monthly-bar" key={item.month}><div className="monthly-bar__columns"><span title={`${item.count} requests`} style={{ height: `${Math.max((item.count / maxMonthly) * 100, item.count ? 6 : 1)}%` }} /><span className="monthly-bar__approved" title={`${item.approved} approved`} style={{ height: `${Math.max((item.approved / maxMonthly) * 100, item.approved ? 6 : 1)}%` }} /></div><strong>{item.count}</strong><small>{new Intl.DateTimeFormat(undefined, { month: 'short', year: '2-digit' }).format(new Date(`${item.month}-01`))}</small></div>) : <p className="muted-text">No monthly data available.</p>}</div><div className="chart-legend"><span><i className="legend-total" />Created</span><span><i className="legend-approved" />Approved</span></div></PageSection>
        </div>}
      </> : null}
    </div>
  );
}

function localDate(value: Date): string {
  const year = value.getFullYear();
  const month = String(value.getMonth() + 1).padStart(2, '0');
  const day = String(value.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function BarList({ data, total, max }: { data: Array<{ label: string; value: number }>; total: number; max?: number }) {
  if (!data.length) return <p className="muted-text">No breakdown data available.</p>;
  const maximum = max ?? Math.max(1, ...data.map((item) => item.value));
  return <div className="bar-list">{data.map((item) => <div className="bar-list__row" key={item.label}><div><span>{item.label}</span><strong>{item.value}<small>{percentage(item.value, total)}%</small></strong></div><div className="progress-track"><span style={{ width: `${Math.max((item.value / maximum) * 100, item.value ? 3 : 0)}%` }} /></div></div>)}</div>;
}
