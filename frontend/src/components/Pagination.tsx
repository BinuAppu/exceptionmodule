import { ChevronLeft, ChevronRight } from 'lucide-react';
import { Button } from './common';

interface PaginationProps {
  page: number;
  pages: number;
  total: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  onPageSizeChange?: (size: number) => void;
}
export function Pagination({ page, pages, total, pageSize, onPageChange, onPageSizeChange }: PaginationProps) {
  if (total === 0) return null;
  const first = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const last = Math.min(page * pageSize, total);
  return (
    <nav className="pagination" aria-label="Pagination">
      <p>Showing <strong>{first}–{last}</strong> of <strong>{total}</strong></p>
      <div className="pagination__controls">
        {onPageSizeChange ? (
          <label className="pagination__size">Rows
            <select value={pageSize} onChange={(event) => onPageSizeChange(Number(event.target.value))}>
              {[10, 20, 50].map((size) => <option key={size} value={size}>{size}</option>)}
            </select>
          </label>
        ) : null}
        <Button variant="secondary" size="sm" disabled={page <= 1} onClick={() => onPageChange(page - 1)} aria-label="Previous page">
          <ChevronLeft size={17} />Previous
        </Button>
        <span>Page {page} of {Math.max(pages, 1)}</span>
        <Button variant="secondary" size="sm" disabled={page >= pages} onClick={() => onPageChange(page + 1)} aria-label="Next page">
          Next<ChevronRight size={17} />
        </Button>
      </div>
    </nav>
  );
}
