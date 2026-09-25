import type { RequestStatus, RiskLevel } from '../types/api';

export const statusLabels: Record<RequestStatus, string> = {
  draft: 'Draft',
  submitted: 'Submitted',
  pending_manager_approval: 'Manager review',
  manager_approved: 'Manager approved',
  manager_rejected: 'Manager rejected',
  pending_delivery_head_approval: 'Delivery Head review',
  delivery_head_approved: 'Delivery Head approved',
  delivery_head_rejected: 'Delivery Head rejected',
  pending_approver_review: 'Exception review',
  clarification_required: 'Needs clarification',
  approved: 'Approved',
  rejected: 'Rejected',
  active: 'Active',
  extension_requested: 'Extension requested',
  extension_pending_approval: 'Extension review',
  expired: 'Expired',
  cancelled: 'Cancelled',
  withdrawn: 'Withdrawn',
  closed: 'Closed',
};

export const riskLabels: Record<RiskLevel, string> = {
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
};

export function formatDate(value?: string | null, options?: Intl.DateTimeFormatOptions): string {
  if (!value) return 'Not set';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Not set';
  return new Intl.DateTimeFormat(undefined, options ?? { dateStyle: 'medium' }).format(date);
}

export function formatDateTime(value?: string | null): string {
  return formatDate(value, { dateStyle: 'medium', timeStyle: 'short' });
}

export function formatRelativeDate(value?: string | null): string {
  if (!value) return 'Not set';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Not set';
  const deltaDays = Math.round((date.getTime() - Date.now()) / 86_400_000);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  if (Math.abs(deltaDays) < 31) return formatter.format(deltaDays, 'day');
  const deltaMonths = Math.round(deltaDays / 30.44);
  return formatter.format(deltaMonths, 'month');
}

export function formatFileSize(bytes?: number): string {
  if (bytes === undefined || bytes === null) return 'Size unavailable';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
}

export function initials(name?: string): string {
  if (!name) return '?';
  return name
    .split(/\s+/)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join('');
}

export function titleFromKey(value: string): string {
  return value
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function percentage(value: number, total: number): number {
  if (!total) return 0;
  return Math.round((value / total) * 100);
}
