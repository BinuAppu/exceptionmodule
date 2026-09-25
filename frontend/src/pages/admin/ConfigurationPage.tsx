import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Building2, Save, SlidersHorizontal } from 'lucide-react';
import { useEffect, useState, type FormEvent } from 'react';
import { Button, ErrorState, LoadingState, PageHeader, PageSection } from '../../components/common';
import { useToast } from '../../contexts/ToastContext';
import { apiRequest } from '../../lib/api';
import { formatDateTime } from '../../lib/format';
import type { AppSettings } from '../../types/api';

type SettingsForm = Omit<AppSettings, 'updated_at'>;
const defaults: SettingsForm = { organization_name: '', support_email: '', default_review_days: 5, default_exception_days: 30, reminder_days_before_expiry: 7, require_mfa_for_approvers: true, session_timeout_minutes: 30, password_policy: {} };

export default function ConfigurationPage() {
  const { showToast } = useToast();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<SettingsForm>(defaults);
  const settingsQuery = useQuery({ queryKey: ['admin-settings'], queryFn: () => apiRequest<AppSettings>('/admin/settings') });
  const saveMutation = useMutation({
    mutationFn: () => apiRequest<AppSettings>('/admin/settings', { method: 'PATCH', body: form }),
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ['admin-settings'] }); showToast('Organization configuration saved.', 'success'); },
  });
  useEffect(() => { if (settingsQuery.data) setForm({ organization_name: settingsQuery.data.organization_name, support_email: settingsQuery.data.support_email ?? '', default_review_days: settingsQuery.data.default_review_days, default_exception_days: settingsQuery.data.default_exception_days, reminder_days_before_expiry: settingsQuery.data.reminder_days_before_expiry, require_mfa_for_approvers: settingsQuery.data.require_mfa_for_approvers, session_timeout_minutes: settingsQuery.data.session_timeout_minutes, password_policy: settingsQuery.data.password_policy ?? {} }); }, [settingsQuery.data]);
  const submit = (event: FormEvent) => { event.preventDefault(); saveMutation.mutate(); };

  if (settingsQuery.isLoading) return <div className="page admin-page"><PageHeader eyebrow="Administration" title="Configuration" /><LoadingState rows={7} /></div>;
  if (settingsQuery.isError) return <div className="page admin-page"><PageHeader eyebrow="Administration" title="Configuration" /><ErrorState error={settingsQuery.error} onRetry={() => void settingsQuery.refetch()} /></div>;
  return (
    <div className="page admin-page">
      <PageHeader eyebrow="Administration" title="Configuration" description="Organization-wide defaults for reviews, exception periods, and account policy." actions={<Button form="settings-form" type="submit" loading={saveMutation.isPending}><Save size={17} />Save changes</Button>} />
      <form id="settings-form" onSubmit={submit} className="settings-layout">
        <div>
          <PageSection title="Organization" description="Displayed in user-facing notices and system communication."><div className="form-grid form-grid--2"><div className="field"><label htmlFor="org-name">Organization name</label><input id="org-name" required value={form.organization_name} onChange={(event) => setForm({ ...form, organization_name: event.target.value })} /></div><div className="field"><label htmlFor="support-email">Support email</label><input id="support-email" type="email" value={form.support_email} onChange={(event) => setForm({ ...form, support_email: event.target.value })} /></div></div></PageSection>
          <PageSection title="Request defaults" description="Starting values proposed on new request forms."><div className="form-grid form-grid--3"><div className="field"><label htmlFor="review-days">Review due (days)</label><input id="review-days" type="number" min={1} max={90} required value={form.default_review_days} onChange={(event) => setForm({ ...form, default_review_days: Number(event.target.value) })} /></div><div className="field"><label htmlFor="exception-days">Exception period (days)</label><input id="exception-days" type="number" min={1} max={365} required value={form.default_exception_days} onChange={(event) => setForm({ ...form, default_exception_days: Number(event.target.value) })} /></div><div className="field"><label htmlFor="reminder-days">Expiry reminder (days)</label><input id="reminder-days" type="number" min={0} max={90} required value={form.reminder_days_before_expiry} onChange={(event) => setForm({ ...form, reminder_days_before_expiry: Number(event.target.value) })} /></div></div></PageSection>
          <PageSection title="Account policy" description="Security defaults enforced for local accounts and approvers."><div className="form-grid form-grid--2"><div className="field"><label htmlFor="session-timeout">Session timeout (minutes)</label><input id="session-timeout" type="number" min={5} max={480} required value={form.session_timeout_minutes} onChange={(event) => setForm({ ...form, session_timeout_minutes: Number(event.target.value) })} /></div><label className="checkbox-field"><input type="checkbox" checked={form.require_mfa_for_approvers} onChange={(event) => setForm({ ...form, require_mfa_for_approvers: event.target.checked })} /><span><strong>Require MFA for approvers</strong><small>Applies to users with approval responsibilities.</small></span></label></div></PageSection>
          {saveMutation.isError ? <ErrorState error={saveMutation.error} title="Settings were not saved" /> : null}
        </div>
        <aside className="settings-aside"><div className="settings-summary"><span className="settings-summary__icon"><Building2 size={21} /></span><h2>Configuration status</h2><dl><div><dt>Organization</dt><dd>{form.organization_name || 'Not set'}</dd></div><div><dt>Last updated</dt><dd>{formatDateTime(settingsQuery.data?.updated_at)}</dd></div><div><dt>Policy scope</dt><dd>All new requests</dd></div></dl><p><SlidersHorizontal size={16} />Changes affect defaults, not existing requests.</p></div></aside>
      </form>
    </div>
  );
}
