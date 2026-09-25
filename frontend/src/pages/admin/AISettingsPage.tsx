import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Bot, Save, ShieldAlert, Sparkles } from 'lucide-react';
import { useEffect, useState, type FormEvent } from 'react';
import { Button, ErrorState, LoadingState, PageHeader, PageSection } from '../../components/common';
import { useToast } from '../../contexts/ToastContext';
import { apiRequest } from '../../lib/api';
import { formatDateTime } from '../../lib/format';
import type { AISettings } from '../../types/api';

const defaults: AISettings = { enabled: false, provider: '', model: '', data_retention_enabled: false, require_human_approval: true, prompt_version: '' };

export default function AISettingsPage() {
  const { showToast } = useToast();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<AISettings>(defaults);
  const query = useQuery({ queryKey: ['admin-ai-settings'], queryFn: () => apiRequest<AISettings>('/admin/ai-settings') });
  const mutation = useMutation({
    mutationFn: () => apiRequest<AISettings>('/admin/ai-settings', { method: 'PATCH', body: form }),
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ['admin-ai-settings'] }); showToast('AI assistance settings saved.', 'success'); },
  });
  useEffect(() => { if (query.data) setForm({ ...defaults, ...query.data, require_human_approval: query.data.require_human_approval ?? true }); }, [query.data]);
  const submit = (event: FormEvent) => { event.preventDefault(); mutation.mutate(); };
  if (query.isLoading) return <div className="page admin-page"><PageHeader eyebrow="Administration" title="AI settings" /><LoadingState rows={6} /></div>;
  if (query.isError) return <div className="page admin-page"><PageHeader eyebrow="Administration" title="AI settings" /><ErrorState error={query.error} onRetry={() => void query.refetch()} /></div>;
  return (
    <div className="page admin-page">
      <PageHeader eyebrow="Administration" title="AI assistance" description="Configure advisory request analysis. Human reviewers remain responsible for every decision." actions={<Button form="ai-settings-form" type="submit" loading={mutation.isPending}><Save size={17} />Save settings</Button>} />
      <form id="ai-settings-form" onSubmit={submit}>
        <div className="ai-policy-banner"><span><Bot size={24} /></span><div><strong>AI-generated assistance — human approval required</strong><p>AI may identify risk factors, missing information, and suggested next steps. It cannot approve, reject, request clarification, or record a governance decision.</p></div></div>
        <div className="settings-layout">
          <div><PageSection title="Availability" description="Control whether requesters and approvers may request analysis."><label className="switch-field"><input type="checkbox" checked={form.enabled} onChange={(event) => setForm({ ...form, enabled: event.target.checked })} /><span className="switch-control" aria-hidden="true" /><span><strong>Enable AI-generated assistance</strong><small>When disabled, analysis actions are hidden and existing generated output remains labeled as advisory.</small></span></label></PageSection>
            <PageSection title="Model configuration" description="Provider and model values are server-managed after validation."><div className="form-grid form-grid--2"><div className="field"><label htmlFor="ai-provider">Provider</label><input id="ai-provider" value={form.provider ?? ''} onChange={(event) => setForm({ ...form, provider: event.target.value })} placeholder="Configured by your administrator" /></div><div className="field"><label htmlFor="ai-model">Model</label><input id="ai-model" value={form.model ?? ''} onChange={(event) => setForm({ ...form, model: event.target.value })} placeholder="Model identifier" /></div><div className="field"><label htmlFor="prompt-version">Prompt version</label><input id="prompt-version" value={form.prompt_version ?? ''} onChange={(event) => setForm({ ...form, prompt_version: event.target.value })} placeholder="e.g. exception-analysis-v2" /></div></div></PageSection>
            <PageSection title="Data governance" description="Minimize sensitive data sent to external services and preserve human accountability."><label className="checkbox-field"><input type="checkbox" checked={form.require_human_approval} onChange={(event) => setForm({ ...form, require_human_approval: event.target.checked })} /><span><strong>Enforce human approval requirement</strong><small>UI and API responses must distinguish generated assistance from human decisions.</small></span></label><label className="checkbox-field"><input type="checkbox" checked={form.data_retention_enabled ?? false} onChange={(event) => setForm({ ...form, data_retention_enabled: event.target.checked })} /><span><strong>Allow provider-side retention</strong><small>Leave disabled unless your provider contract explicitly permits it.</small></span></label></PageSection>
            {mutation.isError ? <ErrorState error={mutation.error} title="AI settings were not saved" /> : null}
          </div>
          <aside className="settings-aside"><div className="settings-summary"><span className="settings-summary__icon"><Sparkles size={21} /></span><h2>Current status</h2><p className={`configuration-state ${form.enabled ? 'configuration-state--on' : ''}`}><i />{form.enabled ? 'Assistance enabled' : 'Assistance disabled'}</p><dl><div><dt>Provider</dt><dd>{form.provider || 'Not configured'}</dd></div><div><dt>Model</dt><dd>{form.model || 'Not configured'}</dd></div><div><dt>Last updated</dt><dd>{formatDateTime(query.data?.updated_at)}</dd></div></dl><div className="human-decision-note human-decision-note--compact"><ShieldAlert size={17} /><span>Generated output is never an approval.</span></div></div></aside>
        </div>
      </form>
    </div>
  );
}
