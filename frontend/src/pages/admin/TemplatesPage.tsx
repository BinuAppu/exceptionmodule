import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { BookTemplate, Copy, Pencil, Plus } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Dialog } from '../../components/Dialog';
import { Button, EmptyState, ErrorState, InlineError, LoadingState, PageHeader } from '../../components/common';
import { useToast } from '../../contexts/ToastContext';
import { apiRequest } from '../../lib/api';
import { formatDate } from '../../lib/format';
import type { Category, RequestTemplate } from '../../types/api';

interface TemplateForm { name: string; description: string; category_id: string; is_active: boolean; defaultsText: string }
const emptyForm: TemplateForm = { name: '', description: '', category_id: '', is_active: true, defaultsText: '{}' };

export default function TemplatesPage() {
  const { showToast } = useToast();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<RequestTemplate | null>(null);
  const [form, setForm] = useState<TemplateForm>(emptyForm);
  const [jsonError, setJsonError] = useState<string | null>(null);
  const templateQuery = useQuery({ queryKey: ['admin-templates'], queryFn: () => apiRequest<RequestTemplate[]>('/admin/templates') });
  const categoryQuery = useQuery({ queryKey: ['admin-categories'], queryFn: () => apiRequest<Category[]>('/admin/categories') });
  const mutation = useMutation({
    mutationFn: () => {
      const defaultValues: unknown = JSON.parse(form.defaultsText || '{}');
      if (!defaultValues || typeof defaultValues !== 'object' || Array.isArray(defaultValues)) throw new Error('Default values must be a JSON object.');
      return apiRequest<RequestTemplate>(editing ? `/admin/templates/${editing.id}` : '/admin/templates', { method: editing ? 'PATCH' : 'POST', body: { name: form.name, description: form.description, category_id: form.category_id || null, is_active: form.is_active, default_values: defaultValues } });
    },
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ['admin-templates'] }); setOpen(false); showToast(editing ? 'Template updated.' : 'Template created.', 'success'); },
  });
  const duplicateMutation = useMutation({
    mutationFn: (template: RequestTemplate) => apiRequest<RequestTemplate>(`/admin/templates/${template.id}/duplicate`, { method: 'POST' }),
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ['admin-templates'] }); showToast('Template duplicated.', 'success'); },
  });
  const showCreate = () => { setEditing(null); setForm(emptyForm); setJsonError(null); setOpen(true); };
  const showEdit = (template: RequestTemplate) => { setEditing(template); setForm({ name: template.name, description: template.description ?? '', category_id: template.category_id ?? '', is_active: template.is_active, defaultsText: JSON.stringify(template.default_values ?? {}, null, 2) }); setJsonError(null); setOpen(true); };
  const submit = (event: FormEvent) => { event.preventDefault(); setJsonError(null); mutation.mutate(undefined, { onError: (error) => setJsonError(error instanceof Error ? error.message : 'Template could not be saved.') }); };
  return (
    <div className="page admin-page">
      <PageHeader eyebrow="Administration" title="Request templates" description="Pre-approved starting points for recurring exception types. Templates never bypass review." actions={<Button onClick={showCreate}><Plus size={17} />New template</Button>} />
      <section className="content-surface">
        {templateQuery.isLoading ? <LoadingState label="Loading templates…" rows={5} /> : null}{templateQuery.isError ? <ErrorState error={templateQuery.error} onRetry={() => void templateQuery.refetch()} /> : null}
        {templateQuery.data?.length === 0 ? <EmptyState icon={<BookTemplate size={27} />} title="No request templates" description="Create a template to standardize evidence and common defaults for recurring requests." action={<Button onClick={showCreate}>Create template</Button>} /> : null}
        {templateQuery.data && templateQuery.data.length ? <div className="table-scroll"><table className="data-table"><thead><tr><th scope="col">Template</th><th scope="col">Category</th><th scope="col">Status</th><th scope="col">Updated</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead><tbody>{templateQuery.data.map((template) => <tr key={template.id}><td data-label="Template"><strong>{template.name}</strong><span className="table-secondary">{template.description ?? 'No description'}</span></td><td data-label="Category">{categoryQuery.data?.find((category) => category.id === template.category_id)?.name ?? 'All categories'}</td><td data-label="Status"><span className={`status-dot-label status-dot-label--${template.is_active ? 'active' : 'inactive'}`}><i />{template.is_active ? 'Active' : 'Inactive'}</span></td><td data-label="Updated">{formatDate(template.updated_at)}</td><td className="row-actions"><Button variant="ghost" size="sm" onClick={() => showEdit(template)}><Pencil size={16} />Edit</Button><Button variant="ghost" size="sm" onClick={() => duplicateMutation.mutate(template)} disabled={duplicateMutation.isPending}><Copy size={16} />Duplicate</Button></td></tr>)}</tbody></table></div> : null}
      </section>
      <Dialog open={open} title={editing ? 'Edit template' : 'New request template'} size="lg" onClose={() => setOpen(false)} footer={<><Button variant="secondary" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" form="template-form" loading={mutation.isPending}>{editing ? 'Save template' : 'Create template'}</Button></>}>
        <form id="template-form" className="form-grid form-grid--2" onSubmit={submit}><div className="field field--span-2"><label htmlFor="template-name">Template name</label><input id="template-name" required value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></div><div className="field field--span-2"><label htmlFor="template-description">Description</label><textarea id="template-description" rows={3} value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} /></div><div className="field field--span-2"><label htmlFor="template-category">Category</label><select id="template-category" value={form.category_id} onChange={(event) => setForm({ ...form, category_id: event.target.value })}><option value="">All categories</option>{categoryQuery.data?.filter((category) => category.active !== false).map((category) => <option value={category.id} key={category.id}>{category.name}</option>)}</select></div><div className="field field--span-2"><label htmlFor="template-defaults">Default values (JSON)</label><textarea id="template-defaults" className="code-input" rows={10} value={form.defaultsText} onChange={(event) => setForm({ ...form, defaultsText: event.target.value })} spellCheck={false} /><span className="field-help">Provide an object whose keys match request form fields. Sensitive values must not be stored here.</span></div><label className="checkbox-field field--span-2"><input type="checkbox" checked={form.is_active} onChange={(event) => setForm({ ...form, is_active: event.target.checked })} /><span><strong>Active</strong><small>Inactive templates cannot be selected for new requests.</small></span></label><div className="field--span-2"><InlineError message={jsonError} />{mutation.isError && !jsonError ? <ErrorState error={mutation.error} title="Template could not be saved" /> : null}</div></form>
      </Dialog>
    </div>
  );
}
