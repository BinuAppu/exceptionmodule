import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Boxes, Pencil, Plus } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Dialog } from '../../components/Dialog';
import { Button, EmptyState, ErrorState, InlineError, LoadingState, PageHeader } from '../../components/common';
import { useToast } from '../../contexts/ToastContext';
import { apiRequest } from '../../lib/api';
import type { Category } from '../../types/api';

interface CategoryForm {
  code: string;
  name: string;
  description: string;
  default_duration_days: string;
  maximum_duration_days: string;
  display_order: number;
  active: boolean;
  reason: string;
}

const emptyForm: CategoryForm = { code: '', name: '', description: '', default_duration_days: '', maximum_duration_days: '', display_order: 100, active: true, reason: '' };

export default function CategoriesPage() {
  const { showToast } = useToast();
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState<Category | null>(null);
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<CategoryForm>(emptyForm);
  const [formError, setFormError] = useState<string | null>(null);
  const query = useQuery({ queryKey: ['admin-categories'], queryFn: () => apiRequest<Category[]>('/admin/categories') });
  const mutation = useMutation({
    mutationFn: () => {
      const common = {
        name: form.name.trim(),
        description: form.description.trim() || null,
        default_duration_days: form.default_duration_days ? Number(form.default_duration_days) : null,
        maximum_duration_days: form.maximum_duration_days ? Number(form.maximum_duration_days) : null,
        display_order: form.display_order,
      };
      return editing
        ? apiRequest(`/admin/categories/${editing.id}`, { method: 'PATCH', body: { expected_version: editing.version, ...common, is_active: form.active, reason: form.reason.trim() } })
        : apiRequest('/admin/categories', { method: 'POST', body: { code: form.code.trim(), ...common } });
    },
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ['admin-categories'] }); await queryClient.invalidateQueries({ queryKey: ['request-form-options'] }); setOpen(false); showToast(editing ? 'Category updated.' : 'Category created.', 'success'); },
    onError: (error) => setFormError(error instanceof Error ? error.message : 'Category could not be saved.'),
  });
  const showCreate = () => { setEditing(null); setForm(emptyForm); setFormError(null); setOpen(true); };
  const showEdit = (category: Category) => { setEditing(category); setForm({ code: category.code, name: category.name, description: category.description ?? '', default_duration_days: category.default_duration_days?.toString() ?? '', maximum_duration_days: category.maximum_duration_days?.toString() ?? '', display_order: category.display_order, active: category.active, reason: '' }); setFormError(null); setOpen(true); };
  const submit = (event: FormEvent) => { event.preventDefault(); setFormError(null); if (editing && form.reason.trim().length < 5) { setFormError('Enter a reason of at least 5 characters.'); return; } mutation.mutate(); };
  return (
    <div className="page admin-page">
      <PageHeader eyebrow="Administration" title="Categories" description="Maintain the controlled taxonomy used to classify exception requests and route workflows." actions={<Button onClick={showCreate}><Plus size={17} />Add category</Button>} />
      <section className="content-surface">
        {query.isLoading ? <LoadingState label="Loading categories…" rows={5} /> : null}
        {query.isError ? <ErrorState error={query.error} onRetry={() => void query.refetch()} /> : null}
        {query.data?.length === 0 ? <EmptyState icon={<Boxes size={27} />} title="No categories configured" description="Add a category before administrators define category-specific workflows." action={<Button onClick={showCreate}>Add first category</Button>} /> : null}
        {query.data?.length ? <div className="table-scroll"><table className="data-table"><thead><tr><th scope="col">Category</th><th scope="col">Description</th><th scope="col">Default period</th><th scope="col">Status</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead><tbody>{query.data.map((category) => <tr key={category.id}><td data-label="Category"><strong>{category.name}</strong><span className="table-secondary">{category.code}</span></td><td data-label="Description" className="table-wrap-text">{category.description ?? 'No description'}</td><td data-label="Default period">{category.default_duration_days ? `${category.default_duration_days} days` : 'Workflow default'}</td><td data-label="Status"><span className={`status-dot-label status-dot-label--${category.active ? 'active' : 'inactive'}`}><i />{category.active ? 'Active' : 'Inactive'}</span></td><td className="row-actions"><Button variant="ghost" size="sm" onClick={() => showEdit(category)}><Pencil size={16} />Edit</Button></td></tr>)}</tbody></table></div> : null}
      </section>
      <Dialog open={open} title={editing ? 'Edit category' : 'Add category'} onClose={() => setOpen(false)} footer={<><Button variant="secondary" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" form="category-form" loading={mutation.isPending}>{editing ? 'Save changes' : 'Create category'}</Button></>}>
        <form id="category-form" className="form-grid form-grid--2" onSubmit={submit}>
          {!editing ? <div className="field field--span-2"><label htmlFor="category-code">Stable code</label><input id="category-code" required pattern="^[a-z0-9_]+$" maxLength={80} value={form.code} onChange={(event) => setForm({ ...form, code: event.target.value })} placeholder="third_party_vendor" /></div> : null}
          <div className="field field--span-2"><label htmlFor="category-name">Name</label><input id="category-name" required minLength={2} maxLength={160} value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></div>
          <div className="field field--span-2"><label htmlFor="category-description">Description</label><textarea id="category-description" rows={4} value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} /></div>
          <div className="field"><label htmlFor="category-default-days">Default days</label><input id="category-default-days" type="number" min={1} max={3650} value={form.default_duration_days} onChange={(event) => setForm({ ...form, default_duration_days: event.target.value })} /></div>
          <div className="field"><label htmlFor="category-max-days">Maximum days</label><input id="category-max-days" type="number" min={1} max={3650} value={form.maximum_duration_days} onChange={(event) => setForm({ ...form, maximum_duration_days: event.target.value })} /></div>
          <div className="field"><label htmlFor="category-order">Display order</label><input id="category-order" type="number" min={0} max={10000} required value={form.display_order} onChange={(event) => setForm({ ...form, display_order: Number(event.target.value) })} /></div>
          {editing ? <label className="checkbox-field"><input type="checkbox" checked={form.active} onChange={(event) => setForm({ ...form, active: event.target.checked })} /><span><strong>Active</strong></span></label> : null}
          {editing ? <div className="field field--span-2"><label htmlFor="category-reason">Reason for change</label><textarea id="category-reason" rows={3} required minLength={5} maxLength={2000} value={form.reason} onChange={(event) => setForm({ ...form, reason: event.target.value })} /></div> : null}
          <div className="field--span-2"><InlineError message={formError ?? (mutation.error instanceof Error ? mutation.error.message : null)} /></div>
        </form>
      </Dialog>
    </div>
  );
}
