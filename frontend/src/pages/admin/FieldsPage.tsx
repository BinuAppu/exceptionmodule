import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Pencil, Plus, SlidersHorizontal } from 'lucide-react';
import { useMemo, useState, type FormEvent } from 'react';
import { Dialog } from '../../components/Dialog';
import { Button, EmptyState, ErrorState, InlineError, LoadingState, PageHeader } from '../../components/common';
import { useToast } from '../../contexts/ToastContext';
import { apiRequest } from '../../lib/api';
import { titleFromKey } from '../../lib/format';
import type { AdminField, AdminFieldDataType, UserRole } from '../../types/api';

interface FieldForm {
  field_key: string;
  label: string;
  description: string;
  data_type: AdminFieldDataType;
  is_required: boolean;
  default_value: string;
  placeholder: string;
  allowed_values: string;
  visible_roles: UserRole[];
  display_order: number;
  is_active: boolean;
  reason: string;
}

const emptyForm: FieldForm = {
  field_key: '',
  label: '',
  description: '',
  data_type: 'text',
  is_required: false,
  default_value: '',
  placeholder: '',
  allowed_values: '',
  visible_roles: ['user', 'approver', 'admin'],
  display_order: 100,
  is_active: true,
  reason: '',
};

const dataTypes: Array<{ value: AdminFieldDataType; label: string }> = [
  { value: 'text', label: 'Short text' },
  { value: 'long_text', label: 'Long text' },
  { value: 'number', label: 'Number' },
  { value: 'date', label: 'Date' },
  { value: 'datetime', label: 'Date and time' },
  { value: 'boolean', label: 'Checkbox' },
  { value: 'dropdown', label: 'Single select' },
  { value: 'multi_select', label: 'Multiple select' },
  { value: 'user_selector', label: 'User selector' },
  { value: 'application_selector', label: 'Application selector' },
  { value: 'attachment', label: 'Attachment reference' },
  { value: 'url', label: 'URL' },
];

const roleOptions: Array<{ value: UserRole; label: string }> = [
  { value: 'user', label: 'Requester' },
  { value: 'approver', label: 'Approver' },
  { value: 'admin', label: 'Administrator' },
];

function parseAllowedValues(text: string): string[] {
  return text.split('\n').map((line) => line.trim()).filter(Boolean);
}

export default function FieldsPage() {
  const { showToast } = useToast();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<AdminField | null>(null);
  const [form, setForm] = useState<FieldForm>(emptyForm);
  const [formError, setFormError] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ['admin-fields'],
    queryFn: () => apiRequest<AdminField[]>('/admin/fields'),
  });

  const mutation = useMutation({
    mutationFn: () => {
      if (editing ? form.reason.trim().length < 5 : !form.field_key.trim()) {
        throw new Error(editing ? 'Enter a reason of at least 5 characters.' : 'A stable field key is required.');
      }
      const values = {
        label: form.label.trim(),
        description: form.description.trim() || null,
        is_required: form.is_required,
        default_value: parseDefaultValue(form.default_value, form.data_type),
        placeholder: form.placeholder.trim() || null,
        allowed_values: parseAllowedValues(form.allowed_values),
        visible_roles: form.visible_roles,
        display_order: form.display_order,
      };
      if (editing) {
        return apiRequest<{ id: string; version: number; active: boolean }>(`/admin/fields/${editing.id}`, {
          method: 'PATCH',
          body: { expected_version: editing.version, ...values, is_active: form.is_active, reason: form.reason.trim() },
        });
      }
      return apiRequest<{ id: string; version: number }>('/admin/fields', {
        method: 'POST',
        body: { field_key: form.field_key.trim(), data_type: form.data_type, ...values },
      });
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['admin-fields'] });
      await queryClient.invalidateQueries({ queryKey: ['request-form-options'] });
      setOpen(false);
      showToast(editing ? 'Custom field updated.' : 'Custom field created.', 'success');
    },
    onError: (error) => setFormError(error instanceof Error ? error.message : 'Field could not be saved.'),
  });

  const fields = useMemo(() => [...(query.data ?? [])].sort((a, b) => a.display_order - b.display_order || a.label.localeCompare(b.label)), [query.data]);

  const showCreate = () => {
    setEditing(null);
    setForm(emptyForm);
    setFormError(null);
    setOpen(true);
  };

  const showEdit = (field: AdminField) => {
    setEditing(field);
    setForm({
      field_key: field.key,
      label: field.label,
      description: field.description ?? '',
      data_type: field.data_type,
      is_required: field.required,
      default_value: field.default_value == null ? '' : String(field.default_value),
      placeholder: field.placeholder ?? '',
      allowed_values: field.allowed_values.map(String).join('\n'),
      visible_roles: field.visible_roles.filter((role): role is UserRole => role === 'user' || role === 'approver' || role === 'admin'),
      display_order: field.display_order,
      is_active: field.active,
      reason: '',
    });
    setFormError(null);
    setOpen(true);
  };

  const toggleRole = (role: UserRole) => setForm((current) => ({
    ...current,
    visible_roles: current.visible_roles.includes(role)
      ? current.visible_roles.filter((item) => item !== role)
      : [...current.visible_roles, role],
  }));

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setFormError(null);
    if (!form.label.trim()) {
      setFormError('Field label is required.');
      return;
    }
    if (['dropdown', 'multi_select'].includes(form.data_type) && parseAllowedValues(form.allowed_values).length === 0) {
      setFormError('Select fields require at least one allowed value.');
      return;
    }
    mutation.mutate();
  };

  return (
    <div className="page admin-page">
      <PageHeader eyebrow="Administration" title="Custom fields" description="Add controlled organization-specific information to request forms without changing workflow code." actions={<Button onClick={showCreate}><Plus size={17} />Add field</Button>} />
      <section className="content-surface">
        {query.isLoading ? <LoadingState label="Loading custom fields…" rows={5} /> : null}
        {query.isError ? <ErrorState error={query.error} onRetry={() => void query.refetch()} /> : null}
        {fields.length === 0 ? <EmptyState icon={<SlidersHorizontal size={27} />} title="No custom fields" description="The standard request form is currently used without additional fields." action={<Button onClick={showCreate}>Add custom field</Button>} /> : null}
        {fields.length ? (
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th scope="col">Field</th><th scope="col">Type</th><th scope="col">Visible to</th><th scope="col">Required</th><th scope="col">Status</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>{fields.map((field) => (
                <tr key={field.id}>
                  <td data-label="Field"><strong>{field.label}</strong><span className="table-secondary">{field.key}</span></td>
                  <td data-label="Type">{titleFromKey(field.data_type)}</td>
                  <td data-label="Visible to">{field.visible_roles.length ? field.visible_roles.map(titleFromKey).join(', ') : 'All roles'}</td>
                  <td data-label="Required">{field.required ? 'Yes' : 'No'}</td>
                  <td data-label="Status"><span className={`status-dot-label status-dot-label--${field.active ? 'active' : 'inactive'}`}><i />{field.active ? 'Active' : 'Inactive'}</span></td>
                  <td className="row-actions"><Button variant="ghost" size="sm" onClick={() => showEdit(field)}><Pencil size={16} />Edit</Button></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        ) : null}
      </section>

      <Dialog open={open} title={editing ? 'Edit custom field' : 'Add custom field'} size="lg" description="Field changes apply to new and draft requests; historical values remain intact." onClose={() => setOpen(false)} footer={<><Button variant="secondary" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" form="field-form" loading={mutation.isPending}>{editing ? 'Save field' : 'Create field'}</Button></>}>
        <form id="field-form" className="form-grid form-grid--2" onSubmit={submit}>
          {!editing ? <div className="field field--span-2"><label htmlFor="field-key">Stable field key</label><input id="field-key" required pattern="^[a-z][a-z0-9_]{1,98}[a-z0-9]$" value={form.field_key} onChange={(event) => setForm({ ...form, field_key: event.target.value })} placeholder="cost_center" /><span className="field-help">Lowercase letters, numbers, and underscores; cannot be changed later.</span></div> : null}
          <div className="field field--span-2"><label htmlFor="field-label">Field label</label><input id="field-label" required minLength={2} maxLength={160} value={form.label} onChange={(event) => setForm({ ...form, label: event.target.value })} /></div>
          <div className="field"><label htmlFor="field-type">Field type</label><select id="field-type" value={form.data_type} disabled={Boolean(editing)} onChange={(event) => setForm({ ...form, data_type: event.target.value as AdminFieldDataType })}>{dataTypes.map((type) => <option value={type.value} key={type.value}>{type.label}</option>)}</select>{editing ? <span className="field-help">The stored value type cannot be changed after creation.</span> : null}</div>
          <div className="field"><label htmlFor="field-order">Display order</label><input id="field-order" type="number" min={0} max={10000} required value={form.display_order} onChange={(event) => setForm({ ...form, display_order: Number(event.target.value) })} /></div>
          <div className="field field--span-2"><label htmlFor="field-description">Help text</label><textarea id="field-description" rows={3} maxLength={2000} value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} /></div>
          <div className="field"><label htmlFor="field-placeholder">Placeholder</label><input id="field-placeholder" maxLength={255} value={form.placeholder} onChange={(event) => setForm({ ...form, placeholder: event.target.value })} /></div>
          <div className="field"><label htmlFor="field-default">Default value</label><input id="field-default" value={form.default_value} onChange={(event) => setForm({ ...form, default_value: event.target.value })} /></div>
          {['dropdown', 'multi_select'].includes(form.data_type) ? <div className="field field--span-2"><label htmlFor="field-options">Allowed values</label><textarea id="field-options" rows={5} value={form.allowed_values} onChange={(event) => setForm({ ...form, allowed_values: event.target.value })} placeholder="One value per line" /></div> : null}
          <fieldset className="field field--span-2 choice-fieldset"><legend>Visible roles</legend><div className="checkbox-grid">{roleOptions.map((role) => <label className="checkbox-field" key={role.value}><input type="checkbox" checked={form.visible_roles.includes(role.value)} onChange={() => toggleRole(role.value)} /><span><strong>{role.label}</strong></span></label>)}</div></fieldset>
          <label className="checkbox-field"><input type="checkbox" checked={form.is_required} onChange={(event) => setForm({ ...form, is_required: event.target.checked })} /><span><strong>Required field</strong></span></label>
          {editing ? <label className="checkbox-field"><input type="checkbox" checked={form.is_active} onChange={(event) => setForm({ ...form, is_active: event.target.checked })} /><span><strong>Active</strong></span></label> : null}
          {editing ? <div className="field field--span-2"><label htmlFor="field-reason">Reason for change</label><textarea id="field-reason" rows={3} required minLength={5} maxLength={2000} value={form.reason} onChange={(event) => setForm({ ...form, reason: event.target.value })} /></div> : null}
          <div className="field--span-2"><InlineError message={formError ?? (mutation.error instanceof Error ? mutation.error.message : null)} /></div>
        </form>
      </Dialog>
    </div>
  );
}

function parseDefaultValue(value: string, dataType: AdminFieldDataType): unknown {
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (dataType === 'number') {
    const number = Number(trimmed);
    return Number.isFinite(number) ? number : trimmed;
  }
  if (dataType === 'boolean') return trimmed.toLowerCase() === 'true';
  return trimmed;
}
