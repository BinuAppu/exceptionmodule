import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ChevronDown, ListChecks, Pencil, Plus } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { Dialog } from '../../components/Dialog';
import { Button, EmptyState, ErrorState, LoadingState, PageHeader } from '../../components/common';
import { useToast } from '../../contexts/ToastContext';
import { apiRequest } from '../../lib/api';
import { titleFromKey } from '../../lib/format';
import type { Category, UserRole, Workflow, WorkflowStage } from '../../types/api';

export default function WorkflowsPage() {
  const { showToast } = useToast();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<Workflow | null>(null);
  const [form, setForm] = useState({ name: '', description: '', category_id: '', is_default: false, is_active: true });
  const [stageWorkflow, setStageWorkflow] = useState<Workflow | null>(null);
  const [stageForm, setStageForm] = useState({ name: '', description: '', approver_role: 'approver' as UserRole | '' });
  const workflowQuery = useQuery({ queryKey: ['admin-workflows'], queryFn: () => apiRequest<Workflow[]>('/admin/workflows') });
  const categoryQuery = useQuery({ queryKey: ['admin-categories'], queryFn: () => apiRequest<Category[]>('/admin/categories') });
  const saveMutation = useMutation({
    mutationFn: () => apiRequest<Workflow>(editing ? `/admin/workflows/${editing.id}` : '/admin/workflows', { method: editing ? 'PATCH' : 'POST', body: { ...form, category_id: form.category_id || null } }),
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ['admin-workflows'] }); setOpen(false); showToast(editing ? 'Workflow updated.' : 'Workflow created.', 'success'); },
  });
  const stageMutation = useMutation({
    mutationFn: () => apiRequest<WorkflowStage>(`/admin/workflows/${stageWorkflow?.id}/stages`, { method: 'POST', body: { ...stageForm, approver_role: stageForm.approver_role || null } }),
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ['admin-workflows'] }); setStageWorkflow(null); setStageForm({ name: '', description: '', approver_role: 'approver' }); showToast('Approval stage added.', 'success'); },
  });
  const showCreate = () => { setEditing(null); setForm({ name: '', description: '', category_id: '', is_default: false, is_active: true }); setOpen(true); };
  const showEdit = (workflow: Workflow) => { setEditing(workflow); setForm({ name: workflow.name, description: workflow.description ?? '', category_id: workflow.category_id ?? '', is_default: workflow.is_default, is_active: workflow.is_active }); setOpen(true); };
  const showStage = (workflow: Workflow) => { setStageWorkflow(workflow); setStageForm({ name: '', description: '', approver_role: 'approver' }); };
  return (
    <div className="page admin-page">
      <PageHeader eyebrow="Administration" title="Workflows" description="Define the ordered human approval stages assigned to exception requests." actions={<Button onClick={showCreate}><Plus size={17} />New workflow</Button>} />
      <section className="content-surface">
        {workflowQuery.isLoading ? <LoadingState label="Loading workflows…" rows={5} /> : null}{workflowQuery.isError ? <ErrorState error={workflowQuery.error} onRetry={() => void workflowQuery.refetch()} /> : null}
        {workflowQuery.data?.length === 0 ? <EmptyState icon={<ListChecks size={27} />} title="No workflows configured" description="Create an approval workflow before submitting new exception requests." action={<Button onClick={showCreate}>Create workflow</Button>} /> : null}
        {workflowQuery.data && workflowQuery.data.length ? <div className="workflow-list">{workflowQuery.data.map((workflow) => <details className="workflow-row" key={workflow.id}><summary><div><span className="workflow-row__icon"><ListChecks size={19} /></span><div><strong>{workflow.name}</strong><small>{workflow.stages.length} stage{workflow.stages.length === 1 ? '' : 's'} · {workflow.is_default ? 'Default workflow' : 'Category workflow'}</small></div></div><div className="workflow-row__meta"><span className={`status-dot-label status-dot-label--${workflow.is_active ? 'active' : 'inactive'}`}><i />{workflow.is_active ? 'Active' : 'Inactive'}</span><ChevronDown size={18} aria-hidden="true" /></div></summary><div className="workflow-row__body"><p>{workflow.description ?? 'No workflow description provided.'}</p><ol className="workflow-stages">{workflow.stages.sort((a, b) => a.sequence - b.sequence).map((stage) => <li key={stage.id}><span>{stage.sequence}</span><div><strong>{stage.name}</strong><small>{stage.description ?? 'No stage guidance'}</small></div><span className="tag">{stage.approver_role ? titleFromKey(stage.approver_role) : `${stage.approver_ids?.length ?? 0} named approver${stage.approver_ids?.length === 1 ? '' : 's'}`}</span></li>)}</ol><div className="row-actions"><Button variant="secondary" size="sm" onClick={() => showStage(workflow)}><Plus size={16} />Add stage</Button><Button variant="ghost" size="sm" onClick={() => showEdit(workflow)}><Pencil size={16} />Edit workflow</Button></div></div></details>)}</div> : null}
      </section>
      <Dialog open={open} title={editing ? 'Edit workflow' : 'New workflow'} onClose={() => setOpen(false)} footer={<><Button variant="secondary" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" form="workflow-form" loading={saveMutation.isPending}>{editing ? 'Save workflow' : 'Create workflow'}</Button></>}>
        <form id="workflow-form" className="form-grid form-grid--2" onSubmit={(event: FormEvent) => { event.preventDefault(); saveMutation.mutate(); }}><div className="field field--span-2"><label htmlFor="workflow-name">Workflow name</label><input id="workflow-name" required value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></div><div className="field field--span-2"><label htmlFor="workflow-description">Description</label><textarea id="workflow-description" rows={3} value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} /></div><div className="field field--span-2"><label htmlFor="workflow-category">Category</label><select id="workflow-category" value={form.category_id} onChange={(event) => setForm({ ...form, category_id: event.target.value, is_default: event.target.value ? false : form.is_default })}><option value="">Use default workflow</option>{categoryQuery.data?.map((category) => <option value={category.id} key={category.id}>{category.name}</option>)}</select></div><label className="checkbox-field"><input type="checkbox" checked={form.is_default} disabled={Boolean(form.category_id)} onChange={(event) => setForm({ ...form, is_default: event.target.checked })} /><span><strong>Default workflow</strong><small>Used when no category workflow matches.</small></span></label><label className="checkbox-field"><input type="checkbox" checked={form.is_active} onChange={(event) => setForm({ ...form, is_active: event.target.checked })} /><span><strong>Active</strong></span></label>{saveMutation.isError ? <div className="field--span-2"><ErrorState error={saveMutation.error} title="Workflow could not be saved" /></div> : null}</form>
      </Dialog>
      <Dialog open={Boolean(stageWorkflow)} title={`Add stage to ${stageWorkflow?.name ?? ''}`} description="Stages run in sequence. Every stage requires an authorized human decision." onClose={() => setStageWorkflow(null)} footer={<><Button variant="secondary" onClick={() => setStageWorkflow(null)}>Cancel</Button><Button type="submit" form="stage-form" loading={stageMutation.isPending}>Add stage</Button></>}>
        <form id="stage-form" className="form-grid form-grid--2" onSubmit={(event: FormEvent) => { event.preventDefault(); stageMutation.mutate(); }}><div className="field field--span-2"><label htmlFor="stage-name">Stage name</label><input id="stage-name" required value={stageForm.name} onChange={(event) => setStageForm({ ...stageForm, name: event.target.value })} /></div><div className="field field--span-2"><label htmlFor="stage-description">Decision guidance</label><textarea id="stage-description" rows={3} value={stageForm.description} onChange={(event) => setStageForm({ ...stageForm, description: event.target.value })} /></div><div className="field field--span-2"><label htmlFor="stage-role">Eligible role</label><select id="stage-role" value={stageForm.approver_role} onChange={(event) => setStageForm({ ...stageForm, approver_role: event.target.value as UserRole | '' })}><option value="approver">Approver</option><option value="admin">Administrator</option></select></div>{stageMutation.isError ? <div className="field--span-2"><ErrorState error={stageMutation.error} title="Stage could not be added" /></div> : null}</form>
      </Dialog>
    </div>
  );
}
