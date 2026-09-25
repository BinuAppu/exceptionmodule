import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { DatabaseBackup, Download, HardDrive, Plus, RotateCcw, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { Dialog } from '../../components/Dialog';
import { Button, EmptyState, ErrorState, LoadingState, PageHeader } from '../../components/common';
import { useToast } from '../../contexts/ToastContext';
import { apiRequest } from '../../lib/api';
import { formatDateTime, formatFileSize } from '../../lib/format';
import type { Backup } from '../../types/api';

export default function BackupsPage() {
  const { showToast } = useToast();
  const queryClient = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<Backup | null>(null);
  const [restoreTarget, setRestoreTarget] = useState<Backup | null>(null);
  const backupQuery = useQuery({ queryKey: ['admin-backups'], queryFn: () => apiRequest<Backup[]>('/admin/backups') });
  const createMutation = useMutation({
    mutationFn: () => apiRequest<Backup>('/admin/backups', { method: 'POST' }),
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ['admin-backups'] }); setCreateOpen(false); showToast('Backup creation started.', 'success'); },
  });
  const deleteMutation = useMutation({
    mutationFn: (backup: Backup) => apiRequest<void>(`/admin/backups/${backup.id}`, { method: 'DELETE' }),
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ['admin-backups'] }); setDeleteTarget(null); showToast('Backup deleted.', 'success'); },
  });
  const restoreMutation = useMutation({
    mutationFn: (backup: Backup) => apiRequest<void>(`/admin/backups/${backup.id}/restore`, { method: 'POST' }),
    onSuccess: () => { setRestoreTarget(null); showToast('Restore job has been queued. Monitor system notices for completion.', 'success'); },
  });
  return (
    <div className="page admin-page">
      <PageHeader eyebrow="Administration" title="Backups" description="Create, download, restore, and retain encrypted backup artifacts according to policy." actions={<Button onClick={() => setCreateOpen(true)}><Plus size={17} />Create backup</Button>} />
      <div className="backup-policy-note"><HardDrive size={18} /><p><strong>Backup operations are privileged.</strong> Every creation, download, restore, and deletion is written to the audit log.</p></div>
      <section className="content-surface">
        {backupQuery.isLoading ? <LoadingState label="Loading backups…" rows={6} /> : null}{backupQuery.isError ? <ErrorState error={backupQuery.error} onRetry={() => void backupQuery.refetch()} /> : null}
        {backupQuery.data?.length === 0 ? <EmptyState icon={<DatabaseBackup size={27} />} title="No backups available" description="Create a backup to establish a recoverable restore point." action={<Button onClick={() => setCreateOpen(true)}>Create first backup</Button>} /> : null}
        {backupQuery.data && backupQuery.data.length ? <div className="table-scroll"><table className="data-table"><thead><tr><th scope="col">Backup</th><th scope="col">Created</th><th scope="col">Status</th><th scope="col">Retention</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead><tbody>{backupQuery.data.map((backup) => <tr key={backup.id}><td data-label="Backup"><strong>{backup.filename}</strong><span className="table-secondary">{formatFileSize(backup.size)}{backup.created_by ? ` · ${backup.created_by.full_name}` : ''}</span></td><td data-label="Created">{formatDateTime(backup.created_at)}</td><td data-label="Status"><span className={`status-dot-label status-dot-label--${backup.status === 'completed' ? 'active' : backup.status === 'failed' ? 'inactive' : 'pending'}`}><i />{backup.status === 'in_progress' ? 'In progress' : backup.status === 'completed' ? 'Completed' : 'Failed'}</span></td><td data-label="Retention">{backup.retention_until ? `Until ${formatDateTime(backup.retention_until)}` : 'Policy managed'}</td><td className="row-actions"><a className="button button--ghost button--sm" href={`/api/admin/backups/${backup.id}/download`}><Download size={16} />Download</a><Button variant="ghost" size="sm" disabled={backup.status !== 'completed'} onClick={() => setRestoreTarget(backup)}><RotateCcw size={16} />Restore</Button><Button variant="ghost" size="sm" onClick={() => setDeleteTarget(backup)} aria-label={`Delete ${backup.filename}`}><Trash2 size={16} /></Button></td></tr>)}</tbody></table></div> : null}
      </section>
      <Dialog open={createOpen} title="Create a backup" description="A new encrypted backup artifact will be generated from the current system state." onClose={() => setCreateOpen(false)} footer={<><Button variant="secondary" onClick={() => setCreateOpen(false)}>Cancel</Button><Button loading={createMutation.isPending} onClick={() => createMutation.mutate()}><DatabaseBackup size={17} />Start backup</Button></>}><p>Keep the application available while the backup is created. Completion is recorded in the backup list and audit log.</p>{createMutation.isError ? <ErrorState error={createMutation.error} title="Backup could not be started" /> : null}</Dialog>
      <Dialog open={Boolean(restoreTarget)} title="Restore this backup?" description={restoreTarget?.filename} onClose={() => setRestoreTarget(null)} footer={<><Button variant="secondary" onClick={() => setRestoreTarget(null)}>Cancel</Button><Button variant="danger" loading={restoreMutation.isPending} onClick={() => restoreTarget && restoreMutation.mutate(restoreTarget)}><RotateCcw size={17} />Queue restore</Button></>}><div className="danger-confirmation"><RotateCcw size={24} /><p>Restoring replaces current system data with the selected backup. The backend must validate the restore token and create a safety restore point before applying changes.</p></div>{restoreMutation.isError ? <ErrorState error={restoreMutation.error} title="Restore was not queued" /> : null}</Dialog>
      <Dialog open={Boolean(deleteTarget)} title="Delete this backup?" description={deleteTarget?.filename} onClose={() => setDeleteTarget(null)} footer={<><Button variant="secondary" onClick={() => setDeleteTarget(null)}>Cancel</Button><Button variant="danger" loading={deleteMutation.isPending} onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget)}><Trash2 size={17} />Delete permanently</Button></>}><div className="danger-confirmation"><Trash2 size={24} /><p>Deleting a backup removes that restore point. This action cannot be undone.</p></div>{deleteMutation.isError ? <ErrorState error={deleteMutation.error} title="Backup was not deleted" /> : null}</Dialog>
    </div>
  );
}
