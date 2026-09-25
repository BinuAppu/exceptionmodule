import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Pencil, Search, ShieldCheck, UserRound } from 'lucide-react';
import { useDeferredValue, useMemo, useState, type FormEvent } from 'react';
import { Dialog } from '../../components/Dialog';
import { Pagination } from '../../components/Pagination';
import { Button, EmptyState, ErrorState, InlineError, LoadingState, PageHeader } from '../../components/common';
import { useToast } from '../../contexts/ToastContext';
import { apiRequest, toQuery } from '../../lib/api';
import { formatDateTime, initials, titleFromKey } from '../../lib/format';
import type { AdminUser, Paginated, UserRole } from '../../types/api';

interface UserForm {
  display_name: string;
  department: string;
  job_title: string;
  status: AdminUser['status'];
  roles: UserRole[];
  reason: string;
  reauthPassword: string;
}

const roleOptions: Array<{ value: UserRole; label: string }> = [
  { value: 'user', label: 'Requester' },
  { value: 'approver', label: 'Approver' },
  { value: 'admin', label: 'Administrator' },
];

const statusLabels: Record<AdminUser['status'], string> = {
  active: 'Active',
  disabled: 'Disabled',
  locked: 'Locked',
};

function sameRoles(left: UserRole[], right: UserRole[]): boolean {
  return [...left].sort().join('|') === [...right].sort().join('|');
}

export default function UsersPage() {
  const { showToast } = useToast();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState('');
  const deferredSearch = useDeferredValue(search.trim());
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [editingUser, setEditingUser] = useState<AdminUser | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [form, setForm] = useState<UserForm>({
    display_name: '',
    department: '',
    job_title: '',
    status: 'active',
    roles: ['user'],
    reason: '',
    reauthPassword: '',
  });

  const usersQuery = useQuery({
    queryKey: ['admin-users', { search: deferredSearch, page, pageSize }],
    queryFn: () => apiRequest<Paginated<AdminUser>>('/admin/users', {
      query: toQuery({ search: deferredSearch, page, page_size: pageSize }),
    }),
  });

  const saveMutation = useMutation({
    mutationFn: () => {
      if (!editingUser) throw new Error('No user is selected.');
      const rolesChanged = !sameRoles(form.roles, editingUser.roles);
      if (rolesChanged && !form.reauthPassword) {
        throw new Error('Re-enter your current password to change application roles.');
      }
      return apiRequest<AdminUser>(`/admin/users/${editingUser.id}`, {
        method: 'PATCH',
        headers: rolesChanged ? { 'X-Reauthentication-Password': form.reauthPassword } : undefined,
        body: {
          expected_version: editingUser.version,
          display_name: form.display_name.trim(),
          department: form.department.trim() || null,
          job_title: form.job_title.trim() || null,
          status: form.status,
          roles: rolesChanged ? form.roles : undefined,
          reason: form.reason.trim(),
        },
      });
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['admin-users'] });
      setEditingUser(null);
      showToast('User changes saved.', 'success');
    },
    onError: (error) => setFormError(error instanceof Error ? error.message : 'User changes could not be saved.'),
  });

  const openEdit = (user: AdminUser) => {
    setEditingUser(user);
    setForm({
      display_name: user.display_name,
      department: user.department ?? '',
      job_title: user.job_title ?? '',
      status: user.status,
      roles: [...user.roles],
      reason: '',
      reauthPassword: '',
    });
    setFormError(null);
  };

  const toggleRole = (role: UserRole) => {
    setForm((current) => ({
      ...current,
      roles: current.roles.includes(role)
        ? current.roles.filter((item) => item !== role)
        : [...current.roles, role],
    }));
  };

  const rolesChanged = useMemo(
    () => Boolean(editingUser && !sameRoles(form.roles, editingUser.roles)),
    [editingUser, form.roles],
  );

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setFormError(null);
    if (form.roles.length === 0) {
      setFormError('At least one application role is required.');
      return;
    }
    if (form.reason.trim().length < 5) {
      setFormError('Enter a reason of at least 5 characters for the audit trail.');
      return;
    }
    saveMutation.mutate();
  };

  return (
    <div className="page admin-page">
      <PageHeader
        eyebrow="Administration"
        title="Users"
        description="Review provisioned identities, application roles, and access status. Federated users are created by a validated SSO sign-in."
      />
      <section className="filter-panel filter-panel--admin" aria-label="User filters">
        <div className="search-field">
          <Search size={18} aria-hidden="true" />
          <label className="sr-only" htmlFor="user-search">Search users</label>
          <input
            id="user-search"
            type="search"
            value={search}
            onChange={(event) => { setSearch(event.target.value); setPage(1); }}
            placeholder="Search name, email, or public user ID"
          />
        </div>
      </section>
      <section className="content-surface" aria-label="Users" aria-busy={usersQuery.isLoading}>
        {usersQuery.isLoading ? <LoadingState label="Loading users…" rows={7} /> : null}
        {usersQuery.isError ? <ErrorState error={usersQuery.error} onRetry={() => void usersQuery.refetch()} /> : null}
        {usersQuery.data?.items.length === 0 ? <EmptyState icon={<UserRound size={27} />} title="No users found" description="No identities match the current search." /> : null}
        {usersQuery.data?.items.length ? (
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th scope="col">User</th><th scope="col">Roles</th><th scope="col">Status</th><th scope="col">Identity</th><th scope="col">Last sign-in</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>{usersQuery.data.items.map((user) => (
                <tr key={user.id}>
                  <td data-label="User"><div className="identity-cell"><span className="avatar avatar--small">{initials(user.display_name)}</span><span><strong>{user.display_name}</strong><small>{user.email} · {user.public_id}</small></span></div></td>
                  <td data-label="Roles"><div className="tag-list">{user.roles.map((role) => <span className="tag" key={role}>{titleFromKey(role)}</span>)}</div></td>
                  <td data-label="Status"><span className={`status-dot-label status-dot-label--${user.status === 'active' ? 'active' : 'inactive'}`}><i />{statusLabels[user.status]}</span></td>
                  <td data-label="Identity">{user.is_break_glass ? <span className="tag"><ShieldCheck size={13} />Break-glass</span> : <span className="muted-text">Federated / provisioned</span>}</td>
                  <td data-label="Last sign-in">{formatDateTime(user.last_login_at)}</td>
                  <td className="row-actions"><Button variant="ghost" size="sm" onClick={() => openEdit(user)} aria-label={`Edit ${user.display_name}`}><Pencil size={16} />Edit</Button></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        ) : null}
      </section>
      {usersQuery.data ? <Pagination page={usersQuery.data.page} pages={usersQuery.data.pages} total={usersQuery.data.total} pageSize={usersQuery.data.page_size} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} /> : null}

      <Dialog
        open={Boolean(editingUser)}
        title="Edit user"
        description="Changes are version-checked and recorded in the audit trail."
        onClose={() => { if (!saveMutation.isPending) setEditingUser(null); }}
        footer={<><Button variant="secondary" onClick={() => setEditingUser(null)}>Cancel</Button><Button type="submit" form="user-form" loading={saveMutation.isPending}>Save changes</Button></>}
      >
        <form id="user-form" className="form-grid form-grid--2" onSubmit={submit}>
          <div className="field field--span-2"><label htmlFor="user-name">Display name</label><input id="user-name" required minLength={2} maxLength={160} value={form.display_name} onChange={(event) => setForm({ ...form, display_name: event.target.value })} /></div>
          <div className="field field--span-2"><label>Email</label><input value={editingUser?.email ?? ''} readOnly aria-readonly="true" /></div>
          <div className="field"><label htmlFor="user-department">Department</label><input id="user-department" value={form.department} onChange={(event) => setForm({ ...form, department: event.target.value })} /></div>
          <div className="field"><label htmlFor="user-job-title">Job title</label><input id="user-job-title" value={form.job_title} onChange={(event) => setForm({ ...form, job_title: event.target.value })} /></div>
          <div className="field field--span-2"><label htmlFor="user-status">Access status</label><select id="user-status" value={form.status} onChange={(event) => setForm({ ...form, status: event.target.value as AdminUser['status'] })}><option value="active">Active</option><option value="locked">Locked</option><option value="disabled">Disabled</option></select></div>
          <fieldset className="field field--span-2 choice-fieldset"><legend>Application roles</legend><div className="checkbox-grid">{roleOptions.map((role) => <label className="checkbox-field" key={role.value}><input type="checkbox" checked={form.roles.includes(role.value)} onChange={() => toggleRole(role.value)} /><span><strong>{role.label}</strong></span></label>)}</div>{rolesChanged ? <div className="field"><label htmlFor="user-reauth">Current administrator password</label><input id="user-reauth" type="password" autoComplete="current-password" required value={form.reauthPassword} onChange={(event) => setForm({ ...form, reauthPassword: event.target.value })} /><span className="field-help">Required because role changes can expand access.</span></div> : null}</fieldset>
          <div className="field field--span-2"><label htmlFor="user-reason">Reason for change</label><textarea id="user-reason" rows={3} required minLength={5} maxLength={2000} value={form.reason} onChange={(event) => setForm({ ...form, reason: event.target.value })} placeholder="Describe the approved access change" /></div>
          <div className="field--span-2"><InlineError message={formError ?? (saveMutation.error instanceof Error ? saveMutation.error.message : null)} /></div>
        </form>
      </Dialog>
    </div>
  );
}
