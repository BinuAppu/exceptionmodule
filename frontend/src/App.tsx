import { lazy, Suspense } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { AppShell } from './components/AppShell';
import { ProtectedRoute, PublicOnlyRoute, RoleRoute } from './routes/guards';
import LoginPage from './pages/auth/LoginPage';
import ChangePasswordPage from './pages/auth/ChangePasswordPage';
import DashboardPage from './pages/DashboardPage';
import RequestsPage from './pages/RequestsPage';
import NewRequestPage from './pages/NewRequestPage';
import RequestDetailPage from './pages/RequestDetailPage';
import NotFoundPage from './pages/NotFoundPage';

const ApprovalsPage = lazy(() => import('./pages/ApprovalsPage'));
const ReportsPage = lazy(() => import('./pages/ReportsPage'));
const UsersPage = lazy(() => import('./pages/admin/UsersPage'));
const ConfigurationPage = lazy(() => import('./pages/admin/ConfigurationPage'));
const WorkflowsPage = lazy(() => import('./pages/admin/WorkflowsPage'));
const CategoriesPage = lazy(() => import('./pages/admin/CategoriesPage'));
const FieldsPage = lazy(() => import('./pages/admin/FieldsPage'));
const TemplatesPage = lazy(() => import('./pages/admin/TemplatesPage'));
const AISettingsPage = lazy(() => import('./pages/admin/AISettingsPage'));
const SecurityPage = lazy(() => import('./pages/admin/SecurityPage'));
const SsoSettingsPage = lazy(() => import('./pages/admin/SsoSettingsPage'));
const AuditPage = lazy(() => import('./pages/admin/AuditPage'));
const BackupsPage = lazy(() => import('./pages/admin/BackupsPage'));

export default function App() {
  return (
    <Suspense fallback={<div className="route-loading" role="status">Loading page…</div>}>
      <Routes>
        <Route element={<PublicOnlyRoute />}>
          <Route path="/login" element={<LoginPage />} />
        </Route>
        <Route element={<ProtectedRoute />}>
          <Route path="/change-password" element={<ChangePasswordPage />} />
          <Route element={<AppShell />}>
            <Route index element={<DashboardPage />} />
            <Route path="requests" element={<RequestsPage />} />
            <Route path="requests/new" element={<NewRequestPage />} />
            <Route path="requests/:id" element={<RequestDetailPage />} />
            <Route path="approvals" element={<ApprovalsPage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route element={<RoleRoute roles={['admin']} />}>
              <Route path="admin/users" element={<UsersPage />} />
              <Route path="admin/configuration" element={<ConfigurationPage />} />
              <Route path="admin/workflows" element={<WorkflowsPage />} />
              <Route path="admin/categories" element={<CategoriesPage />} />
              <Route path="admin/fields" element={<FieldsPage />} />
              <Route path="admin/templates" element={<TemplatesPage />} />
              <Route path="admin/ai" element={<AISettingsPage />} />
              <Route path="admin/security" element={<SecurityPage />} />
              <Route path="admin/sso" element={<SsoSettingsPage />} />
              <Route path="admin/audit" element={<AuditPage />} />
              <Route path="admin/backups" element={<BackupsPage />} />
            </Route>
          </Route>
          <Route path="*" element={<NotFoundPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Suspense>
  );
}
