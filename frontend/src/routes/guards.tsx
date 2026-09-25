import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { LoaderCircle } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import type { UserRole } from '../types/api';

function FullPageLoader() {
  return <div className="auth-loading" role="status"><LoaderCircle className="spin" size={28} /><span>Loading your workspace…</span></div>;
}

export function ProtectedRoute() {
  const { user, isLoading } = useAuth();
  const location = useLocation();
  if (isLoading) return <FullPageLoader />;
  if (!user) return <Navigate to="/login" replace state={{ from: location }} />;
  if (user.must_change_password && location.pathname !== '/change-password') return <Navigate to="/change-password" replace />;
  return <Outlet />;
}

export function PublicOnlyRoute() {
  const { user, isLoading } = useAuth();
  if (isLoading) return <FullPageLoader />;
  if (user) return <Navigate to={user.must_change_password ? '/change-password' : '/'} replace />;
  return <Outlet />;
}

export function RoleRoute({ roles }: { roles: UserRole[] }) {
  const { user, hasRole } = useAuth();
  if (!user) return <Navigate to="/login" replace />;
  if (!roles.some((role) => hasRole(role))) return <Navigate to="/" replace />;
  return <Outlet />;
}
