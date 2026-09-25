import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { apiRequest, ApiError } from '../lib/api';
import type { AuthSession, User } from '../types/api';

interface LoginInput {
  username: string;
  password: string;
}

interface AuthContextValue {
  user: User | null;
  isLoading: boolean;
  login: (input: LoginInput) => Promise<User>;
  loginWithSso: (returnTo?: string) => Promise<void>;
  logout: () => Promise<void>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  refreshUser: () => Promise<void>;
  hasRole: (...roles: User['role'][]) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

function sessionUser(payload: AuthSession | User): User {
  if ('user' in payload) {
    return {
      ...payload.user,
      id: payload.user.public_id,
      full_name: payload.user.display_name,
      role: payload.roles.includes('admin') ? 'admin' : payload.roles.includes('approver') ? 'approver' : 'user',
      roles: payload.roles,
      is_active: true,
    };
  }
  return payload;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const refreshUser = useCallback(async () => {
    try {
      const payload = await apiRequest<AuthSession | User>('/auth/me');
      setUser(sessionUser(payload));
    } catch (error) {
      if (!(error instanceof ApiError) || error.status === 401 || error.status === 403) {
        setUser(null);
      } else {
        setUser(null);
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshUser();
    const handleUnauthorized = () => setUser(null);
    window.addEventListener('exception-manager:unauthorized', handleUnauthorized);
    return () => window.removeEventListener('exception-manager:unauthorized', handleUnauthorized);
  }, [refreshUser]);

  const login = useCallback(async (input: LoginInput) => {
    const payload = await apiRequest<AuthSession | User>('/auth/login', {
      method: 'POST',
      body: { username: input.username.trim(), password: input.password },
    });
    const authenticatedUser = sessionUser(payload);
    setUser(authenticatedUser);
    return authenticatedUser;
  }, []);

  const loginWithSso = useCallback(async (returnTo = '/') => {
    const safeReturnTo = returnTo.startsWith('/') && !returnTo.startsWith('//') ? returnTo : '/';
    window.location.assign(`/api/auth/sso/login?return_to=${encodeURIComponent(safeReturnTo)}`);
  }, []);

  const logout = useCallback(async () => {
    try {
      await apiRequest<void>('/auth/logout', { method: 'POST' });
    } finally {
      setUser(null);
    }
  }, []);

  const changePassword = useCallback(async (currentPassword: string, newPassword: string) => {
    await apiRequest<void>('/auth/change-password', {
      method: 'POST',
      body: { current_password: currentPassword, new_password: newPassword },
    });
    await refreshUser();
  }, [refreshUser]);

  const hasRole = useCallback(
    (...roles: User['role'][]) => (user ? roles.some((role) => (user.roles ?? [user.role]).includes(role)) : false),
    [user],
  );

  const value = useMemo(
    () => ({ user, isLoading, login, loginWithSso, logout, changePassword, refreshUser, hasRole }),
    [user, isLoading, login, loginWithSso, logout, changePassword, refreshUser, hasRole],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used inside AuthProvider');
  return context;
}
