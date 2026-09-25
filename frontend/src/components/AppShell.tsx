import {
  Archive,
  BarChart3,
  BookTemplate,
  Bot,
  Boxes,
  CheckCheck,
  ChevronDown,
  ClipboardCheck,
  DatabaseBackup,
  FilePlus2,
  Fingerprint,
  FolderKanban,
  KeyRound,
  LayoutDashboard,
  ListChecks,
  LogOut,
  Menu,
  ScrollText,
  ShieldCheck,
  SlidersHorizontal,
  Users,
  X,
} from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import type { LucideIcon } from 'lucide-react';
import { NavLink, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { initials } from '../lib/format';
import type { UserRole } from '../types/api';

interface NavItem { to: string; label: string; icon: LucideIcon }
const requestNav: NavItem[] = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/requests', label: 'Requests', icon: FolderKanban },
  { to: '/requests/new', label: 'New request', icon: FilePlus2 },
];
const approvalNav: NavItem[] = [{ to: '/approvals', label: 'Approvals', icon: CheckCheck }];
const insightNav: NavItem[] = [{ to: '/reports', label: 'Reports', icon: BarChart3 }];
const adminNav: NavItem[] = [
  { to: '/admin/users', label: 'Users', icon: Users },
  { to: '/admin/configuration', label: 'Configuration', icon: SlidersHorizontal },
  { to: '/admin/workflows', label: 'Workflows', icon: ListChecks },
  { to: '/admin/categories', label: 'Categories', icon: Boxes },
  { to: '/admin/fields', label: 'Custom fields', icon: SlidersHorizontal },
  { to: '/admin/templates', label: 'Templates', icon: BookTemplate },
  { to: '/admin/ai', label: 'AI settings', icon: Bot },
  { to: '/admin/security', label: 'Security', icon: KeyRound },
  { to: '/admin/sso', label: 'Single sign-on', icon: Fingerprint },
  { to: '/admin/audit', label: 'Audit log', icon: ScrollText },
  { to: '/admin/backups', label: 'Backups', icon: DatabaseBackup },
];

function NavigationGroup({ label, items, onNavigate }: { label: string; items: NavItem[]; onNavigate: () => void }) {
  return (
    <div className="sidebar__group">
      <p className="sidebar__group-label">{label}</p>
      <ul>
        {items.map((item) => {
          const Icon = item.icon;
          return (
            <li key={item.to}>
              <NavLink to={item.to} end={item.to === '/'} onClick={onNavigate}>
                <Icon size={19} aria-hidden="true" />
                <span>{item.label}</span>
              </NavLink>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

const roleLabels: Record<UserRole, string> = { user: 'Requester', approver: 'Approver', admin: 'Administrator' };

export function AppShell() {
  const { user, logout, hasRole } = useAuth();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const location = useLocation();
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setSidebarOpen(false);
    setUserMenuOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    const closeMenu = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) setUserMenuOpen(false);
    };
    document.addEventListener('mousedown', closeMenu);
    return () => document.removeEventListener('mousedown', closeMenu);
  }, []);

  if (!user) return null;

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <div className={`sidebar-backdrop ${sidebarOpen ? 'sidebar-backdrop--visible' : ''}`} onClick={() => setSidebarOpen(false)} aria-hidden="true" />
      <aside className={`sidebar ${sidebarOpen ? 'sidebar--open' : ''}`} aria-label="Primary navigation">
        <div className="sidebar__brand">
          <span className="brand-mark"><ShieldCheck size={24} aria-hidden="true" /></span>
          <div><strong>Exception</strong><span>Manager</span></div>
          <button type="button" className="icon-button sidebar__close" onClick={() => setSidebarOpen(false)} aria-label="Close navigation"><X size={21} /></button>
        </div>
        <nav className="sidebar__nav">
          <NavigationGroup label="Workspace" items={requestNav} onNavigate={() => setSidebarOpen(false)} />
          {hasRole('approver', 'admin') ? <NavigationGroup label="Review" items={approvalNav} onNavigate={() => setSidebarOpen(false)} /> : null}
          {hasRole('approver', 'admin') ? <NavigationGroup label="Insights" items={insightNav} onNavigate={() => setSidebarOpen(false)} /> : null}
          {hasRole('admin') ? <NavigationGroup label="Administration" items={adminNav} onNavigate={() => setSidebarOpen(false)} /> : null}
        </nav>
        <div className="sidebar__footer">
          <div className="sidebar__assurance"><ClipboardCheck size={18} aria-hidden="true" /><div><strong>Decision trail</strong><span>Every action is auditable</span></div></div>
        </div>
      </aside>

      <div className="app-frame">
        <header className="topbar">
          <button type="button" className="icon-button topbar__menu" onClick={() => setSidebarOpen(true)} aria-label="Open navigation" aria-expanded={sidebarOpen}><Menu size={22} /></button>
          <div className="topbar__context"><Archive size={17} aria-hidden="true" /><span>Governance workspace</span></div>
          <div className="topbar__actions" ref={menuRef}>
            <div className="user-menu">
              <button type="button" className="user-menu__trigger" onClick={() => setUserMenuOpen((open) => !open)} aria-expanded={userMenuOpen} aria-haspopup="menu">
                <span className="avatar">{initials(user.full_name)}</span>
                <span className="user-menu__identity"><strong>{user.full_name}</strong><small>{roleLabels[user.role]}</small></span>
                <ChevronDown size={16} aria-hidden="true" />
              </button>
              {userMenuOpen ? (
                <div className="user-menu__popover" role="menu">
                  <div className="user-menu__details"><strong>{user.full_name}</strong><span>{user.email}</span></div>
                  <button type="button" role="menuitem" onClick={() => void logout()}><LogOut size={17} />Sign out</button>
                </div>
              ) : null}
            </div>
          </div>
        </header>
        <main id="main-content" className="main-content" tabIndex={-1}>
          <Outlet />
        </main>
        <footer className="app-footer"><span>Exception Manager</span><span>Protected governance workspace</span></footer>
      </div>
    </div>
  );
}
