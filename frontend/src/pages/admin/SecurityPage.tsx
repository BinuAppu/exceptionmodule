import { useQuery } from '@tanstack/react-query';
import { Fingerprint, KeyRound, LockKeyhole, ShieldCheck } from 'lucide-react';
import { Link } from 'react-router-dom';
import { ErrorState, LoadingState, PageHeader, PageSection } from '../../components/common';
import { apiRequest } from '../../lib/api';
import type { AuthConfiguration } from '../../types/api';

export default function SecurityPage() {
  const query = useQuery({ queryKey: ['auth-configuration'], queryFn: () => apiRequest<AuthConfiguration>('/auth/configuration') });
  if (query.isLoading) return <div className="page admin-page"><PageHeader eyebrow="Administration" title="Security" /><LoadingState rows={5} /></div>;
  if (query.isError) return <div className="page admin-page"><PageHeader eyebrow="Administration" title="Security" /><ErrorState error={query.error} onRetry={() => void query.refetch()} /></div>;
  const configuration = query.data!;
  return (
    <div className="page admin-page">
      <PageHeader eyebrow="Administration" title="Security" description="Review the active identity paths and manage standards-based single sign-on." />
      <div className="settings-layout">
        <div>
          <PageSection title="Workforce authentication" description="Normal workforce access is delegated to the configured identity provider. The local path is reserved for the break-glass administrator.">
            <div className="security-summary-grid">
              <div><span className="security-summary-grid__icon"><Fingerprint size={21} /></span><strong>Single sign-on</strong><p>{configuration.sso_enabled ? `${configuration.sso_display_name ?? 'Identity provider'} is enabled.` : 'No workforce SSO provider is enabled.'}</p><Link className="text-link" to="/admin/sso">Configure SSO</Link></div>
              <div><span className="security-summary-grid__icon"><LockKeyhole size={21} /></span><strong>Break-glass access</strong><p>{configuration.local_break_glass_enabled ? 'The separately controlled local administrator path is available.' : 'Local break-glass sign-in is disabled.'}</p></div>
              <div><span className="security-summary-grid__icon"><KeyRound size={21} /></span><strong>Password policy</strong><p>Local passwords require at least {configuration.password_minimum_length} characters and three character classes.</p></div>
            </div>
          </PageSection>
          <PageSection title="Protocol controls" description="OIDC and SAML configuration is versioned, validated, and audited in its dedicated administration window.">
            <ul className="security-control-list"><li><ShieldCheck size={18} /><span><strong>OIDC Authorization Code + PKCE</strong><small>State, nonce, browser binding, issuer, audience, tenant, and token time claims are validated.</small></span></li><li><ShieldCheck size={18} /><span><strong>SAML SP-initiated SSO</strong><small>Signed requests and assertions, trusted IdP certificate, destination, audience, recipient, and replay controls are enforced.</small></span></li><li><ShieldCheck size={18} /><span><strong>Write-only secrets</strong><small>Client secrets and private keys are never returned to the browser or included in audit values.</small></span></li></ul>
          </PageSection>
        </div>
        <aside className="settings-aside"><div className="settings-summary"><span className="settings-summary__icon"><ShieldCheck size={21} /></span><h2>Security status</h2><dl><div><dt>Federated identity</dt><dd>{configuration.sso_enabled ? 'Enabled' : 'Disabled'}</dd></div><div><dt>Local emergency access</dt><dd>{configuration.local_break_glass_enabled ? 'Available' : 'Disabled'}</dd></div></dl><Link className="button button--primary button--md button--full" to="/admin/sso"><Fingerprint size={17} />Open SSO configuration</Link></div></aside>
      </div>
    </div>
  );
}
