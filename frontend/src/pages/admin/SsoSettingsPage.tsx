import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, CheckCircle2, Clipboard, ExternalLink, Fingerprint, KeyRound, Link2, Save, ShieldCheck, TestTube2, TriangleAlert } from 'lucide-react';
import { useEffect, useState, type FormEvent } from 'react';
import { Button, ErrorState, InlineError, LoadingState, PageHeader, PageSection } from '../../components/common';
import { useToast } from '../../contexts/ToastContext';
import { apiRequest } from '../../lib/api';
import { formatDateTime } from '../../lib/format';
import type { SsoSettings, SsoValidationResult } from '../../types/api';

interface SsoForm extends SsoSettings {
  client_secret: string;
  allowed_domains_text: string;
  reason: string;
  reauthPassword: string;
}

const defaults: SsoForm = {
  version: 0,
  provider: 'oidc',
  enabled: false,
  display_name: 'Organization SSO',
  issuer: '',
  client_id: '',
  scopes: 'openid profile email',
  redirect_uri: `${window.location.origin}/api/auth/sso/callback`,
  required_acr: '',
  email_claim: 'email',
  name_claim: 'name',
  tenant_claim: '',
  tenant_value: '',
  allowed_domains: [],
  allowed_domains_text: '',
  auto_provision: true,
  idp_entity_id: '',
  sso_url: '',
  idp_x509_certificate: '',
  email_attribute: 'email',
  name_attribute: 'displayName',
  sp_entity_id: `${window.location.origin}/api/auth/sso/saml/metadata`,
  acs_url: `${window.location.origin}/api/auth/sso/saml/acs`,
  client_secret_configured: false,
  signing_key_configured: false,
  metadata_url: null,
  updated_at: null,
  client_secret: '',
  reason: '',
  reauthPassword: '',
};

export default function SsoSettingsPage() {
  const { showToast } = useToast();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<SsoForm>(defaults);
  const [formError, setFormError] = useState<string | null>(null);
  const [validation, setValidation] = useState<SsoValidationResult | null>(null);

  const query = useQuery({ queryKey: ['admin-sso'], queryFn: () => apiRequest<SsoSettings>('/admin/sso') });
  useEffect(() => {
    if (!query.data) return;
    setForm({
      ...query.data,
      issuer: query.data.issuer ?? '',
      client_id: query.data.client_id ?? '',
      redirect_uri: query.data.redirect_uri ?? '',
      required_acr: query.data.required_acr ?? '',
      tenant_claim: query.data.tenant_claim ?? '',
      tenant_value: query.data.tenant_value ?? '',
      idp_entity_id: query.data.idp_entity_id ?? '',
      sso_url: query.data.sso_url ?? '',
      idp_x509_certificate: query.data.idp_x509_certificate ?? '',
      sp_entity_id: query.data.sp_entity_id ?? '',
      acs_url: query.data.acs_url ?? '',
      allowed_domains_text: query.data.allowed_domains.join(', '),
      client_secret: '',
      reason: '',
      reauthPassword: '',
    });
  }, [query.data]);

  const configuration = () => {
    const common = {
      provider: form.provider,
      enabled: form.enabled,
      display_name: form.display_name.trim(),
      scopes: form.scopes.trim(),
      allowed_domains: form.allowed_domains_text.split(',').map((item) => item.trim().toLowerCase()).filter(Boolean),
      auto_provision: form.auto_provision,
      client_secret: form.client_secret || undefined,
      expected_version: form.version,
      reason: form.reason.trim(),
      reauthenticated: true,
    };
    if (form.provider === 'oidc') {
      return {
        ...common,
        issuer: form.issuer.trim(),
        client_id: form.client_id.trim(),
        redirect_uri: form.redirect_uri.trim(),
        required_acr: form.required_acr.trim() || null,
        email_claim: form.email_claim.trim(),
        name_claim: form.name_claim.trim(),
        tenant_claim: form.tenant_claim.trim() || null,
        tenant_value: form.tenant_value.trim() || null,
        idp_entity_id: null,
        sso_url: null,
        idp_x509_certificate: null,
        email_attribute: form.email_attribute.trim(),
        name_attribute: form.name_attribute.trim(),
        sp_entity_id: null,
        acs_url: null,
      };
    }
    return {
      ...common,
      issuer: null,
      client_id: null,
      redirect_uri: null,
      required_acr: null,
      email_claim: form.email_claim.trim(),
      name_claim: form.name_claim.trim(),
      tenant_claim: null,
      tenant_value: null,
      idp_entity_id: form.idp_entity_id.trim(),
      sso_url: form.sso_url.trim(),
      idp_x509_certificate: form.idp_x509_certificate.trim(),
      email_attribute: form.email_attribute.trim(),
      name_attribute: form.name_attribute.trim(),
      sp_entity_id: form.sp_entity_id.trim(),
      acs_url: form.acs_url.trim(),
    };
  };

  const saveMutation = useMutation({
    mutationFn: () => apiRequest<SsoSettings>('/admin/sso', {
      method: 'PUT',
      headers: form.reauthPassword ? { 'X-Reauthentication-Password': form.reauthPassword } : undefined,
      body: configuration(),
    }),
    onSuccess: async () => {
      setForm((current) => ({ ...current, client_secret: '', reauthPassword: '', reason: '' }));
      await queryClient.invalidateQueries({ queryKey: ['admin-sso'] });
      showToast('Single sign-on configuration saved.', 'success');
    },
    onError: (error) => setFormError(error instanceof Error ? error.message : 'SSO configuration could not be saved.'),
  });

  const testMutation = useMutation({
    mutationFn: () => apiRequest<SsoValidationResult>('/admin/sso/validate', {
      method: 'POST',
      headers: form.reauthPassword ? { 'X-Reauthentication-Password': form.reauthPassword } : undefined,
      body: configuration(),
    }),
    onSuccess: (result) => { setValidation(result); showToast(result.valid ? 'Identity provider validation passed.' : 'Identity provider validation found issues.', result.valid ? 'success' : 'error'); },
    onError: (error) => setFormError(error instanceof Error ? error.message : 'SSO validation could not be completed.'),
  });

  const validateForm = (): boolean => {
    setFormError(null);
    if (form.display_name.trim().length < 2) return fail('Display name is required.');
    if (form.reason.trim().length < 5) return fail('Enter a reason of at least 5 characters.');
    if (form.provider === 'oidc') {
      if (!/^https:\/\//i.test(form.issuer.trim()) && window.location.protocol !== 'http:') return fail('OIDC issuer must use HTTPS outside local development.');
      if (!form.issuer.trim() || !form.client_id.trim() || !form.redirect_uri.trim()) return fail('Issuer, client ID, and redirect URI are required for OIDC.');
      if (!form.scopes.trim().split(/\s+/).includes('openid')) return fail('OIDC scopes must include openid.');
      if (Boolean(form.tenant_claim.trim()) !== Boolean(form.tenant_value.trim())) return fail('Tenant claim and tenant value must be configured together.');
    } else {
      if (!form.idp_entity_id.trim() || !form.sso_url.trim() || !form.idp_x509_certificate.trim()) return fail('SAML entity ID, SSO URL, and signing certificate are required.');
      if (!form.sp_entity_id.trim() || !form.acs_url.trim()) return fail('SAML service-provider entity ID and ACS URL are required.');
    }
    return true;
  };

  const fail = (message: string) => { setFormError(message); return false; };
  const submit = (event: FormEvent) => { event.preventDefault(); if (validateForm()) saveMutation.mutate(); };
  const test = () => { if (validateForm()) { setValidation(null); testMutation.mutate(); } };
  const copy = async (value: string, label: string) => { await navigator.clipboard.writeText(value); showToast(`${label} copied.`, 'success'); };

  if (query.isLoading) return <div className="page admin-page"><PageHeader eyebrow="Administration" title="Single sign-on" /><LoadingState rows={8} /></div>;
  if (query.isError) return <div className="page admin-page"><PageHeader eyebrow="Administration" title="Single sign-on" /><ErrorState error={query.error} onRetry={() => void query.refetch()} /></div>;

  return (
    <div className="page admin-page">
      <PageHeader eyebrow="Administration" title="Single sign-on" description="Configure and validate one standards-based identity provider. Secrets are write-only and are never returned by the API." actions={<><Button variant="secondary" onClick={test} loading={testMutation.isPending}><TestTube2 size={17} />Test configuration</Button><Button form="sso-form" type="submit" loading={saveMutation.isPending}><Save size={17} />Save SSO</Button></>} />
      <form id="sso-form" onSubmit={submit} className="settings-layout">
        <div>
          <PageSection title="Provider" description="OIDC uses Authorization Code with PKCE. SAML supports service-provider-initiated SSO with signed requests and assertions.">
            <div className="segmented-tabs" role="tablist" aria-label="SSO protocol">
              <button type="button" role="tab" aria-selected={form.provider === 'oidc'} className={form.provider === 'oidc' ? 'active' : ''} onClick={() => setForm({ ...form, provider: 'oidc' })}><KeyRound size={17} />OpenID Connect</button>
              <button type="button" role="tab" aria-selected={form.provider === 'saml'} className={form.provider === 'saml' ? 'active' : ''} onClick={() => setForm({ ...form, provider: 'saml' })}><Fingerprint size={17} />SAML 2.0</button>
            </div>
            <div className="form-grid form-grid--2 sso-provider-grid">
              <div className="field"><label htmlFor="sso-name">Display name</label><input id="sso-name" required maxLength={160} value={form.display_name} onChange={(event) => setForm({ ...form, display_name: event.target.value })} /></div>
              <label className="switch-field"><input type="checkbox" checked={form.enabled} onChange={(event) => setForm({ ...form, enabled: event.target.checked })} /><span className="switch-control" aria-hidden="true" /><span><strong>Enable SSO</strong><small>Expose the provider on the sign-in page.</small></span></label>
              <label className="switch-field"><input type="checkbox" checked={form.auto_provision} onChange={(event) => setForm({ ...form, auto_provision: event.target.checked })} /><span className="switch-control" aria-hidden="true" /><span><strong>Just-in-time provisioning</strong><small>Create a base requester account after validated SSO.</small></span></label>
              <div className="field"><label htmlFor="sso-domains">Allowed email domains</label><input id="sso-domains" value={form.allowed_domains_text} onChange={(event) => setForm({ ...form, allowed_domains_text: event.target.value })} placeholder="example.com, subsidiary.example" /><span className="field-help">Comma-separated. Leave empty only for a deliberately unrestricted provider.</span></div>
            </div>
          </PageSection>

          {form.provider === 'oidc' ? <OidcFields form={form} setForm={setForm} /> : <SamlFields form={form} setForm={setForm} copy={copy} />}

          <PageSection title="Authorization and audit" description="A fresh high-assurance local or federated session is required. For the local break-glass account, enter its current password.">
            <div className="form-grid form-grid--2">
              <div className="field"><label htmlFor="sso-reauth">Current administrator password</label><input id="sso-reauth" type="password" autoComplete="current-password" value={form.reauthPassword} onChange={(event) => setForm({ ...form, reauthPassword: event.target.value })} /><span className="field-help">Omitted for a fresh SSO session that already satisfies step-up policy.</span></div>
              <div className="field"><label htmlFor="sso-reason">Reason for change</label><textarea id="sso-reason" rows={3} required minLength={5} maxLength={2000} value={form.reason} onChange={(event) => setForm({ ...form, reason: event.target.value })} placeholder="Approved identity provider change" /></div>
            </div>
            <InlineError message={formError ?? (saveMutation.error instanceof Error ? saveMutation.error.message : null)} />
          </PageSection>

          {validation ? <PageSection title="Validation result" description={validation.valid ? 'All required provider checks passed.' : 'One or more provider checks failed.'}><div className="validation-list">{Object.entries(validation.checks).map(([name, passed]) => <div key={name}>{passed ? <CheckCircle2 size={18} /> : <TriangleAlert size={18} />}<span><strong>{name}</strong><small>{passed ? 'Passed' : 'Failed'}</small></span></div>)}{validation.errors?.map((message) => <div key={message}><TriangleAlert size={18} /><span><strong>Validation error</strong><small>{message}</small></span></div>)}{validation.warnings?.map((message) => <div key={message}><AlertTriangle size={18} /><span><strong>Warning</strong><small>{message}</small></span></div>)}</div></PageSection> : null}
        </div>

        <aside className="settings-aside">
          <div className="settings-summary">
            <span className="settings-summary__icon"><ShieldCheck size={21} /></span>
            <h2>SSO status</h2>
            <dl><div><dt>Protocol</dt><dd>{form.provider === 'oidc' ? 'OpenID Connect' : 'SAML 2.0'}</dd></div><div><dt>State</dt><dd>{form.enabled ? 'Enabled' : 'Disabled'}</dd></div><div><dt>Configuration</dt><dd>{form.version ? `v${form.version}` : 'Not saved'}</dd></div><div><dt>Client secret</dt><dd>{form.client_secret_configured ? 'Configured' : 'Not configured'}</dd></div><div><dt>Signing key</dt><dd>{form.signing_key_configured ? 'Configured' : 'Generated on save'}</dd></div><div><dt>Last updated</dt><dd>{formatDateTime(form.updated_at)}</dd></div></dl>
            <p><ShieldCheck size={16} />Failed SSO never falls back to a local workforce account.</p>
          </div>
          {form.metadata_url ? <div className="settings-summary"><span className="settings-summary__icon"><Link2 size={21} /></span><h2>SAML metadata</h2><p className="break-all-text">{form.metadata_url}</p><a className="text-link" href={form.metadata_url} target="_blank" rel="noreferrer">Open metadata <ExternalLink size={15} /></a></div> : null}
        </aside>
      </form>
    </div>
  );
}

type SetForm = (value: SsoForm | ((current: SsoForm) => SsoForm)) => void;

function OidcFields({ form, setForm }: { form: SsoForm; setForm: SetForm }) {
  return <PageSection title="OpenID Connect" description="Register the callback shown below. Issuer and audience are validated exactly during callback processing.">
    <div className="form-grid form-grid--2">
      <div className="field field--span-2"><label htmlFor="oidc-issuer">Issuer URL</label><input id="oidc-issuer" type="url" required value={form.issuer} onChange={(event) => setForm({ ...form, issuer: event.target.value })} placeholder="https://login.example.com/tenant/v2.0" /></div>
      <div className="field"><label htmlFor="oidc-client-id">Client ID</label><input id="oidc-client-id" required value={form.client_id} onChange={(event) => setForm({ ...form, client_id: event.target.value })} /></div>
      <div className="field"><label htmlFor="oidc-secret">Client secret</label><input id="oidc-secret" type="password" autoComplete="new-password" value={form.client_secret} onChange={(event) => setForm({ ...form, client_secret: event.target.value })} placeholder={form.client_secret_configured ? 'Leave blank to keep current secret' : 'Required for a confidential client'} /><span className="field-help">Write-only and encrypted at rest.</span></div>
      <div className="field field--span-2"><label htmlFor="oidc-redirect">Redirect URI</label><input id="oidc-redirect" type="url" required value={form.redirect_uri} onChange={(event) => setForm({ ...form, redirect_uri: event.target.value })} /></div>
      <div className="field field--span-2"><label htmlFor="oidc-scopes">Scopes</label><input id="oidc-scopes" required value={form.scopes} onChange={(event) => setForm({ ...form, scopes: event.target.value })} /></div>
      <div className="field"><label htmlFor="oidc-email-claim">Email claim</label><input id="oidc-email-claim" required value={form.email_claim} onChange={(event) => setForm({ ...form, email_claim: event.target.value })} /></div>
      <div className="field"><label htmlFor="oidc-name-claim">Display-name claim</label><input id="oidc-name-claim" required value={form.name_claim} onChange={(event) => setForm({ ...form, name_claim: event.target.value })} /></div>
      <div className="field"><label htmlFor="oidc-acr">Required ACR</label><input id="oidc-acr" value={form.required_acr} onChange={(event) => setForm({ ...form, required_acr: event.target.value })} placeholder="Optional exact claim value" /></div>
      <div className="field"><label htmlFor="oidc-tenant-claim">Tenant claim</label><input id="oidc-tenant-claim" value={form.tenant_claim} onChange={(event) => setForm({ ...form, tenant_claim: event.target.value })} placeholder="tid" /></div>
      <div className="field field--span-2"><label htmlFor="oidc-tenant-value">Required tenant value</label><input id="oidc-tenant-value" value={form.tenant_value} onChange={(event) => setForm({ ...form, tenant_value: event.target.value })} placeholder="Optional exact tenant ID" /></div>
    </div>
  </PageSection>;
}

function SamlFields({ form, setForm, copy }: { form: SsoForm; setForm: SetForm; copy: (value: string, label: string) => Promise<void> }) {
  return <PageSection title="SAML 2.0" description="Configure the identity provider and register this service provider in the IdP. SP-initiated flow only.">
    <div className="form-grid form-grid--2">
      <div className="field field--span-2"><label htmlFor="saml-entity">IdP entity ID</label><input id="saml-entity" required value={form.idp_entity_id} onChange={(event) => setForm({ ...form, idp_entity_id: event.target.value })} /></div>
      <div className="field field--span-2"><label htmlFor="saml-sso">IdP single-sign-on URL</label><input id="saml-sso" type="url" required value={form.sso_url} onChange={(event) => setForm({ ...form, sso_url: event.target.value })} /></div>
      <div className="field field--span-2"><label htmlFor="saml-certificate">IdP X.509 signing certificate</label><textarea id="saml-certificate" className="code-input" rows={7} required value={form.idp_x509_certificate} onChange={(event) => setForm({ ...form, idp_x509_certificate: event.target.value })} placeholder="-----BEGIN CERTIFICATE-----" /><span className="field-help">Public verification certificate. Pin an approved rollover certificate when supplied by your IdP.</span></div>
      <div className="field"><label htmlFor="saml-email">Email attribute</label><input id="saml-email" required value={form.email_attribute} onChange={(event) => setForm({ ...form, email_attribute: event.target.value })} /></div>
      <div className="field"><label htmlFor="saml-name">Display-name attribute</label><input id="saml-name" required value={form.name_attribute} onChange={(event) => setForm({ ...form, name_attribute: event.target.value })} /></div>
      <div className="field field--span-2"><label htmlFor="saml-sp-entity">SP entity ID</label><div className="input-with-action"><input id="saml-sp-entity" required value={form.sp_entity_id} onChange={(event) => setForm({ ...form, sp_entity_id: event.target.value })} /><button type="button" onClick={() => void copy(form.sp_entity_id, 'SP entity ID')} aria-label="Copy SP entity ID"><Clipboard size={17} /></button></div></div>
      <div className="field field--span-2"><label htmlFor="saml-acs">Assertion consumer service URL</label><div className="input-with-action"><input id="saml-acs" type="url" required value={form.acs_url} onChange={(event) => setForm({ ...form, acs_url: event.target.value })} /><button type="button" onClick={() => void copy(form.acs_url, 'ACS URL')} aria-label="Copy ACS URL"><Clipboard size={17} /></button></div></div>
    </div>
  </PageSection>;
}
