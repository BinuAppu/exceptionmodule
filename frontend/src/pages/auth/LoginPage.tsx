import { useQuery } from '@tanstack/react-query';
import { useEffect, useState, type FormEvent } from 'react';
import { Building2, Eye, EyeOff, KeyRound, LockKeyhole, ShieldCheck } from 'lucide-react';
import { Navigate, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { Button, InlineError } from '../../components/common';
import { useAuth } from '../../contexts/AuthContext';
import { apiRequest } from '../../lib/api';
import type { AuthConfiguration } from '../../types/api';

interface LoginState { from?: string }
export default function LoginPage() {
  const { user, login, loginWithSso } = useAuth();
  const [method, setMethod] = useState<'sso' | 'local'>('local');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [ssoLoading, setSsoLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const location = useLocation();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const configurationQuery = useQuery({
    queryKey: ['auth-configuration'],
    queryFn: () => apiRequest<AuthConfiguration>('/auth/configuration'),
    staleTime: 60_000,
  });
  const configuration = configurationQuery.data;
  const ssoEnabled = configuration?.sso_enabled ?? false;
  const localEnabled = configuration?.local_break_glass_enabled ?? true;
  const callbackErrorCode = searchParams.get('error') ?? searchParams.get('sso_error');
  const callbackError = callbackErrorCode
    ? `Single sign-on could not be completed (${callbackErrorCode.replaceAll('_', ' ')}). No local fallback was used.`
    : null;

  useEffect(() => {
    if (ssoEnabled && !localEnabled) setMethod('sso');
  }, [ssoEnabled, localEnabled]);

  if (user) return <Navigate to={user.must_change_password ? '/change-password' : '/'} replace />;

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const authenticatedUser = await login({ username, password });
      const state = location.state as LoginState | null;
      navigate(authenticatedUser.must_change_password ? '/change-password' : state?.from || '/', { replace: true });
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Sign-in failed. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleSso = async () => {
    setError(null);
    setSsoLoading(true);
    try {
      const state = location.state as LoginState | null;
      await loginWithSso(state?.from ?? '/');
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Single sign-on is currently unavailable.');
      setSsoLoading(false);
    }
  };

  return (
    <main className="auth-page">
      <section className="auth-context" aria-label="About Exception Manager">
        <div className="auth-context__inner">
          <div className="auth-brand"><span className="brand-mark"><ShieldCheck size={26} /></span><div><strong>Exception</strong><span>Manager</span></div></div>
          <div className="auth-context__copy">
            <p className="eyebrow">Governed decisions, clearly recorded</p>
            <h1>Move necessary exceptions forward with confidence.</h1>
            <p>Document business need, assess risk, coordinate approvals, and preserve a complete decision trail in one accountable workspace.</p>
          </div>
          <ul className="auth-benefits">
            <li><ShieldCheck size={19} /><span><strong>Controlled access</strong>Role-based workspaces and auditable actions</span></li>
            <li><LockKeyhole size={19} /><span><strong>Accountable review</strong>Clear owners, controls, and remediation commitments</span></li>
            <li><Building2 size={19} /><span><strong>Business context</strong>Evidence and justification alongside every request</span></li>
          </ul>
        </div>
      </section>
      <section className="auth-panel">
        <div className="auth-form-wrap">
          <div className="auth-form__heading">
            <p className="eyebrow">Secure access</p>
            <h2>Sign in to your workspace</h2>
            <p>Use your organization’s identity provider or local account.</p>
          </div>
          {ssoEnabled || localEnabled ? <div className="auth-tabs" role="tablist" aria-label="Sign-in method">
            {ssoEnabled ? <button type="button" role="tab" aria-selected={method === 'sso'} className={method === 'sso' ? 'active' : ''} onClick={() => { setMethod('sso'); setError(null); }}>Single sign-on</button> : null}
            {localEnabled ? <button type="button" role="tab" aria-selected={method === 'local'} className={method === 'local' ? 'active' : ''} onClick={() => { setMethod('local'); setError(null); }}>Break-glass access</button> : null}
          </div> : null}
          {callbackError ? <InlineError message={callbackError} /> : null}
          {method === 'sso' && ssoEnabled ? (
            <div className="auth-method" role="tabpanel">
              <div className="sso-symbol" aria-hidden="true"><KeyRound size={27} /></div>
              <h3>Continue with your organization</h3>
              <p>You’ll be directed to {configuration?.sso_display_name || 'your configured identity provider'}. No credentials are stored by Exception Manager.</p>
              <InlineError message={error} />
              <Button onClick={() => void handleSso()} loading={ssoLoading} className="button--full">Continue with {configuration?.sso_display_name || 'SSO'}</Button>
            </div>
          ) : (
            <form className="auth-method" role="tabpanel" onSubmit={(event) => void handleSubmit(event)}>
              <div className="field">
                <label htmlFor="username">Username or work email</label>
                <input id="username" name="username" type="text" autoComplete="username" required value={username} onChange={(event) => setUsername(event.target.value)} placeholder="breakglass-admin" />
              </div>
              <div className="field">
                <div className="field__label-row"><label htmlFor="password">Break-glass password</label></div>
                <div className="input-with-action">
                  <input id="password" name="password" type={showPassword ? 'text' : 'password'} autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} />
                  <button type="button" onClick={() => setShowPassword((visible) => !visible)} aria-label={showPassword ? 'Hide password' : 'Show password'}>{showPassword ? <EyeOff size={18} /> : <Eye size={18} />}</button>
                </div>
              </div>
              <InlineError message={error} />
              <Button type="submit" loading={submitting} className="button--full">Sign in</Button>
            </form>
          )}
          <p className="auth-help">Need access or having trouble signing in? Contact your Exception Manager administrator.</p>
        </div>
        <p className="auth-legal">Authorized access only. Activity may be recorded for security and audit purposes.</p>
      </section>
    </main>
  );
}
