import { useState, type FormEvent } from 'react';
import { Check, Eye, EyeOff, LogOut, ShieldCheck } from 'lucide-react';
import { Navigate, useNavigate } from 'react-router-dom';
import { Button, InlineError } from '../../components/common';
import { useAuth } from '../../contexts/AuthContext';

export default function ChangePasswordPage() {
  const { user, changePassword, logout } = useAuth();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPasswords, setShowPasswords] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  if (!user) return <Navigate to="/login" replace />;

  const requirements = [
    { label: 'At least 12 characters', met: newPassword.length >= 12 },
    { label: 'Upper and lowercase letters', met: /[a-z]/.test(newPassword) && /[A-Z]/.test(newPassword) },
    { label: 'A number', met: /\d/.test(newPassword) },
    { label: 'A special character', met: /[^A-Za-z0-9]/.test(newPassword) },
  ];
  const allRequirementsMet = requirements.every((requirement) => requirement.met);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    if (newPassword === currentPassword) {
      setError('Your new password must be different from your current password.');
      return;
    }
    if (!allRequirementsMet) {
      setError('Complete all password requirements before continuing.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('The new passwords do not match.');
      return;
    }
    setSubmitting(true);
    try {
      await changePassword(currentPassword, newPassword);
      navigate('/', { replace: true });
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Password could not be changed.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="password-page">
      <section className="password-shell" aria-labelledby="password-title">
        <div className="password-shell__brand"><span className="brand-mark"><ShieldCheck size={25} /></span><div><strong>Exception</strong><span>Manager</span></div></div>
        <div className="password-shell__notice">
          <p className="eyebrow">Account security</p>
          <h1 id="password-title">Choose a new password</h1>
          <p>Your account requires a password change before you can access the governance workspace.</p>
        </div>
        <form className="password-form" onSubmit={(event) => void handleSubmit(event)}>
          <div className="field">
            <label htmlFor="current-password">Current password</label>
            <input id="current-password" type={showPasswords ? 'text' : 'password'} autoComplete="current-password" required value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="new-password">New password</label>
            <input id="new-password" type={showPasswords ? 'text' : 'password'} autoComplete="new-password" required value={newPassword} onChange={(event) => setNewPassword(event.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="confirm-password">Confirm new password</label>
            <input id="confirm-password" type={showPasswords ? 'text' : 'password'} autoComplete="new-password" required value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} />
          </div>
          <div className="password-requirements" aria-label="Password requirements">
            {requirements.map((requirement) => <span className={requirement.met ? 'met' : ''} key={requirement.label}><Check size={15} aria-hidden="true" />{requirement.label}</span>)}
          </div>
          <div className="password-form__utility">
            <button type="button" className="show-password-button" onClick={() => setShowPasswords((visible) => !visible)}>{showPasswords ? <EyeOff size={17} /> : <Eye size={17} />}{showPasswords ? 'Hide passwords' : 'Show passwords'}</button>
            <button type="button" className="text-button" onClick={() => void logout()}><LogOut size={16} />Sign out</button>
          </div>
          <InlineError message={error} />
          <Button type="submit" loading={submitting} className="button--full">Update password and continue</Button>
        </form>
      </section>
    </main>
  );
}
