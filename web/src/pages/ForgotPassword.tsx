import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context';
import { AuthCard, Field, FormError } from './shared';

export function ForgotPassword() {
  const { client } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [step, setStep] = useState<'email' | 'otp'>('email');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleRequestOTP = async (e: FormEvent) => {
    e.preventDefault();
    if (!email.trim()) { setError('Email is required'); return; }
    setLoading(true);
    setError('');
    try {
      await client.requestOTP(email.trim());
      setStep('otp');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOTP = async (e: FormEvent) => {
    e.preventDefault();
    if (!client) return;
    if (!otp.trim()) { setError('Code is required'); return; }
    if (newPassword.length < 8) { setError('Password must be at least 8 characters'); return; }
    setLoading(true);
    setError('');
    try {
      await client.verifyOTP(email.trim(), otp.trim());
      navigate('/login');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  if (step === 'otp') {
    return (
      <AuthCard title="Check your email" subtitle={`We sent a code to ${email}`} icon="mark_email_read">
        <form onSubmit={handleVerifyOTP} className="space-y-6">
          <Field label="Verification Code">
            <input type="text" inputMode="numeric" value={otp} onChange={e => { setOtp(e.target.value); setError(''); }}
              placeholder="123456" autoFocus maxLength={8} className="input-field tracking-[0.5em] font-mono text-center text-lg" />
          </Field>
          <Field label="New Password">
            <input type="password" value={newPassword} onChange={e => { setNewPassword(e.target.value); setError(''); }}
              placeholder="Min. 8 characters" autoComplete="new-password" className="input-field" />
          </Field>
          {error && <FormError msg={error} />}
          <button type="submit" disabled={loading}
            className="w-full btn-primary px-6 py-3 rounded-md text-on-primary font-semibold shadow-lg transition-all hover:scale-[1.02] active:scale-95 disabled:opacity-60">
            {loading ? 'Resetting…' : 'Reset Password'}
          </button>
          <p className="text-center text-xs text-on-surface-variant/60">
            Didn't receive a code?{' '}
            <button type="button" className="text-primary hover:underline" onClick={() => setStep('email')}>
              Try again
            </button>
          </p>
        </form>
      </AuthCard>
    );
  }

  return (
    <AuthCard title="Forgot password" subtitle="Enter your email to receive a reset code" icon="lock_reset">
      <form onSubmit={handleRequestOTP} className="space-y-6">
        <Field label="Email">
          <input type="email" value={email} onChange={e => { setEmail(e.target.value); setError(''); }}
            placeholder="you@example.com" autoFocus autoComplete="email" className="input-field" />
        </Field>
        {error && <FormError msg={error} />}
        <button type="submit" disabled={loading}
          className="w-full btn-primary px-6 py-3 rounded-md text-on-primary font-semibold shadow-lg transition-all hover:scale-[1.02] active:scale-95 disabled:opacity-60">
          {loading ? 'Sending…' : 'Send Reset Code'}
        </button>
        <p className="text-center text-sm text-on-surface-variant">
          <Link to="/login" className="text-primary font-semibold hover:underline">Back to sign in</Link>
        </p>
      </form>
    </AuthCard>
  );
}
