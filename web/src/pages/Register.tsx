import { useState, type FormEvent } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context';
import { AuthCard, Field, FormError, Divider } from './shared';

export function Register() {
  const { client } = useAuth();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !email.trim() || !password) { setError('All fields are required'); return; }
    if (password !== confirmPassword) { setError('Passwords do not match'); return; }
    if (password.length < 8) { setError('Password must be at least 8 characters'); return; }
    setLoading(true);
    setError('');
    try {
      await client.register(email.trim(), password, name.trim());
      setSuccess(true);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  if (success) {
    return (
      <AuthCard title="Account created" icon="check_circle">
        <div className="text-center space-y-4">
          <p className="text-sm text-on-surface-variant">
            We've sent a verification email to <strong className="text-on-surface">{email}</strong>.
            Check your inbox, then sign in.
          </p>
          <Link
            to="/login"
            className="block w-full btn-primary px-6 py-3 rounded-md text-on-primary font-semibold text-center shadow-lg transition-all hover:scale-[1.02]"
          >
            Go to Sign In
          </Link>
        </div>
      </AuthCard>
    );
  }

  return (
    <AuthCard
      title="Create account"
      subtitle="Create your account"
      icon="person_add"
    >
      <form onSubmit={handleSubmit} className="space-y-5">
        <Field label="Full Name">
          <input
            type="text"
            value={name}
            onChange={e => { setName(e.target.value); setError(''); }}
            placeholder="Ada Lovelace"
            autoFocus
            autoComplete="name"
            className="input-field"
          />
        </Field>

        <Field label="Email">
          <input
            type="email"
            value={email}
            onChange={e => { setEmail(e.target.value); setError(''); }}
            placeholder="ada@example.com"
            autoComplete="email"
            className="input-field"
          />
        </Field>

        <Field label="Password">
          <div className="relative">
            <input
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={e => { setPassword(e.target.value); setError(''); }}
              placeholder="Min. 8 characters"
              autoComplete="new-password"
              className="input-field pr-8"
            />
            <button type="button" onClick={() => setShowPassword(v => !v)} tabIndex={-1}
              className="absolute right-0 top-2 text-on-surface-variant/50 hover:text-on-surface-variant transition-colors">
              <span className="material-symbols-outlined text-base" aria-hidden="true">
                {showPassword ? 'visibility_off' : 'visibility'}
              </span>
            </button>
          </div>
          {/* Strength indicator */}
          {password.length > 0 && (
            <div className="flex gap-1 mt-2">
              {[1,2,3,4].map(i => (
                <div key={i} className={`h-1 flex-1 rounded-full transition-colors ${
                  password.length >= i * 3
                    ? password.length >= 12 ? 'bg-green-500' : password.length >= 8 ? 'bg-yellow-400' : 'bg-error'
                    : 'bg-outline-variant/30'
                }`} />
              ))}
            </div>
          )}
        </Field>

        <Field label="Confirm Password">
          <input
            type={showPassword ? 'text' : 'password'}
            value={confirmPassword}
            onChange={e => { setConfirmPassword(e.target.value); setError(''); }}
            placeholder="Repeat password"
            autoComplete="new-password"
            className={`input-field ${confirmPassword && confirmPassword !== password ? 'border-error focus:border-error' : ''}`}
          />
        </Field>

        {error && <FormError msg={error} />}

        <button
          type="submit"
          disabled={loading}
          className="w-full btn-primary px-6 py-3 rounded-md text-on-primary font-semibold shadow-lg transition-all hover:scale-[1.02] active:scale-95 disabled:opacity-60 disabled:scale-100 mt-2"
        >
          {loading ? 'Creating account…' : 'Create Account'}
        </button>

        <Divider text="already have an account" />

        <p className="text-center text-sm text-on-surface-variant">
          <Link to="/login" className="text-primary font-semibold hover:underline">
            Sign in instead
          </Link>
        </p>
      </form>
    </AuthCard>
  );
}
