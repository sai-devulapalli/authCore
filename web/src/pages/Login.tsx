import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context';
import { AuthCard, Field, FormError, Divider } from './Setup';

export function Login() {
  const { client, config, setSession, setPendingMFA } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!client) { navigate('/setup'); return; }
    if (!email.trim() || !password) { setError('Email and password are required'); return; }
    setLoading(true);
    setError('');
    try {
      const res = await client.login(email.trim(), password);
      if (res.mfa_required) {
        setPendingMFA(res.session_token);
        navigate('/mfa');
        return;
      }
      const userInfo = await client.getUserInfo(res.session_token);
      setSession(res.session_token, userInfo);
      navigate('/dashboard');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthCard
      title="Welcome back"
      subtitle={config ? `Sign in to ${config.tenantId}` : 'Sign in to your account'}
      icon="person"
    >
      <form onSubmit={handleSubmit} className="space-y-6">
        <Field label="Email">
          <input
            type="email"
            value={email}
            onChange={e => { setEmail(e.target.value); setError(''); }}
            placeholder="you@example.com"
            autoFocus
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
              placeholder="••••••••"
              autoComplete="current-password"
              className="input-field pr-8"
            />
            <button
              type="button"
              onClick={() => setShowPassword(v => !v)}
              className="absolute right-0 top-2 text-on-surface-variant/50 hover:text-on-surface-variant transition-colors"
              tabIndex={-1}
            >
              <span className="material-symbols-outlined text-base" aria-hidden="true">
                {showPassword ? 'visibility_off' : 'visibility'}
              </span>
            </button>
          </div>
        </Field>

        <div className="flex justify-end -mt-2">
          <Link to="/forgot-password" className="text-xs text-primary hover:underline font-medium">
            Forgot password?
          </Link>
        </div>

        {error && <FormError msg={error} />}

        <button
          type="submit"
          disabled={loading}
          className="w-full btn-primary px-6 py-3 rounded-md text-on-primary font-semibold shadow-lg transition-all hover:scale-[1.02] active:scale-95 disabled:opacity-60 disabled:scale-100"
        >
          {loading ? 'Signing in…' : 'Sign In'}
        </button>

        <Divider text="or" />

        <p className="text-center text-sm text-on-surface-variant">
          Don't have an account?{' '}
          <Link to="/register" className="text-primary font-semibold hover:underline">
            Create one
          </Link>
        </p>
      </form>

      {/* Server/tenant indicator */}
      {config && (
        <div className="mt-6 pt-4 border-t border-outline-variant/20 flex items-center justify-between">
          <span className="text-[10px] text-on-surface-variant/50 font-mono truncate">
            {config.serverUrl} · {config.tenantId}
          </span>
          <Link to="/setup" className="text-[10px] text-primary hover:underline ml-2 shrink-0">change</Link>
        </div>
      )}
    </AuthCard>
  );
}
