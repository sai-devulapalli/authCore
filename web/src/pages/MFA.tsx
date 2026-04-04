import { useState, useRef, type FormEvent, type KeyboardEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context';
import { AuthCard, FormError } from './Setup';

export function MFA() {
  const { client, pendingMFAToken, setSession } = useAuth();
  const navigate = useNavigate();
  const [digits, setDigits] = useState(['', '', '', '', '', '']);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const refs = Array.from({ length: 6 }, () => useRef<HTMLInputElement>(null));

  if (!pendingMFAToken) {
    navigate('/login');
    return null;
  }

  const code = digits.join('');

  const handleDigit = (i: number, val: string) => {
    const digit = val.replace(/\D/g, '').slice(-1);
    const next = [...digits];
    next[i] = digit;
    setDigits(next);
    setError('');
    if (digit && i < 5) refs[i + 1].current?.focus();
    if (next.every(d => d) && next.join('').length === 6) {
      submitCode(next.join(''));
    }
  };

  const handleKey = (i: number, e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !digits[i] && i > 0) {
      refs[i - 1].current?.focus();
    }
    if (e.key === 'ArrowLeft' && i > 0) refs[i - 1].current?.focus();
    if (e.key === 'ArrowRight' && i < 5) refs[i + 1].current?.focus();
  };

  const handlePaste = (e: React.ClipboardEvent) => {
    const text = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
    if (text.length === 6) {
      setDigits(text.split(''));
      submitCode(text);
    }
  };

  const submitCode = async (c: string) => {
    if (!client || !pendingMFAToken) return;
    setLoading(true);
    setError('');
    try {
      const res = await client.verifyMFA(pendingMFAToken, c);
      const userInfo = await client.getUserInfo(res.session_token);
      setSession(res.session_token, userInfo);
      navigate('/dashboard');
    } catch (e) {
      setError((e as Error).message);
      setDigits(['', '', '', '', '', '']);
      refs[0].current?.focus();
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (code.length === 6) submitCode(code);
  };

  return (
    <AuthCard
      title="Two-factor auth"
      subtitle="Enter the 6-digit code from your authenticator app"
      icon="phonelink_lock"
    >
      <form onSubmit={handleSubmit} className="space-y-8">
        {/* OTP digit boxes */}
        <div className="flex gap-2 justify-center" onPaste={handlePaste}>
          {digits.map((d, i) => (
            <input
              key={i}
              ref={refs[i]}
              type="text"
              inputMode="numeric"
              maxLength={1}
              value={d}
              onChange={e => handleDigit(i, e.target.value)}
              onKeyDown={e => handleKey(i, e)}
              autoFocus={i === 0}
              className={`w-11 h-14 text-center text-xl font-bold text-on-surface bg-surface-container-low border-2 rounded-xl transition-colors focus:outline-none focus:ring-0 ${
                d
                  ? 'border-primary bg-primary-container/20'
                  : 'border-outline-variant/40 focus:border-primary'
              }`}
            />
          ))}
        </div>

        {error && <FormError msg={error} />}

        <button
          type="submit"
          disabled={code.length < 6 || loading}
          className="w-full btn-primary px-6 py-3 rounded-md text-on-primary font-semibold shadow-lg transition-all hover:scale-[1.02] active:scale-95 disabled:opacity-40 disabled:scale-100"
        >
          {loading ? 'Verifying…' : 'Verify'}
        </button>

        <p className="text-center text-xs text-on-surface-variant/60">
          Lost access to your authenticator?{' '}
          <button type="button" className="text-primary hover:underline" onClick={() => navigate('/login')}>
            Back to sign in
          </button>
        </p>
      </form>
    </AuthCard>
  );
}
