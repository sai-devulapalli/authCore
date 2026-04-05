import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context';
import type { UserInfo } from '../api/client';

export function Dashboard() {
  const { client, sessionToken, user: cachedUser, clearSession } = useAuth();
  const navigate = useNavigate();
  const [user, setUser] = useState<UserInfo | null>(cachedUser);
  const [loading, setLoading] = useState(!cachedUser);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!client || !sessionToken || cachedUser) { setLoading(false); return; }
    client.getUserInfo(sessionToken)
      .then(setUser)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [client, sessionToken, cachedUser]);

  const handleLogout = async () => {
    if (client && sessionToken) {
      try { await client.logout(sessionToken); } catch { /* ignore */ }
    }
    clearSession();
    navigate('/login');
  };

  const initials = user?.name
    ? user.name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2)
    : user?.email?.[0]?.toUpperCase() ?? '?';

  return (
    <div className="min-h-screen bg-background">
      {/* Top bar */}
      <header className="h-16 bg-white/80 backdrop-blur-md border-b border-outline-variant/20 flex items-center justify-between px-8 sticky top-0 z-10">
        <div className="flex items-center gap-2">
          <span className="font-extrabold text-on-surface text-lg tracking-tight">AuthPlex</span>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-full bg-primary-container flex items-center justify-center text-primary text-xs font-bold">
              {initials}
            </div>
            <span className="text-sm font-medium text-on-surface hidden sm:block">{user?.name || user?.email}</span>
          </div>
          <button
            onClick={handleLogout}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium text-on-surface-variant hover:bg-surface-container-high transition-colors"
          >
            <span className="material-symbols-outlined text-base" aria-hidden="true">logout</span>
            <span className="hidden sm:block">Sign out</span>
          </button>
        </div>
      </header>

      <main className="max-w-2xl mx-auto px-6 py-12">
        {loading ? (
          <div className="flex items-center gap-3 text-primary font-medium">
            <svg className="animate-spin h-5 w-5" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
            </svg>
            Loading…
          </div>
        ) : error ? (
          <div className="flex items-center gap-3 p-4 bg-error-container text-on-error-container rounded-md">
            <span className="material-symbols-outlined" aria-hidden="true">error</span>
            {error}
          </div>
        ) : user ? (
          <div className="space-y-6">
            {/* Welcome card */}
            <div className="bg-surface-container-lowest rounded-xl ghost-border p-8 flex items-center gap-6">
              <div className="w-16 h-16 rounded-full bg-primary-container flex items-center justify-center text-primary text-2xl font-bold shrink-0">
                {initials}
              </div>
              <div>
                <h1 className="text-2xl font-extrabold text-on-surface tracking-tight">
                  {user.name ? `Hello, ${user.name.split(' ')[0]}` : 'Hello'}
                </h1>
                <p className="text-on-surface-variant text-sm mt-0.5">{user.email}</p>
              </div>
            </div>

            {/* Profile info */}
            <div className="bg-surface-container-lowest rounded-xl ghost-border overflow-hidden">
              <div className="px-6 py-4 border-b border-outline-variant/10">
                <h2 className="text-sm font-bold text-on-surface">Account Details</h2>
              </div>
              <dl className="divide-y divide-outline-variant/10">
                {[
                  { label: 'User ID', value: user.sub, mono: true },
                  { label: 'Email', value: user.email },
                  { label: 'Email verified', value: user.email_verified ? 'Yes' : 'Not yet' },
                  ...(user.name ? [{ label: 'Name', value: user.name }] : []),
                ].map(({ label, value, mono }) => (
                  <div key={label} className="flex items-center justify-between px-6 py-4">
                    <dt className="text-[10px] font-bold text-on-surface-variant tracking-widest uppercase">{label}</dt>
                    <dd className={`text-sm text-on-surface ${mono ? 'font-mono text-xs bg-surface-container-high px-2 py-0.5 rounded' : ''}`}>
                      {value}
                    </dd>
                  </div>
                ))}
              </dl>
            </div>

          </div>
        ) : null}
      </main>
    </div>
  );
}
