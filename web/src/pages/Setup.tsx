import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context';

export function Setup() {
  const { configure, config } = useAuth();
  const navigate = useNavigate();
  const [serverUrl, setServerUrl] = useState(config?.serverUrl ?? 'http://localhost:8081');
  const [tenantId, setTenantId] = useState(config?.tenantId ?? '');
  const [error, setError] = useState('');

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (!serverUrl.trim()) { setError('Server URL is required'); return; }
    if (!tenantId.trim()) { setError('Tenant ID is required'); return; }
    configure(serverUrl.trim(), tenantId.trim());
    navigate('/login');
  };

  return (
    <AuthCard
      title="Connect to AuthPlex"
      subtitle="Configure your server and tenant"
      icon="dns"
    >
      <form onSubmit={handleSubmit} className="space-y-6">
        <Field label="Server URL">
          <input
            type="url"
            value={serverUrl}
            onChange={e => { setServerUrl(e.target.value); setError(''); }}
            placeholder="http://localhost:8081"
            autoFocus
            className="input-field font-mono"
          />
        </Field>
        <Field label="Tenant ID">
          <input
            type="text"
            value={tenantId}
            onChange={e => { setTenantId(e.target.value); setError(''); }}
            placeholder="acme"
            className="input-field"
          />
        </Field>
        {error && <FormError msg={error} />}
        <button type="submit" className="w-full btn-primary px-6 py-3 rounded-md text-on-primary font-semibold shadow-lg transition-all hover:scale-[1.02] active:scale-95">
          Continue
        </button>
      </form>
    </AuthCard>
  );
}

// ── Shared layout components (used by all auth pages) ────────────────────────

export function AuthCard({ title, subtitle, icon, children }: {
  title: string; subtitle?: string; icon?: string; children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          {icon && (
            <div className="inline-flex items-center justify-center w-14 h-14 rounded-full bg-primary-container mb-4">
              <span className="material-symbols-outlined text-2xl text-primary" aria-hidden="true">{icon}</span>
            </div>
          )}
          <h1 className="text-2xl font-extrabold text-on-surface tracking-tight">{title}</h1>
          {subtitle && <p className="text-sm text-on-surface-variant mt-1">{subtitle}</p>}
        </div>
        <div className="bg-surface-container-lowest rounded-xl ghost-border shadow-[0_12px_40px_rgba(0,50,101,0.08)]">
          <div className="px-8 py-8">{children}</div>
        </div>
      </div>
    </div>
  );
}

export function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <label className="field-label">{label}</label>
      {children}
    </div>
  );
}

export function FormError({ msg }: { msg: string }) {
  return (
    <div className="flex items-center gap-1.5 text-error text-[11px] font-medium">
      <span className="material-symbols-outlined text-sm" aria-hidden="true">error</span>
      {msg}
    </div>
  );
}

export function Divider({ text }: { text: string }) {
  return (
    <div className="flex items-center gap-3 my-1">
      <div className="flex-1 h-px bg-outline-variant/30" />
      <span className="text-[10px] text-on-surface-variant/50 uppercase tracking-widest font-medium">{text}</span>
      <div className="flex-1 h-px bg-outline-variant/30" />
    </div>
  );
}
