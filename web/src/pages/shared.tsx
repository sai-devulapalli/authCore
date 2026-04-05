// Shared layout components used by all auth pages

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
