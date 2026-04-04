import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context';
import { Setup } from './pages/Setup';
import { Login } from './pages/Login';
import { Register } from './pages/Register';
import { MFA } from './pages/MFA';
import { ForgotPassword } from './pages/ForgotPassword';
import { Dashboard } from './pages/Dashboard';
import type { ReactNode } from 'react';

function RequireAuth({ children }: { children: ReactNode }) {
  const { sessionToken } = useAuth();
  if (!sessionToken) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

function RequireConfig({ children }: { children: ReactNode }) {
  const { config } = useAuth();
  if (!config) return <Navigate to="/setup" replace />;
  return <>{children}</>;
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/setup" element={<Setup />} />
      <Route path="/login" element={<RequireConfig><Login /></RequireConfig>} />
      <Route path="/register" element={<RequireConfig><Register /></RequireConfig>} />
      <Route path="/mfa" element={<RequireConfig><MFA /></RequireConfig>} />
      <Route path="/forgot-password" element={<RequireConfig><ForgotPassword /></RequireConfig>} />
      <Route path="/dashboard" element={<RequireAuth><Dashboard /></RequireAuth>} />
      <Route path="/" element={<Navigate to="/login" replace />} />
      <Route path="*" element={<Navigate to="/login" replace />} />
    </Routes>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}
