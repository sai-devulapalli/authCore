import { createContext, useContext, useState, useCallback, type ReactNode } from 'react';
import { AuthPlexWebClient, type UserInfo } from './api/client';

const SERVER_URL = import.meta.env.VITE_AUTHPLEX_SERVER_URL as string;
const TENANT_ID = import.meta.env.VITE_AUTHPLEX_TENANT_ID as string;

if (!SERVER_URL || !TENANT_ID) {
  throw new Error('VITE_AUTHPLEX_SERVER_URL and VITE_AUTHPLEX_TENANT_ID must be set');
}

const client = new AuthPlexWebClient(SERVER_URL, TENANT_ID);

interface AuthContextType {
  client: AuthPlexWebClient;
  sessionToken: string | null;
  user: UserInfo | null;
  pendingMFAToken: string | null;
  setSession: (token: string, user: UserInfo) => void;
  setPendingMFA: (token: string) => void;
  clearSession: () => void;
}

const AuthContext = createContext<AuthContextType>({
  client,
  sessionToken: null, user: null, pendingMFAToken: null,
  setSession: () => {}, setPendingMFA: () => {}, clearSession: () => {},
});

export function useAuth() { return useContext(AuthContext); }

function loadSession() {
  const token = sessionStorage.getItem('authplex_session');
  const raw = sessionStorage.getItem('authplex_user');
  const user: UserInfo | null = raw ? JSON.parse(raw) : null;
  return { token, user };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const { token: initToken, user: initUser } = loadSession();
  const [sessionToken, setSessionToken] = useState<string | null>(initToken);
  const [user, setUser] = useState<UserInfo | null>(initUser);
  const [pendingMFAToken, setPendingMFAToken] = useState<string | null>(null);

  const setSession = useCallback((token: string, u: UserInfo) => {
    sessionStorage.setItem('authplex_session', token);
    sessionStorage.setItem('authplex_user', JSON.stringify(u));
    setSessionToken(token);
    setUser(u);
    setPendingMFAToken(null);
  }, []);

  const setPendingMFA = useCallback((token: string) => {
    setPendingMFAToken(token);
  }, []);

  const clearSession = useCallback(() => {
    sessionStorage.removeItem('authplex_session');
    sessionStorage.removeItem('authplex_user');
    setSessionToken(null);
    setUser(null);
    setPendingMFAToken(null);
  }, []);

  return (
    <AuthContext.Provider value={{ client, sessionToken, user, pendingMFAToken, setSession, setPendingMFA, clearSession }}>
      {children}
    </AuthContext.Provider>
  );
}
