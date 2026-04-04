import { createContext, useContext, useState, useCallback, type ReactNode } from 'react';
import { AuthPlexWebClient, type UserInfo } from './api/client';

interface Config {
  serverUrl: string;
  tenantId: string;
}

interface AuthContextType {
  config: Config | null;
  client: AuthPlexWebClient | null;
  sessionToken: string | null;
  user: UserInfo | null;
  pendingMFAToken: string | null;
  configure: (serverUrl: string, tenantId: string) => void;
  setSession: (token: string, user: UserInfo) => void;
  setPendingMFA: (token: string) => void;
  clearSession: () => void;
}

const AuthContext = createContext<AuthContextType>({
  config: null, client: null, sessionToken: null, user: null, pendingMFAToken: null,
  configure: () => {}, setSession: () => {}, setPendingMFA: () => {}, clearSession: () => {},
});

export function useAuth() { return useContext(AuthContext); }

function loadConfig(): Config | null {
  const url = localStorage.getItem('authplex_server_url');
  const tid = localStorage.getItem('authplex_tenant_id');
  return url && tid ? { serverUrl: url, tenantId: tid } : null;
}

function loadSession() {
  const token = sessionStorage.getItem('authplex_session');
  const raw = sessionStorage.getItem('authplex_user');
  const user: UserInfo | null = raw ? JSON.parse(raw) : null;
  return { token, user };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [config, setConfig] = useState<Config | null>(loadConfig);
  const [client, setClient] = useState<AuthPlexWebClient | null>(() => {
    const c = loadConfig();
    return c ? new AuthPlexWebClient(c.serverUrl, c.tenantId) : null;
  });

  const { token: initToken, user: initUser } = loadSession();
  const [sessionToken, setSessionToken] = useState<string | null>(initToken);
  const [user, setUser] = useState<UserInfo | null>(initUser);
  const [pendingMFAToken, setPendingMFAToken] = useState<string | null>(null);

  const configure = useCallback((serverUrl: string, tenantId: string) => {
    localStorage.setItem('authplex_server_url', serverUrl);
    localStorage.setItem('authplex_tenant_id', tenantId);
    const c = { serverUrl, tenantId };
    setConfig(c);
    setClient(new AuthPlexWebClient(serverUrl, tenantId));
  }, []);

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
    <AuthContext.Provider value={{ config, client, sessionToken, user, pendingMFAToken, configure, setSession, setPendingMFA, clearSession }}>
      {children}
    </AuthContext.Provider>
  );
}
