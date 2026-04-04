export interface UserInfo {
  sub: string;
  email: string;
  email_verified: boolean;
  name?: string;
  phone_number?: string;
}

export interface LoginResponse {
  session_token: string;
  expires_in: number;
  mfa_required?: boolean;
}

export interface RegisterResponse {
  user_id: string;
  email: string;
  verification_sent: boolean;
}

export class AuthPlexWebClient {
  constructor(
    private serverUrl: string,
    private tenantId: string,
  ) {
    this.serverUrl = serverUrl.replace(/\/$/, '');
  }

  private async request<T>(path: string, options: RequestInit = {}, sessionToken?: string): Promise<T> {
    const res = await fetch(`${this.serverUrl}${path}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-ID': this.tenantId,
        ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
        ...options.headers,
      },
    });

    if (!res.ok) {
      const text = await res.text();
      let message = `HTTP ${res.status}`;
      try {
        const err = JSON.parse(text);
        message = err.error?.message || err.error || err.message || message;
      } catch {
        if (text) message = text;
      }
      throw new Error(message);
    }

    if (res.status === 204) return undefined as T;
    const json = await res.json();
    return json.data !== undefined ? json.data : json;
  }

  login(email: string, password: string): Promise<LoginResponse> {
    return this.request<LoginResponse>('/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  }

  register(email: string, password: string, name: string): Promise<RegisterResponse> {
    return this.request<RegisterResponse>('/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, name }),
    });
  }

  verifyMFA(sessionToken: string, code: string): Promise<LoginResponse> {
    return this.request<LoginResponse>('/mfa/verify', {
      method: 'POST',
      body: JSON.stringify({ session_token: sessionToken, code }),
    });
  }

  getUserInfo(sessionToken: string): Promise<UserInfo> {
    return this.request<UserInfo>('/userinfo', {}, sessionToken);
  }

  logout(sessionToken: string): Promise<void> {
    return this.request<void>('/logout', { method: 'POST' }, sessionToken);
  }

  requestOTP(email: string): Promise<void> {
    return this.request<void>('/otp/request', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  }

  verifyOTP(email: string, code: string): Promise<LoginResponse> {
    return this.request<LoginResponse>('/otp/verify', {
      method: 'POST',
      body: JSON.stringify({ email, code }),
    });
  }
}
