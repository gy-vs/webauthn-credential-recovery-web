/** 服务端 API 客户端 */
import type {
  AssertionResponseDTO,
  AttestationResponseDTO,
  AuthenticationOptionsDTO,
  CeremonySummary,
  CredentialDispositionInfo,
  RegistrationOptionsDTO,
  StoredCredentialInfo,
} from '@lab/shared';

export interface ServerConfig {
  rpId: string;
  rpName: string;
  expectedOrigins: string[];
  defaultTtlMs: number;
}

/** 4xx 响应：携带服务端给出的当前状态，便于旧视图重新审阅 */
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string | undefined,
    message: string,
    public readonly data: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function http<T>(method: string, url: string, body?: unknown): Promise<{ status: number; data: T }> {
  const res = await fetch(url, {
    method,
    headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = (await res.json()) as T;
  if (!res.ok) {
    const d = data as Record<string, unknown>;
    throw new ApiError(res.status, typeof d.code === 'string' ? d.code : undefined, typeof d.message === 'string' ? d.message : `HTTP ${res.status}`, d);
  }
  return { status: res.status, data };
}

export const api = {
  config: () => http<ServerConfig>('GET', '/api/config'),
  registerOptions: (body: {
    userName: string;
    residentKey: string;
    userVerification: string;
    attestation: string;
    ttlMs?: number;
    replacesCredentialId?: string | null;
  }) => http<RegistrationOptionsDTO>('POST', '/api/register/options', body),
  registerResult: (body: AttestationResponseDTO) =>
    http<Record<string, unknown>>('POST', '/api/register/result', body),
  authenticateOptions: (body: {
    userName?: string;
    userVerification: string;
    discoverable?: boolean;
    ttlMs?: number;
  }) => http<AuthenticationOptionsDTO>('POST', '/api/authenticate/options', body),
  authenticateResult: (body: AssertionResponseDTO) =>
    http<Record<string, unknown>>('POST', '/api/authenticate/result', body),
  cancelCeremony: (id: string) => http<{ ceremonyId: string; status: string }>('POST', `/api/ceremonies/${id}/cancel`),
  ceremonies: () => http<CeremonySummary[]>('GET', '/api/ceremonies'),
  ceremony: (id: string) => http<Record<string, unknown>>('GET', `/api/ceremonies/${id}`),
  credentials: () => http<StoredCredentialInfo[]>('GET', '/api/credentials'),
  disposition: (
    id: string,
    body: { action: 'maintain_quarantine' | 'revoke_operator'; expectedVersion: number; note?: string },
  ) => http<{ ok: true; credentialId: string; disposition: CredentialDispositionInfo }>(
    'POST',
    `/api/credentials/${encodeURIComponent(id)}/disposition`,
    body,
  ),
  reset: () => http<{ ok: boolean }>('POST', '/api/reset'),
};
