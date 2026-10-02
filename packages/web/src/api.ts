/** 服务端 API 客户端 */
import type {
  AssertionResponseDTO,
  AttestationResponseDTO,
  AuthenticationOptionsDTO,
  CeremonySummary,
  CredentialDispositionAction,
  RegistrationOptionsDTO,
  StoredCredentialInfo,
} from '@lab/shared';

export interface ServerConfig {
  rpId: string;
  rpName: string;
  expectedOrigins: string[];
  defaultTtlMs: number;
}

export interface ApiError {
  ok: false;
  code?: string;
  message?: string;
  /** 处置冲突时服务端返回的当前凭据快照 */
  current?: StoredCredentialInfo;
  checks?: unknown;
}

async function http<T>(method: string, url: string, body?: unknown): Promise<{ status: number; data: T }> {
  const res = await fetch(url, {
    method,
    headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = (await res.json()) as T;
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
    recoveryOf?: string;
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
  credentials: () => http<StoredCredentialInfo[]>('GET', '/api/credentials'),
  disposition: (id: string, body: { action: CredentialDispositionAction; expectedVersion?: number }) =>
    http<{ ok: true; credential: StoredCredentialInfo } | ApiError>('POST', `/api/credentials/${id}/disposition`, body),
  reset: () => http<{ ok: boolean }>('POST', '/api/reset'),
};
