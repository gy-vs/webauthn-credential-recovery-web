/**
 * 内存存储：challenge 的一次性消费、过期与取消都在这里判定，
 * 保证"两个页面同时完成同一 challenge"只有一个能进入校验。
 * 不连接任何外部数据库，进程重启即清空。
 */
import type {
  AuthenticationOptionsDTO,
  CeremonyKind,
  CeremonyStatus,
  CheckResult,
  FailureCode,
  RegistrationOptionsDTO,
  StoredCredentialInfo,
} from '@lab/shared';
import { randomId } from '@lab/shared';

export interface StoredCredential {
  credentialId: string;
  publicKey: { x: string; y: string };
  counter: number;
  userHandle: string;
  userName: string;
  rpId: string;
  resident: boolean;
  createdAt: string;
}

export interface CeremonyState {
  id: string;
  kind: CeremonyKind;
  status: CeremonyStatus;
  challenge: string;
  options: RegistrationOptionsDTO | AuthenticationOptionsDTO;
  createdAt: number;
  expiresAt: number;
  consumed: boolean;
  failureCode?: FailureCode;
  failureMessage?: string;
  cloneWarning?: boolean;
  checks: CheckResult[];
  credentialId?: string;
}

export type ConsumeOutcome =
  | { outcome: 'ok'; ceremony: CeremonyState }
  | { outcome: 'not_found' }
  | { outcome: 'consumed'; ceremony: CeremonyState }
  | { outcome: 'expired'; ceremony: CeremonyState }
  | { outcome: 'cancelled'; ceremony: CeremonyState };

export class LabStore {
  private readonly ceremonies = new Map<string, CeremonyState>();
  private readonly credentials = new Map<string, StoredCredential>();
  private readonly users = new Map<string, { id: string; name: string; displayName: string }>();

  constructor(private readonly now: () => number = () => Date.now()) {}

  // ---- 用户（内存） ----

  getOrCreateUser(name: string): { id: string; name: string; displayName: string } {
    const existing = this.users.get(name);
    if (existing) return existing;
    const user = { id: randomId(), name, displayName: name };
    this.users.set(name, user);
    return user;
  }

  // ---- 仪式 / challenge ----

  createCeremony(
    kind: CeremonyKind,
    challenge: string,
    options: RegistrationOptionsDTO | AuthenticationOptionsDTO,
    ttlMs: number,
  ): CeremonyState {
    const now = this.now();
    const ceremony: CeremonyState = {
      id: randomId(),
      kind,
      status: 'pending',
      challenge,
      options: { ...options, ceremonyId: '' } as CeremonyState['options'],
      createdAt: now,
      expiresAt: now + ttlMs,
      consumed: false,
      checks: [],
    };
    (ceremony.options as { ceremonyId: string }).ceremonyId = ceremony.id;
    (ceremony.options as { expiresAt: number }).expiresAt = ceremony.expiresAt;
    this.ceremonies.set(ceremony.id, ceremony);
    return ceremony;
  }

  getCeremony(id: string): CeremonyState | undefined {
    return this.ceremonies.get(id);
  }

  /**
   * 一次性消费 challenge。同步执行、无 await——
   * 并发到达的两个请求中只有一个能拿到 'ok'。
   */
  consume(id: string): ConsumeOutcome {
    const ceremony = this.ceremonies.get(id);
    if (!ceremony) return { outcome: 'not_found' };
    if (ceremony.status === 'cancelled') return { outcome: 'cancelled', ceremony };
    if (ceremony.consumed) return { outcome: 'consumed', ceremony };
    if (this.now() > ceremony.expiresAt) {
      ceremony.status = 'expired';
      return { outcome: 'expired', ceremony };
    }
    ceremony.consumed = true;
    return { outcome: 'ok', ceremony };
  }

  cancel(id: string): CeremonyState | undefined {
    const ceremony = this.ceremonies.get(id);
    if (!ceremony) return undefined;
    if (ceremony.status === 'pending' && !ceremony.consumed) {
      ceremony.status = 'cancelled';
    }
    return ceremony;
  }

  complete(id: string, result: { checks: CheckResult[]; credentialId: string; cloneWarning?: boolean }): void {
    const ceremony = this.ceremonies.get(id);
    if (!ceremony) return;
    ceremony.status = result.cloneWarning ? 'completed_with_clone_warning' : 'completed';
    ceremony.checks = result.checks;
    ceremony.credentialId = result.credentialId;
    ceremony.cloneWarning = result.cloneWarning;
  }

  fail(id: string, code: FailureCode, message: string, checks: CheckResult[]): void {
    const ceremony = this.ceremonies.get(id);
    if (!ceremony) return;
    ceremony.status = 'failed';
    ceremony.failureCode = code;
    ceremony.failureMessage = message;
    ceremony.checks = checks;
  }

  /** 惰性过期扫描（供列表展示），返回新过期的仪式 */
  sweepExpired(): CeremonyState[] {
    const now = this.now();
    const expired: CeremonyState[] = [];
    for (const c of this.ceremonies.values()) {
      if (c.status === 'pending' && !c.consumed && now > c.expiresAt) {
        c.status = 'expired';
        expired.push(c);
      }
    }
    return expired;
  }

  listCeremonies(): CeremonyState[] {
    this.sweepExpired();
    return [...this.ceremonies.values()].sort((a, b) => b.createdAt - a.createdAt);
  }

  // ---- 凭据 ----

  credentialExists(credentialId: string): boolean {
    return this.credentials.has(credentialId);
  }

  getCredential(credentialId: string): StoredCredential | undefined {
    return this.credentials.get(credentialId);
  }

  saveCredential(cred: StoredCredential): void {
    this.credentials.set(cred.credentialId, cred);
  }

  updateCounter(credentialId: string, counter: number): void {
    const cred = this.credentials.get(credentialId);
    if (cred) cred.counter = Math.max(cred.counter, counter);
  }

  listCredentials(): StoredCredentialInfo[] {
    return [...this.credentials.values()].map((c) => ({
      credentialId: c.credentialId,
      rpId: c.rpId,
      userHandle: c.userHandle,
      userName: c.userName,
      counter: c.counter,
      resident: c.resident,
      createdAt: c.createdAt,
      publicKey: c.publicKey,
    }));
  }

  credentialsForUser(userName: string): StoredCredential[] {
    return [...this.credentials.values()].filter((c) => c.userName === userName);
  }

  allCredentials(): StoredCredential[] {
    return [...this.credentials.values()];
  }

  reset(): void {
    this.ceremonies.clear();
    this.credentials.clear();
    this.users.clear();
  }
}
