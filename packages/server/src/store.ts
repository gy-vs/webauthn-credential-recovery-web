/**
 * 内存存储：challenge 的一次性消费、过期与取消都在这里判定，
 * 保证"两个页面同时完成同一 challenge"只有一个能进入校验。
 * 凭据处置（隔离 / 撤销 / 恢复替代）同样在这里做同步、原子的状态翻转，
 * 不连接任何外部数据库，进程重启即清空。
 */
import type {
  AuthenticationOptionsDTO,
  CeremonyKind,
  CeremonyStatus,
  CheckResult,
  CredentialDisposition,
  CredentialDispositionInfo,
  DispositionEvent,
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
  disposition: CredentialDispositionInfo;
}

/** 处置动作冲突结果（乐观版本 / 状态不符） */
export type DispositionConflict =
  | { ok: false; code: 'credential_not_found' }
  | { ok: false; code: 'disposition_conflict'; message: string; current: CredentialDispositionInfo; state: CredentialDisposition };

export type DispositionResult =
  | { ok: true; credential: StoredCredential }
  | DispositionConflict;

export interface RecoveryLinkResult {
  ok: true;
  oldCredential: StoredCredential;
}
export type RecoveryLinkOutcome =
  | RecoveryLinkResult
  | { ok: false; code: 'recovery_target_invalid'; message: string; state?: CredentialDisposition; current?: CredentialDispositionInfo };

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

  /** 新注册凭据的初始处置快照 */
  initialDisposition(nowIso: string): CredentialDispositionInfo {
    return { state: 'active', version: 0, updatedAt: nowIso, history: [] };
  }

  updateCounter(credentialId: string, counter: number): void {
    const cred = this.credentials.get(credentialId);
    if (cred) cred.counter = Math.max(cred.counter, counter);
  }

  listCredentials(): StoredCredentialInfo[] {
    return [...this.credentials.values()].map(this.toInfo);
  }

  /**
   * 可用于认证的凭据：只有 active 状态进入 allowCredentials。
   * 隔离/撤销凭据仍在凭据库中（可审阅、可被离线复检引用），但不会被签发。
   */
  credentialsForUser(userName: string): StoredCredential[] {
    return [...this.credentials.values()].filter(
      (c) => c.userName === userName && c.disposition.state === 'active',
    );
  }

  allCredentials(): StoredCredential[] {
    return [...this.credentials.values()];
  }

  private toInfo = (c: StoredCredential): StoredCredentialInfo => ({
    credentialId: c.credentialId,
    rpId: c.rpId,
    userHandle: c.userHandle,
    userName: c.userName,
    counter: c.counter,
    resident: c.resident,
    createdAt: c.createdAt,
    publicKey: c.publicKey,
    disposition: c.disposition,
  });

  // ---- 凭据处置：隔离 / 维持 / 撤销 / 恢复替代（同步、原子） ----

  private pushHistory(cred: StoredCredential, event: DispositionEvent): void {
    cred.disposition.history.push(event);
    cred.disposition.updatedAt = event.at;
  }

  /** 计数器克隆告警：把凭据从 active 原子地翻转为 quarantined。重复告警不重复翻转。 */
  quarantineForCloneWarning(credentialId: string, ceremonyId: string): StoredCredential | undefined {
    const cred = this.credentials.get(credentialId);
    if (!cred) return undefined;
    if (cred.disposition.state === 'active') {
      const at = new Date(this.now()).toISOString();
      const from = cred.disposition.state;
      cred.disposition.state = 'quarantined';
      cred.disposition.version += 1;
      cred.disposition.evidenceCeremonyId = ceremonyId;
      this.pushHistory(cred, {
        action: 'quarantine_clone_warning',
        ceremonyId,
        from,
        to: 'quarantined',
        at,
        note: '服务端校验真实断言后检测到计数器回退（疑似克隆），自动隔离',
      });
    }
    return cred;
  }

  /**
   * 操作员处置动作。必须携带该页面看到的 version：
   * 另一个页面已经先处置时，后到的旧视图得到 disposition_conflict，不能覆盖新决定。
   */
  applyDisposition(params: {
    credentialId: string;
    action: 'maintain_quarantine' | 'revoke_operator';
    expectedVersion: number;
    note?: string;
  }): DispositionResult {
    const cred = this.credentials.get(params.credentialId);
    if (!cred) return { ok: false, code: 'credential_not_found' };
    if (cred.disposition.version !== params.expectedVersion) {
      return this.conflict(
        cred,
        `凭据处置版本已变化：页面基于版本 ${params.expectedVersion}，当前为 ${cred.disposition.version}（可能已在另一页面处置），请刷新后重新审阅`,
      );
    }
    if (cred.disposition.state !== 'quarantined') {
      return this.conflict(
        cred,
        `凭据当前为 ${cred.disposition.state} 状态，不能执行 ${params.action}（只有隔离中的凭据可被维持/撤销）`,
      );
    }
    const at = new Date(this.now()).toISOString();
    if (params.action === 'maintain_quarantine') {
      const from = cred.disposition.state;
      cred.disposition.version += 1;
      this.pushHistory(cred, {
        action: 'maintain_quarantine',
        ceremonyId: null,
        from,
        to: 'quarantined',
        at,
        note: params.note || '操作员审阅后决定维持隔离',
      });
    } else {
      const from = cred.disposition.state;
      cred.disposition.state = 'revoked';
      cred.disposition.version += 1;
      this.pushHistory(cred, {
        action: 'revoke_operator',
        ceremonyId: null,
        from,
        to: 'revoked',
        at,
        note: params.note || '操作员审阅后撤销该凭据',
      });
    }
    return { ok: true, credential: cred };
  }

  private conflict(cred: StoredCredential, message: string): DispositionConflict {
    return {
      ok: false,
      code: 'disposition_conflict',
      message,
      current: cred.disposition,
      state: cred.disposition.state,
    };
  }

  /**
   * 恢复注册校验通过后，把被替代的隔离凭据原子地标记为 revoked（replaced）。
   * 必须仍为 quarantined 且版本与 options 签发时的快照一致——
   * 防止"先签发 options、另一页面先撤销/维持"后恢复仍覆盖决定。
   */
  linkRecovery(params: {
    oldCredentialId: string;
    expectedVersion: number;
    newCredentialId: string;
    ceremonyId: string;
  }): RecoveryLinkOutcome {
    const cred = this.credentials.get(params.oldCredentialId);
    if (!cred) {
      return { ok: false, code: 'recovery_target_invalid', message: `恢复目标凭据 ${params.oldCredentialId} 不存在` };
    }
    if (cred.disposition.state !== 'quarantined') {
      return {
        ok: false,
        code: 'recovery_target_invalid',
        message: `恢复目标凭据当前为 ${cred.disposition.state} 状态，只有隔离中的凭据可被恢复替代`,
        state: cred.disposition.state,
        current: cred.disposition,
      };
    }
    if (cred.disposition.version !== params.expectedVersion) {
      return {
        ok: false,
        code: 'recovery_target_invalid',
        message: `恢复目标凭据版本已变化（options 签发时为 ${params.expectedVersion}，当前为 ${cred.disposition.version}），请重新发起恢复仪式`,
        state: cred.disposition.state,
        current: cred.disposition,
      };
    }
    const at = new Date(this.now()).toISOString();
    const from = cred.disposition.state;
    cred.disposition.state = 'revoked';
    cred.disposition.version += 1;
    cred.disposition.replacedByCredentialId = params.newCredentialId;
    this.pushHistory(cred, {
      action: 'revoke_replaced',
      ceremonyId: params.ceremonyId,
      from,
      to: 'revoked',
      at,
      note: '用户通过新的注册仪式建立替代凭据，旧凭据自动撤销',
      relatedCredentialId: params.newCredentialId,
    });
    return { ok: true, oldCredential: cred };
  }

  /** 在新凭据上记录恢复关联（指向被替代的旧凭据） */
  markReplacement(newCredentialId: string, oldCredentialId: string): void {
    const cred = this.credentials.get(newCredentialId);
    if (!cred) return;
    cred.disposition.replacesCredentialId = oldCredentialId;
    cred.disposition.updatedAt = new Date(this.now()).toISOString();
  }

  reset(): void {
    this.ceremonies.clear();
    this.credentials.clear();
    this.users.clear();
  }
}
