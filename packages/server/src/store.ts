/**
 * 内存存储：challenge 的一次性消费、过期与取消都在这里判定，
 * 保证"两个页面同时完成同一 challenge"只有一个能进入校验。
 * 不连接任何外部数据库，进程重启即清空。
 *
 * 凭据处置状态机（active / quarantined / revoked）也在此维护：
 * 克隆告警 → 隔离；操作员动作（维持隔离 / 撤销）带乐观版本；
 * 恢复注册完成 → 旧凭据撤销、双向关联。所有处置状态只能由服务端推进。
 */
import type {
  AuthenticationOptionsDTO,
  CeremonyKind,
  CeremonyStatus,
  CheckResult,
  CredentialDisposition,
  CredentialDispositionAction,
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
  disposition: CredentialDisposition;
  /** 单调递增：任何处置状态/关联变化都会 +1，操作员动作凭它做乐观并发 */
  dispositionVersion: number;
  /** 产生隔离的克隆告警仪式 id */
  cloneWarningCeremonyId?: string;
  /** 被恢复注册替代后，替代凭据 id */
  replacedByCredentialId?: string;
  /** 恢复凭据：替代了哪一枚异常凭据 */
  recoveryOfCredentialId?: string;
  /** 恢复凭据：对应的恢复注册仪式 id */
  recoveryCeremonyId?: string;
  dispositionHistory: DispositionEvent[];
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
  /** 恢复注册：目标异常凭据 id 与签发时快照的处置版本 */
  recovery?: { credentialId: string; dispositionVersion: number };
}

export type ConsumeOutcome =
  | { outcome: 'ok'; ceremony: CeremonyState }
  | { outcome: 'not_found' }
  | { outcome: 'consumed'; ceremony: CeremonyState }
  | { outcome: 'expired'; ceremony: CeremonyState }
  | { outcome: 'cancelled'; ceremony: CeremonyState };

export type DispositionApplyResult =
  | { ok: true; credential: StoredCredential }
  | {
      ok: false;
      code: FailureCode;
      message: string;
      /** 冲突/无效时返回服务端当前状态，便于调用方重新审阅；凭据不存在时为 undefined */
      current?: StoredCredential;
    };

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

  /** 记录恢复注册的目标凭据与版本快照（options 已通过校验） */
  attachRecovery(ceremony: CeremonyState, credentialId: string): void {
    const target = this.credentials.get(credentialId);
    if (!target) return;
    ceremony.recovery = { credentialId, dispositionVersion: target.dispositionVersion };
    (ceremony.options as RegistrationOptionsDTO).recoveryOf = credentialId;
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

  /**
   * 真实断言校验通过后发现计数器克隆：把凭据从 active 推进到 quarantined。
   * 只有首次告警产生状态变化；重复告警（隔离中的再次尝试在处置门禁就被拦截，
   * 不会走到这里）保持幂等。返回是否发生了状态推进。
   */
  quarantineOnCloneWarning(credentialId: string, ceremonyId: string): boolean {
    const cred = this.credentials.get(credentialId);
    if (!cred || cred.disposition !== 'active') return false;
    cred.disposition = 'quarantined';
    cred.dispositionVersion += 1;
    cred.cloneWarningCeremonyId = ceremonyId;
    cred.dispositionHistory.push({
      ceremonyId,
      disposition: 'quarantined',
      reason: 'clone_warning',
      detail: '真实断言签名校验通过，但计数器未严格递增：疑似克隆 authenticator，凭据自动隔离',
      at: new Date(this.now()).toISOString(),
    });
    return true;
  }

  /**
   * 操作员处置：维持隔离 / 撤销。expectedVersion 做乐观并发——
   * 另一个页面已先行处置时，后到的旧视图得到 disposition_conflict 与当前状态。
   */
  applyDisposition(
    credentialId: string,
    action: CredentialDispositionAction,
    expectedVersion: number | undefined,
  ): DispositionApplyResult {
    const cred = this.credentials.get(credentialId);
    if (!cred) {
      return {
        ok: false,
        code: 'unknown_credential',
        message: `凭据 ${credentialId} 不存在`,
      };
    }
    if (expectedVersion !== undefined && cred.dispositionVersion !== expectedVersion) {
      return {
        ok: false,
        code: 'disposition_conflict',
        message:
          `处置版本冲突：视图基于 v${expectedVersion}，服务端当前为 v${cred.dispositionVersion}` +
          `（${cred.disposition}），请重新审阅后再处置`,
        current: cred,
      };
    }

    if (action === 'maintain_quarantine') {
      if (cred.disposition !== 'quarantined') {
        return {
          ok: false,
          code: 'invalid_disposition_action',
          message: `维持隔离仅对隔离中的凭据有效，当前处置状态为 ${cred.disposition}`,
          current: cred,
        };
      }
      cred.dispositionVersion += 1;
      cred.dispositionHistory.push({
        ceremonyId: null,
        disposition: 'quarantined',
        reason: 'operator_maintain_quarantine',
        detail: '操作员审阅克隆告警后决定维持隔离，凭据继续不可用于新认证',
        at: new Date(this.now()).toISOString(),
      });
      return { ok: true, credential: cred };
    }

    if (action === 'revoke') {
      if (cred.disposition === 'revoked') {
        // 幂等：已是撤销态直接成功，避免重复点击产生歧义
        return { ok: true, credential: cred };
      }
      cred.disposition = 'revoked';
      cred.dispositionVersion += 1;
      cred.dispositionHistory.push({
        ceremonyId: null,
        disposition: 'revoked',
        reason: 'operator_revoke',
        detail: '操作员撤销该凭据：旧凭据即使仍留在软件 authenticator 中也不得再用',
        at: new Date(this.now()).toISOString(),
      });
      return { ok: true, credential: cred };
    }

    return {
      ok: false,
      code: 'invalid_disposition_action',
      message: `未知处置动作 ${String(action)}`,
      current: cred,
    };
  }

  /**
   * 恢复注册校验通过后调用：新凭据落库，旧异常凭据撤销并双向关联。
   * expectedVersion 来自 options 签发时的快照——options 签发与提交之间
   * 若有人先处置了旧凭据，本次恢复冲突失败，必须重新发起仪式。
   */
  completeRecovery(
    newCred: StoredCredential,
    ceremonyId: string,
  ):
    | { ok: true; newCredential: StoredCredential; oldCredential: StoredCredential }
    | {
        ok: false;
        code: FailureCode;
        message: string;
        current: StoredCredential | undefined;
      } {
    const ceremony = this.ceremonies.get(ceremonyId);
    const recovery = ceremony?.recovery;
    if (!recovery) {
      return {
        ok: false,
        code: 'recovery_target_invalid',
        message: '该注册仪式未关联恢复目标，不能按恢复流程完成',
        current: undefined,
      };
    }

    const old = this.credentials.get(recovery.credentialId);
    if (!old) {
      return {
        ok: false,
        code: 'recovery_target_invalid',
        message: '恢复目标凭据已不存在（服务端可能已重置），请重新审阅',
        current: undefined,
      };
    }
    if (old.dispositionVersion !== recovery.dispositionVersion) {
      return {
        ok: false,
        code: 'disposition_conflict',
        message:
          `恢复目标在 options 签发后被处置过（快照 v${recovery.dispositionVersion} → 当前 v${old.dispositionVersion}）` +
          `，本次恢复仪式作废，请用新 challenge 重新发起`,
        current: old,
      };
    }
    if (old.disposition === 'active') {
      return {
        ok: false,
        code: 'recovery_target_invalid',
        message: '恢复目标当前并非异常凭据（active），不能走恢复替代',
        current: old,
      };
    }

    newCred.recoveryOfCredentialId = old.credentialId;
    newCred.recoveryCeremonyId = ceremonyId;
    this.saveCredential(newCred);

    old.disposition = 'revoked';
    old.replacedByCredentialId = newCred.credentialId;
    old.dispositionVersion += 1;
    old.dispositionHistory.push({
      ceremonyId,
      disposition: 'revoked',
      reason: 'replaced_by_recovery',
      detail: `用户通过新的注册仪式建立替代凭据 ${newCred.credentialId}（完整 challenge/origin/RP ID/签名/UV 校验通过），旧凭据撤销`,
      at: new Date(this.now()).toISOString(),
    });
    return { ok: true, newCredential: newCred, oldCredential: old };
  }

  toCredentialInfo(c: StoredCredential): StoredCredentialInfo {
    return {
      credentialId: c.credentialId,
      rpId: c.rpId,
      userHandle: c.userHandle,
      userName: c.userName,
      counter: c.counter,
      resident: c.resident,
      createdAt: c.createdAt,
      publicKey: c.publicKey,
      disposition: c.disposition,
      dispositionVersion: c.dispositionVersion,
      cloneWarningCeremonyId: c.cloneWarningCeremonyId,
      replacedByCredentialId: c.replacedByCredentialId,
      recoveryOfCredentialId: c.recoveryOfCredentialId,
      recoveryCeremonyId: c.recoveryCeremonyId,
      dispositionHistory: c.dispositionHistory.map((e) => ({ ...e })),
    };
  }

  listCredentials(): StoredCredentialInfo[] {
    return [...this.credentials.values()].map((c) => this.toCredentialInfo(c));
  }

  credentialsForUser(userName: string): StoredCredential[] {
    return [...this.credentials.values()].filter((c) => c.userName === userName);
  }

  /** 可进入认证 allowCredentials 的凭据：隔离中仍列出（让服务端处置门禁产出可解释终态），已撤销的不列出 */
  authenticatableCredentials(userName?: string): StoredCredential[] {
    const all = userName
      ? this.credentialsForUser(userName)
      : [...this.credentials.values()];
    return all.filter((c) => c.disposition !== 'revoked');
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
