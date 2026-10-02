/**
 * 工作台共享类型：DTO、仪式记录、终态与错误码。
 * 所有二进制字段在 JSON 中均为 base64url（无填充）。
 */

export type B64u = string;

export type UserVerification = 'required' | 'preferred' | 'discouraged';
export type ResidentKey = 'required' | 'preferred' | 'discouraged';
export type AttestationConveyance = 'none' | 'direct';

export interface PublicKeyCredentialDescriptorJSON {
  type: 'public-key';
  id: B64u;
  transports?: string[];
}

export interface RegistrationOptionsDTO {
  ceremonyId: string;
  rp: { id: string; name: string };
  user: { id: B64u; name: string; displayName: string };
  challenge: B64u;
  pubKeyCredParams: Array<{ type: 'public-key'; alg: -7 }>;
  authenticatorSelection: {
    residentKey: ResidentKey;
    userVerification: UserVerification;
  };
  attestation: AttestationConveyance;
  excludeCredentials: PublicKeyCredentialDescriptorJSON[];
  /** 恢复注册：替代哪一枚处于隔离中的异常凭据（服务端在签发时校验并快照版本） */
  recoveryOf?: B64u;
  /** 服务端绝对过期时间（epoch ms） */
  expiresAt: number;
  timeout: number;
}

export interface AuthenticationOptionsDTO {
  ceremonyId: string;
  rpId: string;
  challenge: B64u;
  allowCredentials: PublicKeyCredentialDescriptorJSON[];
  userVerification: UserVerification;
  expiresAt: number;
  timeout: number;
}

export interface AttestationResponseDTO {
  ceremonyId: string;
  credentialId: B64u;
  clientDataJSON: B64u;
  attestationObject: B64u;
  transports?: string[];
  /** 客户端自报的 resident 提示（仅用于工作台展示，服务端不参与校验） */
  residentHint?: boolean;
}

export interface AssertionResponseDTO {
  ceremonyId: string;
  credentialId: B64u;
  clientDataJSON: B64u;
  authenticatorData: B64u;
  signature: B64u;
  userHandle: B64u | null;
}

/** 服务端执行的每一项检查，用于可解释终态 */
export interface CheckResult {
  check: string;
  ok: boolean;
  detail?: string;
}

export type FailureCode =
  | 'challenge_not_found'
  | 'challenge_consumed'
  | 'challenge_expired'
  | 'ceremony_cancelled'
  | 'type_mismatch'
  | 'challenge_mismatch'
  | 'origin_mismatch'
  | 'rp_id_mismatch'
  | 'up_flag_missing'
  | 'uv_required'
  | 'attestation_verification_failed'
  | 'bad_signature'
  | 'duplicate_credential'
  | 'unknown_credential'
  | 'user_handle_mismatch'
  | 'bad_format'
  // 异常凭据处置
  | 'credential_quarantined'
  | 'credential_revoked'
  | 'invalid_disposition_action'
  | 'disposition_conflict'
  | 'recovery_target_invalid';

export type CeremonyKind = 'registration' | 'authentication';

export type CeremonyStatus =
  | 'pending'
  | 'completed'
  | 'completed_with_clone_warning'
  | 'failed'
  | 'cancelled'
  | 'expired';

/** 客户端仪式记录中的一步：名称 + 输入 + 输出（JSON 可序列化，无私钥） */
export interface StepEntry {
  name: string;
  at: string; // ISO 时间（来自可注入时钟）
  actor: 'client' | 'authenticator' | 'server';
  input?: unknown;
  output?: unknown;
  note?: string;
}

/** 可导出 / 可重新导入检查的仪式记录。绝不包含私钥材料。 */
export interface CeremonyRecord {
  version: 1;
  kind: CeremonyKind;
  ceremonyId: string;
  startedAt: string;
  finishedAt: string | null;
  origin: string;
  rpId: string;
  userVerification: UserVerification;
  residentKey?: ResidentKey;
  attestation?: AttestationConveyance;
  options: RegistrationOptionsDTO | AuthenticationOptionsDTO;
  clientDataJSON: B64u;
  /** 凭据公钥（公开材料，用于导入后重放校验签名） */
  credentialPublicKey?: { kty: 'EC2'; alg: -7; crv: 'P-256'; x: B64u; y: B64u };
  attestationObject?: B64u;
  authenticatorData?: B64u;
  signature?: B64u;
  userHandle?: B64u | null;
  serverResult: {
    status: CeremonyStatus;
    failureCode?: FailureCode;
    failureMessage?: string;
    cloneWarning?: boolean;
    /** 认证/注册终态后该凭据在服务端的处置状态（克隆告警后为 quarantined 等） */
    credentialDisposition?: CredentialDisposition;
    /** 恢复注册完成后，与原异常凭据的关联 */
    recovery?: {
      recoveryOfCredentialId: B64u;
      replacedByCredentialId: B64u;
      cloneWarningCeremonyId?: string;
    };
    checks: CheckResult[];
  };
  steps: StepEntry[];
}

/**
 * 凭据处置状态（服务端权威，前端只展示不持有）：
 * - active：正常可用
 * - quarantined：计数器克隆告警后隔离，不能完成新认证，等待操作员审阅
 * - revoked：操作员撤销或被恢复仪式替代，永久不可再用（即使私钥仍留在某 authenticator 中）
 */
export type CredentialDisposition = 'active' | 'quarantined' | 'revoked';

/** 凭据处置动作 */
export type CredentialDispositionAction = 'maintain_quarantine' | 'revoke';

/** 处置状态变更证据（全部为公开信息，不含私钥；时间来自可注入时钟） */
export interface DispositionEvent {
  /** 触发该状态的仪式 id（克隆告警仪式 / 恢复注册仪式）；操作员手动动作为 null */
  ceremonyId: string | null;
  /** 变更后的处置状态 */
  disposition: CredentialDisposition;
  /** 导致状态变化的原因码 */
  reason:
    | 'enrolled'
    | 'clone_warning'
    | 'operator_maintain_quarantine'
    | 'operator_revoke'
    | 'replaced_by_recovery';
  detail: string;
  at: string;
}

export interface StoredCredentialInfo {
  credentialId: B64u;
  rpId: string;
  userHandle: B64u;
  userName: string;
  counter: number;
  resident: boolean;
  createdAt: string;
  publicKey: { x: B64u; y: B64u };
  /** 当前处置状态（服务端权威） */
  disposition: CredentialDisposition;
  /** 单调递增的处置版本，操作员动作通过它做乐观并发 */
  dispositionVersion: number;
  /** 产生隔离/撤销的克隆告警仪式 id（若有） */
  cloneWarningCeremonyId?: string;
  /** 恢复注册建立的替代凭据 id（旧凭据被替代时） */
  replacedByCredentialId?: B64u;
  /** 该凭据替代了哪一枚异常凭据（恢复凭据上存在） */
  recoveryOfCredentialId?: B64u;
  /** 关联的恢复注册仪式 id（恢复凭据上存在） */
  recoveryCeremonyId?: string;
  dispositionHistory: DispositionEvent[];
}

export interface CeremonySummary {
  ceremonyId: string;
  kind: CeremonyKind;
  status: CeremonyStatus;
  failureCode?: FailureCode;
  failureMessage?: string;
  cloneWarning?: boolean;
  createdAt: string;
  expiresAt: number;
  /** 该仪式涉及的凭据 id（完成后落库） */
  credentialId?: string;
}
