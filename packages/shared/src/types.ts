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
  | 'bad_format';

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
    checks: CheckResult[];
  };
  steps: StepEntry[];
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
}
