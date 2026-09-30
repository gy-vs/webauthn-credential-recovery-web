/**
 * 软件测试 authenticator：ES256、可注入时钟、可配置 UV 行为、
 * resident key 支持、签名计数器及测试钩子（回退计数器 / 强制复用 credential id）。
 * 私钥只活在内存句柄中，任何日志与导出都不会包含私钥材料。
 */
import { buildAuthData } from './authdata.js';
import { b64uDecode, b64uEncode, concatBytes } from './base64url.js';
import { cborEncode } from './cbor.js';
import type { CryptoProvider, EcPublicKey, KeyPairHandle } from './crypto-provider.js';
import { CodedError } from './errors.js';
import type { AttestationConveyance, ResidentKey, UserVerification } from './types.js';

export interface AuthenticatorConfig {
  aaguid?: Uint8Array;
  /** 可注入时钟，默认真实时间 */
  clock?: () => number;
  /** 是否支持用户验证 */
  uvSupported?: boolean;
  /** 本次仪式 UV 是否通过（模拟用户通过/拒绝验证） */
  uvResult?: boolean;
  /** 是否支持 discoverable（resident）凭据 */
  residentKeysSupported?: boolean;
  /** 计数器初始值 */
  counterStart?: number;
  /** 仪式步骤回调（仅公开材料） */
  onEvent?: (name: string, detail: Record<string, unknown>) => void;
}

export interface StoredCredential {
  credentialId: Uint8Array;
  privateKey: unknown;
  publicKey: EcPublicKey;
  rpId: string;
  userHandle: Uint8Array;
  userName: string;
  resident: boolean;
  counter: number;
  createdAt: number;
}

export interface MakeCredentialParams {
  rpId: string;
  userHandle: Uint8Array;
  userName: string;
  clientDataHash: Uint8Array;
  excludeCredentialIds?: string[]; // base64url
  residentKey: ResidentKey;
  userVerification: UserVerification;
  attestation: AttestationConveyance;
}

export interface MakeCredentialResult {
  credentialId: string; // base64url
  attestationObject: Uint8Array;
  publicKey: EcPublicKey;
  resident: boolean;
  counter: number;
}

export interface GetAssertionParams {
  rpId: string;
  /** undefined = discoverable 流程（allowCredentials 为空） */
  allowCredentialIds?: string[];
  clientDataHash: Uint8Array;
  userVerification: UserVerification;
}

export interface GetAssertionResult {
  credentialId: string;
  authenticatorData: Uint8Array;
  signature: Uint8Array;
  userHandle: Uint8Array;
  counter: number;
  publicKey: EcPublicKey;
}

export class SoftwareAuthenticator {
  readonly id: string;
  private readonly crypto: CryptoProvider;
  private readonly aaguid: Uint8Array;
  private readonly clock: () => number;
  private readonly onEvent: (name: string, detail: Record<string, unknown>) => void;
  uvSupported: boolean;
  uvResult: boolean;
  residentKeysSupported: boolean;
  private counterStart: number;
  private readonly creds = new Map<string, StoredCredential>();
  /** 测试钩子：强制下一次 makeCredential 复用该 credential id（制造重复 id 场景） */
  private forcedCredentialId: Uint8Array | null = null;

  constructor(crypto: CryptoProvider, config: AuthenticatorConfig = {}, id?: string) {
    this.crypto = crypto;
    this.id = id ?? `authn-${Math.random().toString(36).slice(2, 8)}`;
    this.aaguid = config.aaguid ?? new Uint8Array(16);
    this.clock = config.clock ?? (() => Date.now());
    this.uvSupported = config.uvSupported ?? true;
    this.uvResult = config.uvResult ?? true;
    this.residentKeysSupported = config.residentKeysSupported ?? true;
    this.counterStart = config.counterStart ?? 0;
    this.onEvent = config.onEvent ?? (() => {});
  }

  now(): number {
    return this.clock();
  }

  private uvFlag(required: UserVerification): boolean {
    if (required === 'required' && !this.uvSupported) {
      throw new CodedError('ConstraintError', 'user verification required but authenticator does not support it');
    }
    if (required === 'discouraged') return false;
    return this.uvSupported && this.uvResult;
  }

  async makeCredential(params: MakeCredentialParams): Promise<MakeCredentialResult> {
    const startedAt = new Date(this.clock()).toISOString();
    this.onEvent('authenticator.makeCredential.begin', {
      at: startedAt,
      rpId: params.rpId,
      userName: params.userName,
      residentKey: params.residentKey,
      userVerification: params.userVerification,
      attestation: params.attestation,
    });

    // 测试钩子生效时（强制复用 credential id）模拟"不守规矩的 authenticator"，
    // 跳过 excludeCredentials 检查，让服务端的 duplicate_credential 防线接管
    if (!this.forcedCredentialId) {
      for (const id of params.excludeCredentialIds ?? []) {
        if (this.creds.has(id)) {
          this.onEvent('authenticator.makeCredential.refused', { reason: 'excludeCredentials 命中本地凭据', credentialId: id });
          throw new CodedError('NotAllowedError', 'credential already registered on this authenticator (excludeCredentials)');
        }
      }
    } else {
      this.onEvent('authenticator.debug.ignoreExcludeCredentials', {
        reason: 'forcedCredentialId 生效，跳过 excludeCredentials（模拟异常 authenticator）',
      });
    }

    const wantResident = params.residentKey === 'required' || params.residentKey === 'preferred';
    if (params.residentKey === 'required' && !this.residentKeysSupported) {
      throw new CodedError('ConstraintError', 'resident key required but not supported');
    }
    const resident = wantResident && this.residentKeysSupported;
    const uv = this.uvFlag(params.userVerification);

    const keyPair: KeyPairHandle = await this.crypto.generateEcKeyPair();
    const credentialId = this.forcedCredentialId ?? this.crypto.randomBytes(32);
    this.forcedCredentialId = null;
    const credentialIdB64 = b64uEncode(credentialId);

    const cred: StoredCredential = {
      credentialId,
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      rpId: params.rpId,
      userHandle: params.userHandle,
      userName: params.userName,
      resident,
      counter: this.counterStart,
      createdAt: this.clock(),
    };
    this.creds.set(credentialIdB64, cred);

    const rpIdHash = await this.crypto.sha256(new TextEncoder().encode(params.rpId));
    const authData = buildAuthData({
      rpIdHash,
      userPresent: true,
      userVerified: uv,
      signCount: cred.counter,
      attestedCredential: { aaguid: this.aaguid, credentialId, publicKey: keyPair.publicKey },
    });

    let attestationObject: Uint8Array;
    if (params.attestation === 'direct') {
      // packed 自证明：sig = Sign(credPrivKey, authData ‖ clientDataHash)
      const sig = await this.crypto.sign(keyPair.privateKey, concatBytes(authData, params.clientDataHash));
      attestationObject = cborEncode(
        new Map<string, import('./cbor.js').CborValue>([
          ['fmt', 'packed'],
          ['attStmt', new Map<string, import('./cbor.js').CborValue>([['alg', -7], ['sig', sig]])],
          ['authData', authData],
        ]),
      );
    } else {
      attestationObject = cborEncode(
        new Map<string, import('./cbor.js').CborValue>([
          ['fmt', 'none'],
          ['attStmt', new Map<string, import('./cbor.js').CborValue>()],
          ['authData', authData],
        ]),
      );
    }

    this.onEvent('authenticator.makeCredential.done', {
      at: new Date(this.clock()).toISOString(),
      credentialId: credentialIdB64,
      publicKey: keyPair.publicKey,
      resident,
      userVerified: uv,
      signCount: cred.counter,
      fmt: params.attestation === 'direct' ? 'packed(self)' : 'none',
    });

    return {
      credentialId: credentialIdB64,
      attestationObject,
      publicKey: keyPair.publicKey,
      resident,
      counter: cred.counter,
    };
  }

  async getAssertion(params: GetAssertionParams): Promise<GetAssertionResult> {
    this.onEvent('authenticator.getAssertion.begin', {
      at: new Date(this.clock()).toISOString(),
      rpId: params.rpId,
      allowCredentials: params.allowCredentialIds ?? '(discoverable)',
      userVerification: params.userVerification,
    });

    let cred: StoredCredential | undefined;
    if (params.allowCredentialIds !== undefined) {
      for (const id of params.allowCredentialIds) {
        const c = this.creds.get(id);
        if (c && c.rpId === params.rpId) {
          cred = c;
          break;
        }
      }
    } else {
      // discoverable：仅 resident 凭据可被无 allowCredentials 的断言使用
      for (const c of this.creds.values()) {
        if (c.rpId === params.rpId && c.resident) {
          cred = c;
          break;
        }
      }
    }
    if (!cred) {
      this.onEvent('authenticator.getAssertion.refused', { reason: '无可用凭据' });
      throw new CodedError('NotAllowedError', 'no usable credential for this RP on the authenticator');
    }

    const uv = this.uvFlag(params.userVerification);
    cred.counter = (cred.counter + 1) >>> 0;

    const rpIdHash = await this.crypto.sha256(new TextEncoder().encode(params.rpId));
    const authenticatorData = buildAuthData({
      rpIdHash,
      userPresent: true,
      userVerified: uv,
      signCount: cred.counter,
    });
    const signature = await this.crypto.sign(
      cred.privateKey,
      concatBytes(authenticatorData, params.clientDataHash),
    );

    const credentialId = b64uEncode(cred.credentialId);
    this.onEvent('authenticator.getAssertion.done', {
      at: new Date(this.clock()).toISOString(),
      credentialId,
      signCount: cred.counter,
      userVerified: uv,
    });

    return {
      credentialId,
      authenticatorData,
      signature,
      userHandle: cred.userHandle,
      counter: cred.counter,
      publicKey: cred.publicKey,
    };
  }

  // ---- 测试钩子（不导出私钥） ----

  listCredentials(): Array<{
    credentialId: string;
    rpId: string;
    userName: string;
    resident: boolean;
    counter: number;
    publicKey: EcPublicKey;
  }> {
    return [...this.creds.values()].map((c) => ({
      credentialId: b64uEncode(c.credentialId),
      rpId: c.rpId,
      userName: c.userName,
      resident: c.resident,
      counter: c.counter,
      publicKey: c.publicKey,
    }));
  }

  /** 克隆模拟：把某凭据计数器回退到指定值 */
  debugSetCounter(credentialIdB64: string, value: number): void {
    const c = this.creds.get(credentialIdB64);
    if (!c) throw new CodedError('NotFoundError', `unknown credential ${credentialIdB64}`);
    c.counter = value >>> 0;
    this.onEvent('authenticator.debug.setCounter', { credentialId: credentialIdB64, counter: c.counter });
  }

  /** 强制下一次注册复用已有 credential id（制造 duplicate_credential 场景） */
  debugForceCredentialId(credentialIdB64: string): void {
    this.forcedCredentialId = b64uDecode(credentialIdB64);
  }
}
