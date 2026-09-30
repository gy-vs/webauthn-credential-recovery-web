/**
 * 仪式驱动器：扮演"浏览器客户端"，把 options → clientDataJSON →
 * authenticator → 服务端校验串成一条步骤链，产出可导出的 CeremonyRecord。
 * 这里可以故意"不守规矩"：伪造 origin/rpId、篡改签名、延迟提交、并发提交。
 */
import {
  buildClientDataJSON,
  b64uDecode,
  b64uEncode,
  createWebCrypto,
  type AssertionResponseDTO,
  type AttestationResponseDTO,
  type AttestationConveyance,
  type AuthenticationOptionsDTO,
  type CeremonyRecord,
  type CeremonyStatus,
  type CheckResult,
  type FailureCode,
  type RegistrationOptionsDTO,
  type ResidentKey,
  type SoftwareAuthenticator,
  type StepEntry,
  type UserVerification,
} from '@lab/shared';
import { api } from './api';

export interface AuthnHandle {
  id: string;
  name: string;
  auth: SoftwareAuthenticator;
  /** authenticator 内部事件缓冲（无私钥），仪式开始时清空、结束时倒入步骤 */
  events: Array<{ name: string; detail: Record<string, unknown> }>;
  clockMode: 'real' | 'fixed';
  fixedIso: string;
}

export interface LabConfig {
  origin: string;
  rpIdOverride: string; // 空串 = 使用服务端 rpId
  userName: string;
  residentKey: ResidentKey;
  userVerification: UserVerification;
  attestation: AttestationConveyance;
  discoverable: boolean;
  ttlMs: number | null; // null = 服务端默认
}

export interface RunHooks {
  /** 提交前等待（超时场景） */
  waitMsBeforeSubmit?: number;
  /** 提交前取消仪式（取消场景） */
  cancelBeforeSubmit?: boolean;
  /** 篡改签名（签名失败场景） */
  tamperSignature?: boolean;
}

const crypto = createWebCrypto();
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

class Recorder {
  steps: StepEntry[] = [];
  constructor(private readonly clock: () => number) {}
  add(actor: StepEntry['actor'], name: string, input?: unknown, output?: unknown, note?: string): void {
    this.steps.push({ name, at: new Date(this.clock()).toISOString(), actor, input, output, note });
  }
}

function drainAuthenticatorEvents(handle: AuthnHandle, rec: Recorder): void {
  for (const ev of handle.events.splice(0)) {
    rec.add('authenticator', ev.name, undefined, ev.detail);
  }
}

interface ServerReply {
  status: number;
  data: Record<string, unknown>;
}

function serverResultFrom(reply: ServerReply): CeremonyRecord['serverResult'] {
  const d = reply.data;
  const checks = (d.checks as CheckResult[] | undefined) ?? [];
  if (d.ok === true) {
    return {
      status: d.cloneWarning ? 'completed_with_clone_warning' : 'completed',
      cloneWarning: Boolean(d.cloneWarning),
      checks,
    };
  }
  const code = d.code as FailureCode | undefined;
  const status: CeremonyStatus =
    code === 'ceremony_cancelled' ? 'cancelled' : code === 'challenge_expired' ? 'expired' : 'failed';
  return {
    status,
    failureCode: code,
    failureMessage: typeof d.message === 'string' ? d.message : undefined,
    checks,
  };
}

function baseRecord(kind: CeremonyRecord['kind'], ceremonyId: string, cfg: LabConfig): CeremonyRecord {
  return {
    version: 1,
    kind,
    ceremonyId,
    startedAt: new Date().toISOString(),
    finishedAt: null,
    origin: cfg.origin,
    rpId: '',
    userVerification: cfg.userVerification,
    residentKey: kind === 'registration' ? cfg.residentKey : undefined,
    attestation: kind === 'registration' ? cfg.attestation : undefined,
    options: {} as CeremonyRecord['options'],
    clientDataJSON: '',
    serverResult: { status: 'failed', checks: [] },
    steps: [],
  };
}

export async function runRegistration(
  handle: AuthnHandle,
  cfg: LabConfig,
  hooks: RunHooks = {},
): Promise<CeremonyRecord> {
  const rec = new Recorder(() => handle.auth.now());
  const record = baseRecord('registration', '', cfg);
  handle.events.length = 0;

  const reqBody = {
    userName: cfg.userName,
    residentKey: cfg.residentKey,
    userVerification: cfg.userVerification,
    attestation: cfg.attestation,
    ...(cfg.ttlMs !== null ? { ttlMs: cfg.ttlMs } : {}),
  };
  rec.add('client', 'client.request.registerOptions', reqBody);
  const optionsRes = await api.registerOptions(reqBody);
  const options = optionsRes.data;
  rec.add('server', 'server.issue.registerOptions', undefined, options, `challenge 一次性，TTL=${options.timeout}ms`);
  record.options = options;
  record.ceremonyId = options.ceremonyId;
  record.rpId = options.rp.id;

  const effectiveRpId = cfg.rpIdOverride || options.rp.id;
  const clientDataJSON = buildClientDataJSON({
    type: 'webauthn.create',
    challengeB64u: options.challenge,
    origin: cfg.origin,
  });
  rec.add('client', 'client.build.clientDataJSON', { type: 'webauthn.create', challenge: options.challenge, origin: cfg.origin }, {
    clientDataJSON: b64uEncode(clientDataJSON),
    note: cfg.origin === '' ? undefined : `客户端声明 origin=${cfg.origin}`,
  });
  record.clientDataJSON = b64uEncode(clientDataJSON);

  const clientDataHash = await crypto.sha256(clientDataJSON);
  let made;
  try {
    made = await handle.auth.makeCredential({
      rpId: effectiveRpId,
      userHandle: b64uDecode(options.user.id),
      userName: options.user.name,
      clientDataHash,
      excludeCredentialIds: options.excludeCredentials.map((c) => c.id),
      residentKey: cfg.residentKey,
      userVerification: cfg.userVerification,
      attestation: cfg.attestation,
    });
  } catch (e) {
    drainAuthenticatorEvents(handle, rec);
    const err = e as { code?: string; message?: string };
    rec.add('authenticator', 'authenticator.makeCredential.error', undefined, { code: err.code, message: err.message });
    record.steps = rec.steps;
    record.finishedAt = new Date().toISOString();
    record.serverResult = {
      status: 'failed',
      failureMessage: `authenticator 拒绝：${err.code ?? ''} ${err.message ?? ''}`,
      checks: [],
    };
    return record;
  }
  drainAuthenticatorEvents(handle, rec);
  record.credentialPublicKey = { kty: 'EC2', alg: -7, crv: 'P-256', ...made.publicKey };
  record.attestationObject = b64uEncode(made.attestationObject);

  if (hooks.waitMsBeforeSubmit) {
    rec.add('client', 'client.wait', undefined, undefined, `故意等待 ${hooks.waitMsBeforeSubmit}ms（超时场景）`);
    await sleep(hooks.waitMsBeforeSubmit);
  }
  if (hooks.cancelBeforeSubmit) {
    const cancelRes = await api.cancelCeremony(options.ceremonyId);
    rec.add('client', 'client.cancel', { ceremonyId: options.ceremonyId }, cancelRes.data, '用户在确认前取消');
  }

  const response: AttestationResponseDTO = {
    ceremonyId: options.ceremonyId,
    credentialId: made.credentialId,
    clientDataJSON: b64uEncode(clientDataJSON),
    attestationObject: b64uEncode(made.attestationObject),
    residentHint: made.resident,
  };
  rec.add('client', 'client.submit.attestation', response);
  const result = await api.registerResult(response);
  rec.add('server', 'server.verify.attestation', undefined, result.data, `HTTP ${result.status}`);
  record.serverResult = serverResultFrom(result);
  record.steps = rec.steps;
  record.finishedAt = new Date().toISOString();
  return record;
}

export async function runAuthentication(
  handle: AuthnHandle,
  cfg: LabConfig,
  hooks: RunHooks = {},
): Promise<CeremonyRecord> {
  const rec = new Recorder(() => handle.auth.now());
  const record = baseRecord('authentication', '', cfg);
  handle.events.length = 0;

  const reqBody = {
    userName: cfg.userName,
    userVerification: cfg.userVerification,
    discoverable: cfg.discoverable,
    ...(cfg.ttlMs !== null ? { ttlMs: cfg.ttlMs } : {}),
  };
  rec.add('client', 'client.request.authOptions', reqBody);
  const optionsRes = await api.authenticateOptions(reqBody);
  const options: AuthenticationOptionsDTO = optionsRes.data;
  rec.add('server', 'server.issue.authOptions', undefined, options,
    options.allowCredentials.length === 0 ? 'discoverable：allowCredentials 为空（resident key 流程）' : undefined);
  record.options = options;
  record.ceremonyId = options.ceremonyId;
  record.rpId = options.rpId;

  const effectiveRpId = cfg.rpIdOverride || options.rpId;
  const clientDataJSON = buildClientDataJSON({
    type: 'webauthn.get',
    challengeB64u: options.challenge,
    origin: cfg.origin,
  });
  rec.add('client', 'client.build.clientDataJSON', { type: 'webauthn.get', challenge: options.challenge, origin: cfg.origin }, {
    clientDataJSON: b64uEncode(clientDataJSON),
  });
  record.clientDataJSON = b64uEncode(clientDataJSON);

  const clientDataHash = await crypto.sha256(clientDataJSON);
  let assertion;
  try {
    assertion = await handle.auth.getAssertion({
      rpId: effectiveRpId,
      allowCredentialIds: options.allowCredentials.length ? options.allowCredentials.map((c) => c.id) : undefined,
      clientDataHash,
      userVerification: cfg.userVerification,
    });
  } catch (e) {
    drainAuthenticatorEvents(handle, rec);
    const err = e as { code?: string; message?: string };
    rec.add('authenticator', 'authenticator.getAssertion.error', undefined, { code: err.code, message: err.message });
    record.steps = rec.steps;
    record.finishedAt = new Date().toISOString();
    record.serverResult = {
      status: 'failed',
      failureMessage: `authenticator 拒绝：${err.code ?? ''} ${err.message ?? ''}`,
      checks: [],
    };
    return record;
  }
  drainAuthenticatorEvents(handle, rec);
  record.credentialPublicKey = { kty: 'EC2', alg: -7, crv: 'P-256', ...assertion.publicKey };
  record.authenticatorData = b64uEncode(assertion.authenticatorData);
  record.userHandle = b64uEncode(assertion.userHandle);

  let signature = assertion.signature;
  if (hooks.tamperSignature) {
    signature = signature.slice();
    signature[10] = signature[10]! ^ 0xff;
    rec.add('client', 'client.tamper.signature', undefined, { flippedByte: 10 }, '篡改签名第 10 字节（签名失败场景）');
  }
  record.signature = b64uEncode(signature);

  if (hooks.waitMsBeforeSubmit) {
    rec.add('client', 'client.wait', undefined, undefined, `故意等待 ${hooks.waitMsBeforeSubmit}ms（超时场景）`);
    await sleep(hooks.waitMsBeforeSubmit);
  }
  if (hooks.cancelBeforeSubmit) {
    const cancelRes = await api.cancelCeremony(options.ceremonyId);
    rec.add('client', 'client.cancel', { ceremonyId: options.ceremonyId }, cancelRes.data);
  }

  const response: AssertionResponseDTO = {
    ceremonyId: options.ceremonyId,
    credentialId: assertion.credentialId,
    clientDataJSON: b64uEncode(clientDataJSON),
    authenticatorData: b64uEncode(assertion.authenticatorData),
    signature: b64uEncode(signature),
    userHandle: b64uEncode(assertion.userHandle),
  };
  rec.add('client', 'client.submit.assertion', response);
  const result = await api.authenticateResult(response);
  rec.add('server', 'server.verify.assertion', undefined, result.data, `HTTP ${result.status}`);
  record.serverResult = serverResultFrom(result);
  record.steps = rec.steps;
  record.finishedAt = new Date().toISOString();
  return record;
}

/**
 * 并发消费：两个"页面"拿到同一 challenge，各自完成客户端部分后同时提交。
 * 服务端恰好接受一个，另一个得到 challenge_consumed。
 */
export async function runConcurrentConsume(
  handleA: AuthnHandle,
  handleB: AuthnHandle,
  cfg: LabConfig,
): Promise<CeremonyRecord> {
  const rec = new Recorder(() => Date.now());
  const record = baseRecord('registration', '', cfg);
  record.rpId = '(server)';
  handleA.events.length = 0;
  handleB.events.length = 0;

  const reqBody = {
    userName: cfg.userName,
    residentKey: cfg.residentKey,
    userVerification: cfg.userVerification,
    attestation: cfg.attestation,
  };
  rec.add('client', 'pageA.request.registerOptions', reqBody);
  const optionsRes = await api.registerOptions(reqBody);
  const options: RegistrationOptionsDTO = optionsRes.data;
  rec.add('server', 'server.issue.registerOptions', undefined, options, '同一 challenge 被两个页面共享');
  record.options = options;
  record.ceremonyId = options.ceremonyId;
  record.rpId = options.rp.id;

  const buildPage = async (handle: AuthnHandle, page: string) => {
    const clientDataJSON = buildClientDataJSON({ type: 'webauthn.create', challengeB64u: options.challenge, origin: cfg.origin });
    const clientDataHash = await crypto.sha256(clientDataJSON);
    const made = await handle.auth.makeCredential({
      rpId: options.rp.id,
      userHandle: b64uDecode(options.user.id),
      userName: options.user.name,
      clientDataHash,
      excludeCredentialIds: [],
      residentKey: cfg.residentKey,
      userVerification: cfg.userVerification,
      attestation: cfg.attestation,
    });
    rec.add('client', `${page}.build.attestation`, undefined, { credentialId: made.credentialId });
    return {
      response: {
        ceremonyId: options.ceremonyId,
        credentialId: made.credentialId,
        clientDataJSON: b64uEncode(clientDataJSON),
        attestationObject: b64uEncode(made.attestationObject),
      } satisfies AttestationResponseDTO,
      publicKey: made.publicKey,
    };
  };

  const [pageA, pageB] = await Promise.all([buildPage(handleA, 'pageA'), buildPage(handleB, 'pageB')]);
  rec.add('client', 'pages.submit.concurrent', undefined, undefined, '两个页面同时提交同一 challenge');
  const [resA, resB] = await Promise.all([
    api.registerResult(pageA.response),
    api.registerResult(pageB.response),
  ]);
  rec.add('server', 'server.verify.pageA', undefined, resA.data, `HTTP ${resA.status}`);
  rec.add('server', 'server.verify.pageB', undefined, resB.data, `HTTP ${resB.status}`);

  const winner = resA.data.ok === true ? resA : resB.data.ok === true ? resB : null;
  const loser = resA.data.ok === true ? resB : resA;
  const winnerPage = resA.data.ok === true ? pageA : pageB;
  record.clientDataJSON = pageA.response.clientDataJSON; // 两页面共享同一 challenge/origin，clientDataJSON 一致
  record.credentialPublicKey = { kty: 'EC2', alg: -7, crv: 'P-256', ...winnerPage.publicKey };
  record.attestationObject = winnerPage.response.attestationObject;
  record.serverResult = winner
    ? {
        status: 'completed',
        checks: [
          ...((winner.data.checks as CheckResult[] | undefined) ?? []),
          {
            check: 'concurrent.loser',
            ok: true,
            detail: `另一页面被拒绝：${String(loser.data.code)} —— ${String(loser.data.message)}`,
          },
        ],
      }
    : serverResultFrom(resA);
  record.steps = rec.steps;
  record.finishedAt = new Date().toISOString();
  return record;
}

/** 克隆告警场景：正常认证一次 → 回退计数器 → 再认证一次 */
export async function runCloneScenario(
  handle: AuthnHandle,
  cfg: LabConfig,
  credentialId: string,
): Promise<CeremonyRecord[]> {
  const first = await runAuthentication(handle, cfg);
  handle.auth.debugSetCounter(credentialId, 0);
  const second = await runAuthentication(handle, cfg);
  second.steps.unshift({
    name: 'authenticator.debug.setCounter',
    at: new Date().toISOString(),
    actor: 'authenticator',
    output: { credentialId, counter: 0 },
    note: '模拟克隆：计数器回退到 0',
  });
  return [first, second];
}
