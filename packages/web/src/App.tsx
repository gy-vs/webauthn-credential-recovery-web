import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  createWebCrypto,
  SoftwareAuthenticator,
  type CeremonyRecord,
  type StoredCredentialInfo,
} from '@lab/shared';
import { api, type ServerConfig } from './api';
import { CeremonyDetail, StatusBadge } from './components/CeremonyDetail';
import { exportRecord, ImportPanel } from './components/ImportPanel';
import {
  runAuthentication,
  runCloneScenario,
  runConcurrentConsume,
  runRegistration,
  type AuthnHandle,
  type LabConfig,
} from './runner';

let handleSeq = 0;

function createHandle(name?: string): AuthnHandle {
  const handle: AuthnHandle = {
    id: `h${++handleSeq}`,
    name: name ?? `authenticator-${handleSeq}`,
    auth: undefined as unknown as SoftwareAuthenticator,
    events: [],
    clockMode: 'real',
    fixedIso: '2026-09-26T00:00:00.000Z',
  };
  handle.auth = new SoftwareAuthenticator(
    createWebCrypto(),
    {
      clock: () => (handle.clockMode === 'fixed' ? new Date(handle.fixedIso).getTime() : Date.now()),
      onEvent: (n, d) => handle.events.push({ name: n, detail: d }),
    },
    handle.id,
  );
  return handle;
}

const DEFAULT_CFG: LabConfig = {
  origin: '',
  rpIdOverride: '',
  userName: 'alice',
  residentKey: 'preferred',
  userVerification: 'preferred',
  attestation: 'none',
  discoverable: false,
  ttlMs: null,
};

export default function App() {
  const [serverConfig, setServerConfig] = useState<ServerConfig | null>(null);
  const [handles, setHandles] = useState<AuthnHandle[]>(() => [createHandle()]);
  const [activeId, setActiveId] = useState(handles[0]!.id);
  const [cfg, setCfg] = useState<LabConfig>(DEFAULT_CFG);
  const [records, setRecords] = useState<CeremonyRecord[]>([]);
  const [selected, setSelected] = useState(0);
  const [credentials, setCredentials] = useState<StoredCredentialInfo[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [, forceRender] = useState(0);

  const active = handles.find((h) => h.id === activeId) ?? handles[0]!;

  useEffect(() => {
    api.config().then(({ data }) => {
      setServerConfig(data);
      setCfg((c) => ({ ...c, origin: c.origin || data.expectedOrigins[0] || '' }));
    });
    refreshCredentials();
  }, []);

  const refreshCredentials = useCallback(async () => {
    const { data } = await api.credentials();
    setCredentials(data);
  }, []);

  const exec = useCallback(
    async (label: string, fn: () => Promise<CeremonyRecord[]>) => {
      setBusy(label);
      setError(null);
      try {
        const produced = await fn();
        setRecords((rs) => [...produced.reverse(), ...rs]);
        setSelected(0);
        await refreshCredentials();
        forceRender((n) => n + 1);
      } catch (e) {
        setError(`${label} 执行异常：${(e as Error).message}`);
      } finally {
        setBusy(null);
      }
    },
    [refreshCredentials],
  );

  const scenarios = useMemo(
    () =>
      [
        { key: 'register', label: '注册', run: () => runRegistration(active, cfg).then((r) => [r]) },
        { key: 'auth', label: '认证', run: () => runAuthentication(active, cfg).then((r) => [r]) },
        {
          key: 'auth-discoverable',
          label: '认证（resident key 发现）',
          run: () => runAuthentication(active, { ...cfg, discoverable: true }).then((r) => [r]),
        },
        {
          key: 'cancel',
          label: '取消仪式',
          run: () => runRegistration(active, cfg, { cancelBeforeSubmit: true }).then((r) => [r]),
        },
        {
          key: 'timeout',
          label: '超时（TTL 1.2s，延迟 1.6s 提交）',
          run: () =>
            runRegistration(active, { ...cfg, ttlMs: 1200 }, { waitMsBeforeSubmit: 1600 }).then((r) => [r]),
        },
        {
          key: 'concurrent',
          label: '并发消费同一 challenge',
          run: async () => {
            let second = handles.find((h) => h.id !== active.id);
            if (!second) {
              second = createHandle();
              setHandles((hs) => [...hs, second!]);
            }
            return [await runConcurrentConsume(active, second, cfg)];
          },
        },
        {
          key: 'bad-origin',
          label: '错误 origin',
          run: () =>
            runRegistration(active, { ...cfg, origin: 'https://evil.example.com' }).then((r) => [r]),
        },
        {
          key: 'bad-rpid',
          label: '错误 RP ID',
          run: () =>
            runAuthentication(active, { ...cfg, rpIdOverride: 'evil.example.com' }).then((r) => [r]),
        },
        {
          key: 'bad-sig',
          label: '签名失败（篡改签名）',
          run: () => runAuthentication(active, cfg, { tamperSignature: true }).then((r) => [r]),
        },
        {
          key: 'clone',
          label: '计数器克隆告警',
          run: () => {
            const cred = active.auth.listCredentials()[0];
            if (!cred) throw new Error('当前 authenticator 没有凭据，请先注册');
            return runCloneScenario(active, cfg, cred.credentialId);
          },
        },
        {
          key: 'dup-cred',
          label: '重复 credential id',
          run: async () => {
            const first = await runRegistration(active, cfg);
            const credId = first.attestationObject
              ? (first.steps.find((s) => s.name === 'authenticator.makeCredential.done')?.output as { credentialId?: string } | undefined)?.credentialId
              : undefined;
            const target = credId ?? active.auth.listCredentials()[0]?.credentialId;
            if (!target) throw new Error('没有可复用的 credential id');
            active.auth.debugForceCredentialId(target);
            const second = await runRegistration(active, cfg);
            return [first, second];
          },
        },
      ] as const,
    [active, cfg, handles],
  );

  const resetAll = async () => {
    await api.reset();
    setRecords([]);
    await refreshCredentials();
  };

  return (
    <div className="app">
      <header>
        <h1>WebAuthn 仪式模拟工作台</h1>
        {serverConfig && (
          <span className="muted">
            服务端 rpId=<code>{serverConfig.rpId}</code> 允许 origin=
            {serverConfig.expectedOrigins.map((o) => <code key={o}>{o}</code>)}
          </span>
        )}
      </header>

      <div className="layout">
        <aside>
          <section className="panel">
            <h3>仪式配置（客户端行为）</h3>
            <label>
              clientData origin
              <input value={cfg.origin} onChange={(e) => setCfg({ ...cfg, origin: e.target.value })} />
            </label>
            <label>
              rpId 覆盖（留空=服务端值）
              <input value={cfg.rpIdOverride} onChange={(e) => setCfg({ ...cfg, rpIdOverride: e.target.value })} placeholder="evil.example.com" />
            </label>
            <label>
              用户名
              <input value={cfg.userName} onChange={(e) => setCfg({ ...cfg, userName: e.target.value })} />
            </label>
            <label>
              userVerification
              <select value={cfg.userVerification} onChange={(e) => setCfg({ ...cfg, userVerification: e.target.value as LabConfig['userVerification'] })}>
                <option value="required">required</option>
                <option value="preferred">preferred</option>
                <option value="discouraged">discouraged</option>
              </select>
            </label>
            <label>
              residentKey
              <select value={cfg.residentKey} onChange={(e) => setCfg({ ...cfg, residentKey: e.target.value as LabConfig['residentKey'] })}>
                <option value="required">required</option>
                <option value="preferred">preferred</option>
                <option value="discouraged">discouraged</option>
              </select>
            </label>
            <label>
              attestation
              <select value={cfg.attestation} onChange={(e) => setCfg({ ...cfg, attestation: e.target.value as LabConfig['attestation'] })}>
                <option value="none">none</option>
                <option value="direct">direct（packed 自证明）</option>
              </select>
            </label>
            <label>
              challenge TTL（ms，0=服务端默认）
              <input
                type="number"
                value={cfg.ttlMs ?? 0}
                onChange={(e) => setCfg({ ...cfg, ttlMs: Number(e.target.value) > 0 ? Number(e.target.value) : null })}
              />
            </label>
          </section>

          <section className="panel">
            <h3>测试 Authenticator（ES256）</h3>
            <select value={activeId} onChange={(e) => setActiveId(e.target.value)}>
              {handles.map((h) => (
                <option key={h.id} value={h.id}>{h.name}</option>
              ))}
            </select>
            <button type="button" onClick={() => { const h = createHandle(); setHandles([...handles, h]); setActiveId(h.id); }}>
              + 新建
            </button>
            <label className="row">
              <input
                type="checkbox"
                checked={active.auth.uvSupported}
                onChange={(e) => { active.auth.uvSupported = e.target.checked; forceRender((n) => n + 1); }}
              />
              支持 UV
            </label>
            <label className="row">
              <input
                type="checkbox"
                checked={active.auth.uvResult}
                onChange={(e) => { active.auth.uvResult = e.target.checked; forceRender((n) => n + 1); }}
              />
              用户验证通过
            </label>
            <label className="row">
              <input
                type="checkbox"
                checked={active.clockMode === 'fixed'}
                onChange={(e) => { active.clockMode = e.target.checked ? 'fixed' : 'real'; forceRender((n) => n + 1); }}
              />
              注入固定时钟
            </label>
            {active.clockMode === 'fixed' && (
              <input value={active.fixedIso} onChange={(e) => { active.fixedIso = e.target.value; forceRender((n) => n + 1); }} />
            )}
            <h4>凭据（无私钥）</h4>
            {active.auth.listCredentials().length === 0 && <p className="muted">尚无凭据</p>}
            {active.auth.listCredentials().map((c) => (
              <div key={c.credentialId} className="cred">
                <code title={c.credentialId}>{c.credentialId.slice(0, 12)}…</code>
                <span className="muted">{c.rpId} / {c.userName}{c.resident ? ' / resident' : ''}</span>
                <span>
                  计数器 {c.counter}
                  <button
                    type="button"
                    onClick={() => {
                      const v = prompt('设置计数器为（模拟克隆回退）', String(c.counter));
                      if (v !== null) {
                        active.auth.debugSetCounter(c.credentialId, Number(v));
                        forceRender((n) => n + 1);
                      }
                    }}
                  >
                    回退
                  </button>
                </span>
              </div>
            ))}
          </section>

          <section className="panel">
            <h3>服务端凭据库（内存）</h3>
            {credentials.length === 0 && <p className="muted">空</p>}
            {credentials.map((c) => (
              <div key={c.credentialId} className="cred">
                <code title={c.credentialId}>{c.credentialId.slice(0, 12)}…</code>
                <span className="muted">{c.userName}{c.resident ? ' / resident' : ''}</span>
                <span>计数器 {c.counter}</span>
              </div>
            ))}
            <button type="button" className="danger" onClick={resetAll}>重置服务端状态</button>
          </section>
        </aside>

        <main>
          <section className="panel">
            <h3>场景</h3>
            <div className="scenarios">
              {scenarios.map((s) => (
                <button key={s.key} type="button" disabled={busy !== null} onClick={() => exec(s.label, s.run)}>
                  {busy === s.label ? '执行中…' : s.label}
                </button>
              ))}
            </div>
            {error && <div className="failure">{error}</div>}
          </section>

          <section className="panel">
            <h3>仪式记录（{records.length}）</h3>
            <div className="record-list">
              {records.map((r, i) => (
                <button
                  key={`${r.ceremonyId}-${i}`}
                  type="button"
                  className={`record-item ${i === selected ? 'selected' : ''}`}
                  onClick={() => setSelected(i)}
                >
                  <StatusBadge status={r.serverResult.status} />
                  <span>{r.kind === 'registration' ? '注册' : '认证'}</span>
                  <code>{r.ceremonyId.slice(0, 10)}</code>
                  {r.serverResult.failureCode && <code className="code-bad">{r.serverResult.failureCode}</code>}
                </button>
              ))}
            </div>
            {records[selected] && (
              <CeremonyDetail record={records[selected]} onExport={exportRecord} />
            )}
          </section>

          <section className="panel">
            <ImportPanel />
          </section>
        </main>
      </div>
    </div>
  );
}
