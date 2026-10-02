import { useState } from 'react';
import type {
  CredentialDisposition,
  CredentialDispositionInfo,
  DispositionEvent,
  StoredCredentialInfo,
} from '@lab/shared';
import { ApiError } from '../api';

const STATE_LABEL: Record<CredentialDisposition, string> = {
  active: '✅ 正常',
  quarantined: '⛔ 隔离中',
  revoked: '🚫 已撤销',
};

export function DispositionBadge({ disposition }: { disposition: CredentialDispositionInfo }) {
  return (
    <span
      className={`status disposition-${disposition.state}`}
      title={`版本 v${disposition.version}，更新于 ${disposition.updatedAt}`}
    >
      {STATE_LABEL[disposition.state]}
      <span className="muted"> v{disposition.version}</span>
    </span>
  );
}

const ACTION_LABEL: Record<DispositionEvent['action'], string> = {
  quarantine_clone_warning: '克隆告警 → 隔离',
  maintain_quarantine: '操作员维持隔离',
  revoke_operator: '操作员撤销',
  revoke_replaced: '恢复注册替代 → 撤销',
};

function HistoryView({ disposition }: { disposition: CredentialDispositionInfo }) {
  if (disposition.history.length === 0) return null;
  return (
    <details className="disposition-history">
      <summary>处置证据链（{disposition.history.length}）</summary>
      <ol className="steps">
        {disposition.history.map((h, i) => (
          <li key={i} className="step step-server">
            <div className="step-head">
              <strong>{ACTION_LABEL[h.action]}</strong>
              <code>{h.from} → {h.to}</code>
              <span className="muted">{h.at}</span>
            </div>
            {h.ceremonyId && (
              <div className="muted">
                仪式 <code>{h.ceremonyId}</code>
                {h.relatedCredentialId && <> · 关联凭据 <code>{h.relatedCredentialId.slice(0, 12)}…</code></>}
              </div>
            )}
            {h.note && <div className="step-note">{h.note}</div>}
          </li>
        ))}
      </ol>
    </details>
  );
}

export interface CredentialCardProps {
  credential: StoredCredentialInfo;
  busy: boolean;
  /** 用该凭据强制再发起一次认证（隔离/撤销凭据留在 authenticator 中再尝试） */
  onAuthenticateAttempt: (credential: StoredCredentialInfo) => void;
  /** 操作员处置：维持隔离 / 撤销 */
  onDisposition: (
    credential: StoredCredentialInfo,
    action: 'maintain_quarantine' | 'revoke_operator',
    note?: string,
  ) => Promise<void>;
  /** 发起恢复注册（新 authenticator 注册替代凭据） */
  onRecover: (credential: StoredCredentialInfo) => void;
}

export function CredentialCard({
  credential,
  busy,
  onAuthenticateAttempt,
  onDisposition,
  onRecover,
}: CredentialCardProps) {
  const [actionError, setActionError] = useState<string | null>(null);
  const [note, setNote] = useState('');
  const c = credential;
  const d = c.disposition;

  const run = async (action: 'maintain_quarantine' | 'revoke_operator') => {
    setActionError(null);
    try {
      await onDisposition(c, action);
      setNote('');
    } catch (e) {
      if (e instanceof ApiError) {
        setActionError(`处置被服务端拒绝（${e.code ?? 'error'}）：${e.message}——已刷新为当前状态，请重新审阅`);
      } else {
        setActionError(`处置失败：${(e as Error).message}`);
      }
    }
  };

  return (
    <div className={`cred-card cred-card-${d.state}`}>
      <div className="cred-row">
        <code title={c.credentialId}>{c.credentialId.slice(0, 12)}…</code>
        <DispositionBadge disposition={d} />
      </div>
      <div className="muted">
        {c.userName}{c.resident ? ' / resident' : ''} · 计数器 {c.counter} · {c.rpId}
      </div>
      {d.state === 'quarantined' && d.evidenceCeremonyId && (
        <div className="clone-warning">
          告警仪式（隔离证据）：<code>{d.evidenceCeremonyId}</code>
        </div>
      )}
      {d.state === 'revoked' && d.replacedByCredentialId && (
        <div className="import-valid">
          已被恢复注册的新凭据替代：<code>{d.replacedByCredentialId.slice(0, 12)}…</code>
        </div>
      )}
      {d.state === 'active' && d.replacesCredentialId && (
        <div className="import-valid">
          恢复凭据，替代了异常旧凭据：<code>{d.replacesCredentialId.slice(0, 12)}…</code>
        </div>
      )}
      <HistoryView disposition={d} />
      {d.state === 'quarantined' && (
        <div className="disposition-actions">
          <input
            placeholder="处置备注（可选）"
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
          <div className="scenarios">
            <button type="button" disabled={busy} onClick={() => run('maintain_quarantine')}>
              维持隔离
            </button>
            <button type="button" className="danger" disabled={busy} onClick={() => run('revoke_operator')}>
              撤销凭据
            </button>
            <button type="button" disabled={busy} onClick={() => onRecover(c)}>
              发起恢复注册（新 authenticator）
            </button>
            <button type="button" disabled={busy} onClick={() => onAuthenticateAttempt(c)}>
              用此凭据再认证（应被拒绝）
            </button>
          </div>
        </div>
      )}
      {d.state === 'revoked' && (
        <div className="disposition-actions">
          <button type="button" disabled={busy} onClick={() => onAuthenticateAttempt(c)}>
            用此凭据再认证（应被拒绝）
          </button>
        </div>
      )}
      {actionError && <div className="failure">{actionError}</div>}
    </div>
  );
}
