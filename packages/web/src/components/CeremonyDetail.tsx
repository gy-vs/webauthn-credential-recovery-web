import type { CeremonyRecord, CeremonyStatus, CheckResult } from '@lab/shared';
import { JsonView } from './JsonView';

const STATUS_LABEL: Record<CeremonyStatus, string> = {
  pending: '进行中',
  completed: '✅ 完成',
  completed_with_clone_warning: '⚠️ 完成（克隆告警）',
  failed: '❌ 失败',
  cancelled: '🚫 已取消',
  expired: '⏰ 已过期',
};

export function StatusBadge({ status }: { status: CeremonyStatus }) {
  return <span className={`status status-${status}`}>{STATUS_LABEL[status]}</span>;
}

export function ChecksView({ checks }: { checks: CheckResult[] }) {
  if (checks.length === 0) return null;
  return (
    <table className="checks">
      <thead>
        <tr>
          <th>检查项</th>
          <th>结果</th>
          <th>说明</th>
        </tr>
      </thead>
      <tbody>
        {checks.map((c, i) => (
          <tr key={i} className={c.ok ? 'check-ok' : 'check-bad'}>
            <td><code>{c.check}</code></td>
            <td>{c.ok ? '✓' : '✗'}</td>
            <td>{c.detail ?? ''}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const ACTOR_LABEL = { client: '🖥 客户端', authenticator: '🔐 Authenticator', server: '🗄 服务端' } as const;

export function CeremonyDetail({ record, onExport }: { record: CeremonyRecord; onExport: (r: CeremonyRecord) => void }) {
  return (
    <div className="ceremony-detail">
      <div className="ceremony-head">
        <StatusBadge status={record.serverResult.status} />
        <strong>{record.kind === 'registration' ? '注册' : '认证'}</strong>
        <code>{record.ceremonyId}</code>
        <span className="muted">
          rpId={record.rpId} origin={record.origin} uv={record.userVerification}
          {record.residentKey ? ` rk=${record.residentKey}` : ''}
          {record.attestation ? ` att=${record.attestation}` : ''}
        </span>
        <button type="button" onClick={() => onExport(record)}>导出记录</button>
      </div>
      {record.serverResult.failureCode && (
        <div className="failure">
          终态：<code>{record.serverResult.failureCode}</code> — {record.serverResult.failureMessage}
        </div>
      )}
      {record.serverResult.cloneWarning && (
        <div className="clone-warning">⚠️ 计数器回退：疑似克隆 authenticator（仪式仍到达可解释终态）</div>
      )}
      <h4>服务端检查链</h4>
      <ChecksView checks={record.serverResult.checks} />
      <h4>仪式步骤（{record.steps.length}）</h4>
      <ol className="steps">
        {record.steps.map((s, i) => (
          <li key={i} className={`step step-${s.actor}`}>
            <div className="step-head">
              <span className="actor">{ACTOR_LABEL[s.actor]}</span>
              <code>{s.name}</code>
              <span className="muted">{s.at}</span>
            </div>
            {s.note && <div className="step-note">{s.note}</div>}
            {s.input !== undefined && (
              <div className="step-io"><span className="io-label">输入</span><JsonView data={s.input} /></div>
            )}
            {s.output !== undefined && (
              <div className="step-io"><span className="io-label">输出</span><JsonView data={s.output} /></div>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}
