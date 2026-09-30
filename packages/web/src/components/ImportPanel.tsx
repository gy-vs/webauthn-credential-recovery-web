import { useState } from 'react';
import { createWebCrypto, verifyExportedRecord, type CeremonyRecord, type CheckResult } from '@lab/shared';
import { ChecksView } from './CeremonyDetail';

export function exportRecord(record: CeremonyRecord): void {
  const json = JSON.stringify(record, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `webauthn-${record.kind}-${record.ceremonyId || 'record'}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export function ImportPanel() {
  const [text, setText] = useState('');
  const [result, setResult] = useState<{ valid: boolean; checks: CheckResult[] } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const verify = async (json: string) => {
    setError(null);
    setResult(null);
    try {
      const record = JSON.parse(json) as CeremonyRecord;
      const check = await verifyExportedRecord(record, createWebCrypto());
      setResult(check);
    } catch (e) {
      setError(`解析失败：${(e as Error).message}`);
    }
  };

  return (
    <div className="import-panel">
      <h3>重新导入检查</h3>
      <p className="muted">
        粘贴或选择导出的仪式记录（JSON）。将离线重放全部可验证检查：base64url 规范性、
        challenge 绑定、rpIdHash、签名（使用记录中的公钥，无需私钥）。
      </p>
      <div className="import-controls">
        <input
          type="file"
          accept="application/json"
          onChange={async (e) => {
            const file = e.target.files?.[0];
            if (!file) return;
            const content = await file.text();
            setText(content);
            await verify(content);
          }}
        />
        <button type="button" onClick={() => verify(text)} disabled={!text.trim()}>
          校验
        </button>
      </div>
      <textarea
        rows={8}
        placeholder='{"version":1,"kind":"registration",...}'
        value={text}
        onChange={(e) => setText(e.target.value)}
      />
      {error && <div className="failure">{error}</div>}
      {result && (
        <div>
          <div className={result.valid ? 'import-valid' : 'failure'}>
            {result.valid ? '✅ 记录有效：所有离线检查通过' : '❌ 记录无效'}
          </div>
          <ChecksView checks={result.checks} />
        </div>
      )}
    </div>
  );
}
