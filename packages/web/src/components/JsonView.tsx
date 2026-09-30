import { useState } from 'react';

export function JsonView({ data, collapsed = true }: { data: unknown; collapsed?: boolean }) {
  const [open, setOpen] = useState(!collapsed);
  if (data === undefined || data === null) return null;
  const text = JSON.stringify(data, null, 2);
  const preview = JSON.stringify(data);
  return (
    <div className="json-view">
      <button className="json-toggle" onClick={() => setOpen(!open)} type="button">
        {open ? '▾' : '▸'} {open ? '收起' : preview.slice(0, 80) + (preview.length > 80 ? '…' : '')}
      </button>
      {open && <pre>{text}</pre>}
    </div>
  );
}
