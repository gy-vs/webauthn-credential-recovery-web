/**
 * 服务端入口：内存存储 + 可配置 RP 参数，不连接任何外部身份平台或数据库。
 * 环境变量：PORT(默认 8787) / RP_ID(默认 localhost) / ALLOWED_ORIGINS(逗号分隔)
 */
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { createNodeCrypto } from '@lab/shared';
import { createApp } from './app.js';
import { LabStore } from './store.js';

const PORT = Number(process.env.PORT ?? 8787);
const RP_ID = process.env.RP_ID ?? 'localhost';
const ORIGINS = (process.env.ALLOWED_ORIGINS ?? 'http://localhost:5173,http://127.0.0.1:5173')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const crypto = await createNodeCrypto();
const store = new LabStore();
const app = createApp({
  store,
  crypto,
  config: {
    rpId: RP_ID,
    rpName: 'WebAuthn Ceremony Lab',
    expectedOrigins: ORIGINS,
    defaultTtlMs: 60_000,
    maxTtlMs: 10 * 60_000,
  },
});

// 生产模式：若 web 已构建则直接托管
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webDist = path.resolve(__dirname, '../../web/dist');
if (existsSync(webDist)) {
  app.use(express.static(webDist));
  app.get('*', (_req, res) => res.sendFile(path.join(webDist, 'index.html')));
}

app.listen(PORT, () => {
  console.log(`[webauthn-lab] server on http://localhost:${PORT}`);
  console.log(`[webauthn-lab] rpId=${RP_ID} origins=${ORIGINS.join(', ')}`);
});
