# WebAuthn Ceremony Lab

Browser-based registration and authentication simulator with an in-memory server.

Requires Node.js 20 or newer. Run `npm ci`, then `npm run dev` for the web app and API. Run `npm test` and `npm run typecheck` to check the project. `npm run build && npm start` serves the production build on port 8787.

## Credential quarantine & recovery

The clone-detector scenario (counter rollback on a cryptographically valid
assertion) no longer ends with a one-off warning. The server marks the
credential **quarantined** atomically after the real assertion verifies:

- `active → quarantined` carries the warning ceremony id as evidence, plus a
  monotonically increasing disposition **version** and a full history.
- Quarantined/revoked credentials stay in the credential store (auditable) but
  are removed from `allowCredentials`. A later authentication using one —
  discoverable, or forced by a client that ignores `allowCredentials` — still
  runs the full check chain (challenge, origin, RP ID, signature, UV) and is
  then rejected with `403 credential_quarantined` / `credential_revoked`.
  A larger counter never lifts the quarantine; the counter is frozen as
  evidence.
- Other unaffected credentials (same user or other users) keep working.
- Operators review the evidence in the credential panel and choose
  **maintain quarantine** or **revoke**. Actions send the version the page
  saw; a stale view against a credential disposed elsewhere gets
  `409 disposition_conflict` with the current state, and can never silently
  overwrite the newer decision.
- **Recovery** is a fresh registration ceremony (typically on a new software
  authenticator) with `replacesCredentialId`. It goes through the existing
  challenge / origin / RP ID / signature / UV checks, excludes every existing
  credential id (the old one cannot be reused), and only after verification
  atomically flips the old credential to `revoked (replaced)` and links both
  credentials. If the old credential was disposed (version/state change) after
  the recovery options were issued, completion fails with
  `recovery_target_invalid` and the new credential is not stored — no counter
  editing, no server reset.

Disposition state lives only in the in-memory server; every panel refresh,
authenticator-handle switch, or page reload fetches it from
`/api/credentials`, never from a component-local selection. Private keys
remain in software-authenticator memory only and never appear in responses,
exports, ceremony records, or logs.
