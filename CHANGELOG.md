# Changelog

All notable changes to this project are documented here.

## 2.0.0 — 2026-10-28

### Security (protocol v2, breaking)

- **Password is never sent over the wire**: join now uses a server-nonce challenge and an HMAC-SHA256 proof derived locally with scrypt; the server stores only an `authKey` verifier.
- **End-to-end encrypted shared snapshots**: files, update notes, readmes and change summaries are encrypted with AES-256-GCM using a content key derived from the room password on each member; the room server is a blind relay that persists ciphertext only.
- **Authenticated APIs**: `latest`, `status`, `publish`, `heartbeat` require a session token; the anonymous room-status query is removed.
- **Anti-enumeration**: unknown rooms, wrong passwords and expired/replayed nonces return the same unified `401`; challenge replies no longer expose room names.
- **Rate limiting**: per-IP challenge limits and join-failure lockout (`429` + `Retry-After`).
- **Smaller exposure**: UDP discovery replies are v2-only and carry no room name; the plugin's `/group-collab/status` web route is loopback-only.
- **Password policy**: minimum length raised to 8; legacy v1 room files are renamed `.json.legacy-v1` and never loaded.
- Added independent attack-surface tests (`tests/security.test.mjs`) and a canary-based wire/disk leak test suite.

### Changed

- Room server `MAX_BODY_BYTES` raised for encrypted publish payloads; snapshot limits validated client-side after decryption.
- Docs: added `SECURITY.md` threat model, refreshed `README.md`/`VERIFICATION.md`.

## 1.0.0 — 2026-10-28

- Initial release: password-protected rooms (`/group create|join`), workspace layout `own/`, `shared/`, `backup/`, shared-folder sync between online members, append-only backup versions, automatic project/member readmes under `shared/readme/`, chat update notices/goals, LAN UDP discovery, `group_room`/`group_share` agent tools.
