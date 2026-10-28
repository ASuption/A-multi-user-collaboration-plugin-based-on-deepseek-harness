# DSH Group Collaboration Plugin — Design & Contracts

> **协议 v2 更新（保密性加固）**：自 2026-10-28 起，网络协议升级为 v2：密码挑战应答（密码不过网）、共享快照 AES-256-GCM 端到端加密（服务器只存密文）、状态接口鉴权、每 IP 限流、旧 v1 房间不兼容。**v2 的权威规格见 [SECURITY.md](SECURITY.md)**；本文件中涉及 v1 线上协议（明文加入、passwordHash、未鉴权 status、UDP 带房间名）的描述以 SECURITY.md 为准。其余模块契约（工作区、备份、readme、命令/工具、成员运行时）继续有效。

Target workspace: the repository root
Bundle directory: `<repo>/group-collab`
Bundle package name: `@local/dsh-group-collab` (Host-only DSH/Cordis bundle, no runtime deps, Node builtins only).

The plugin is a persistent Host plugin installed with `plugin_manager install_bundle`. It provides:
- slash command `/group ...` in the chat composer (room create/join by room number + password, upload, sync, backup, status, readme),
- model-facing tools with the same operations,
- real TCP/HTTP + UDP-discovery sync between DSH instances on one host or a LAN,
- three workspace folders `own/`, `shared/`, `backup/`, and `shared/readme/`,
- chat notices (user-role context injection) explaining every shared-folder update.

## Hard constraints

- Plain ESM JavaScript only. Node builtins only (`node:fs/promises`, `node:path`, `node:crypto`, `node:http`, `node:dgram`, `node:os`, `node:url`, `node:events`). Do NOT import `@deepseek-ai/*` packages and do NOT add npm dependencies.
- The plugin must not throw at load when optional services are missing. `index.js` declares `export const inject = ['agents','commands','tools','workingDirectory']`.
- Every registered resource goes through `ctx.effect(...)` (return disposers) so plugin unload cleans up timers/servers.
- Node binary for tests: Node.js 22+ (`node` on PATH; DSH desktop ships one under `<DSH_HOME>/dsh-runtimes/`).
  Run tests from `<repo>/group-collab` with `node --test "tests/*.test.mjs"`.
- Do not touch files outside your assigned write scope. Do not modify other teammates' files.

## File ownership

| File | Owner |
|---|---|
| `group-collab/lib/protocol.js`, `lib/room-server.js`, `lib/room-client.js`, `tests/protocol.test.mjs`, `tests/net.test.mjs` | net-dev |
| `group-collab/lib/workspace.js`, `lib/backup.js`, `lib/readme.js`, `tests/workspace.test.mjs`, `tests/backup.test.mjs`, `tests/readme.test.mjs` | workspace-dev |
| `group-collab/lib/member.js`, `index.js`, `package.json`, `cordis.patch.yml`, `locale/*.json`, `icon.svg`, `README.md` | Lead |
| `group-collab/tests/e2e.test.mjs`, `tests/fake-ctx.test.mjs` | qa-verifier (later) |

## Domain model

- **Room**: `{number:"123456", name?, rev:number, snapshot: Snapshot|null, passwordHash, salt, createdAt, lastUpdate}`. Room number: 4–8 digits. Password: >= 4 chars, never stored in plaintext on the server (scrypt).
- **Member**: one DSH workspace = one member. `{id: 12-hex, name: string, root: absolute workspace path, room, origin(server URL), token, rev}`. Member state is persisted at `<workspace>/.dsh-group/member.json` (server password may be persisted there when `rememberPassword` is true, for auto-rejoin; document the risk).
- **Snapshot**: full content of the shared folder:
  ```js
  { rev: number, by: {id,name}, note: string, at: ISO string,
    files: [{ path: "src/a.js" /* POSIX relative, no ".." */, size: number,
              sha256: hex, data: base64 string }],
    changes: { added: string[], modified: string[], deleted: string[] } }
  ```
  Limits: <= 2000 files, <= 32 MiB total, <= 8 MiB per file. Path must be relative POSIX, no absolute/`..`/backslash, no duplicated path.
- **Workspace layout** (created under the session working directory):
  ```
  <root>/own/            developer's private work
  <root>/shared/         authoritative shared project (overwritten by sync)
  <root>/shared/readme/README.md          project-wide readme
  <root>/shared/readme/members/<name>.md  one readme per member
  <root>/backup/index.json
  <root>/backup/v<NNNN>-<stamp>-<reason>/ full copy of a shared-folder version
  <root>/.dsh-group/member.json          member config/state
  ```
- Every change of `shared/` creates one backup version (append-only). `own/` is never synced.

## lib/protocol.js — exported contract

```js
export const PROTOCOL_VERSION = 1
export const DEFAULT_TCP_PORT = 45890
export const DEFAULT_UDP_PORT = 45891
export const LIMITS = { maxFiles: 2000, maxTotalBytes: 32*1024*1024, maxFileBytes: 8*1024*1024,
                        maxPathLength: 400, maxNoteLength: 2000 }
export class CollabError extends Error { constructor(code, message, details) ; code; details }
// codes used by all modules: BAD_REQUEST, UNAUTHORIZED, NOT_FOUND, CONFLICT, TOO_LARGE,
//   BAD_ROOM, BAD_PASSWORD, BAD_PATH, BAD_SNAPSHOT, OFFLINE, VERSION, PROTOCOL

export function normalizeRoomNumber(value)        // string|number -> "123456" or throw CollabError('BAD_ROOM')
export function validatePassword(value)          // throws CollabError('BAD_PASSWORD') when invalid
export function hashPassword(password, salt?)    // -> { salt: hex, hash: hex } (scryptSync, 16B salt, 32B key)
export function verifyPassword(password, salt, hash) // -> boolean (timingSafeEqual)
export function createToken()                    // -> 32-byte hex
export function makeMemberId()                   // -> 12-byte hex
export function sanitizeMemberName(value, fallback) // trimmed, 1..40 chars, no path separators/control chars
export function safeMemberFileName(name)         // filesystem/URL-safe readme member filename (no slash, no leading dot)
export function assertSafeRelativePath(path)     // throws CollabError('BAD_PATH'); normalizes "a//b", rejects "..", "\", abs, nul
export function normalizeSnapshot(snapshot, { requireRev = true } = {}) // deep validation -> detached validated snapshot, throws BAD_SNAPSHOT
export function snapshotDigest(snapshot)          // sha256 over sorted "path:sha256" lines
export function diffSnapshots(prevFiles, nextFiles) // {added,modified,deleted} path arrays (uses path->sha256 maps)
export function fileSha256(buffer)               // hex
export function encodeFile(buffer) / decodeFile(entry) // base64 helpers, BAD_SNAPSHOT on bad data
export function validMember(member)              // {id,name} check for network input
```
Snapshot/room/member JSON crossing the network must be validated with these helpers on both sides.

## lib/room-server.js — exported contract

```js
export class RoomServer {
  constructor({ dataDir, tcpPort = DEFAULT_TCP_PORT, udpPort = DEFAULT_UDP_PORT,
                enableDiscovery = true, logger = console, hostName })
  async listen(): Promise<{ tcpPort, udpPort, origin }>   // binds 0.0.0.0, port fallback +0..+9
  async close(): Promise<void>
  get origin(): string | undefined                       // http://127.0.0.1:<tcpPort>
  listRooms(): Array<{ number, name, rev, online, createdAt }>
  hasRoom(number): boolean
  async createLocalRoom({ number, password, name, createdBy }) // idempotent error if exists: CollabError('CONFLICT')
  getLocalRoom(number): { number, name, origin, rev } | undefined
}
```
HTTP API (JSON, no cookies; `POST` bodies <= 64 MiB):
- `POST /group/v1/join` `{ v, room, password, member:{id,name}, workspace? }` →
  `{ ok:true, token, server:{origin,hostName}, room:{number,name,rev,createdAt},
     members:[{id,name,online}], snapshot: Snapshot|null, syncRequested:boolean }`
- `POST /group/v1/heartbeat` `{ token, member }` → `{ ok:true, rev, members, syncRequested }`
- `GET  /group/v1/latest?token=&rev=` → `{ ok:true, rev, members, lastUpdate, snapshot? ,syncRequested }`
  (`snapshot` omitted only when the caller passes its current `rev` equal to the room rev)
- `POST /group/v1/publish` `{ token, member, baseRev, snapshot, note }` →
  `{ ok:true, rev }`; on stale `baseRev` → HTTP 409 `{ ok:false, error:{code:'CONFLICT',...},
  rev, lastUpdate, snapshot }`.
- `POST /group/v1/leave` `{ token }` → `{ ok:true }`
- `GET  /group/v1/status?room=` → `{ ok:true, room, rev, members, snapshotDigest }`
- Unknown route → 404 `{ok:false,error:{code:'NOT_FOUND'}}`; malformed JSON/oversize/validation errors → 4xx with CollabError code.
Server behavior:
- members map is in-memory (`lastSeen`); online = lastSeen within 15s; join returns all currently registered members.
- publish: token→member auth; baseRev must equal current rev (else 409 + latest snapshot + lastUpdate); server assigns rev = current+1; stores snapshot; persists the room (atomic write: write `<room>.json.tmp` then rename) under `<dataDir>/rooms/<number>.json`; sets lastUpdate `{by,note,at,rev,changes}`; sets a short-lived `syncRequested` flag if some online member's known rev < room.rev (server tracks member `knownRev` from latest/heartbeat? simplest: set on join when room rev>0).
- UDP discovery (when enabled): bind `udpPort`; on `{t:'dsh-group-discover', v:1, room}` reply to `rinfo.address:rinfo.port` with `{t:'dsh-group-room', v:1, room, name, url:'http://<rinfo.address>:<tcpPort>'}` for a locally hosted room. Ignore malformed datagrams. Close socket on close().
- room persistence is loaded lazily on first access; corrupted room file is ignored + renamed `.corrupt`.

## lib/room-client.js — exported contract

```js
export class RoomClient {
  constructor({ origin, room, password, member:{id,name}, timeoutMs = 5000, logger })
  get origin()
  async join(): Promise<{token, room, members, snapshot, syncRequested, server}>
  async heartbeat(): Promise<{rev, members, syncRequested}>
  async latest(knownRev = 0): Promise<{rev, members, snapshot?, lastUpdate?, syncRequested}>
  async publish({ baseRev, snapshot, note }): Promise<{rev}>   // throws CollabError('CONFLICT', ..., {snapshot, lastUpdate})
  async leave(): Promise<void>
  async status(): Promise<object>
  close()
}
export async function discoverRoom({ room, udpPort = DEFAULT_UDP_PORT, timeoutMs = 1200,
                                     broadcastAddresses = ['255.255.255.255','127.0.0.1'] })
  // -> {origin, room, name, via:'discovery'} | undefined
```
HTTP with global `fetch` + AbortSignal; network failure -> CollabError('OFFLINE'); non-2xx -> CollabError(code from body). `RoomClient` is single-room; caller owns lifecycle.

## lib/workspace.js — exported contract

```js
export const LAYOUT = { stateDir: '.dsh-group', own: 'own', shared: 'shared', backup: 'backup', readme: 'readme' }
export async function ensureLayout(root)                  // creates own/shared/shared/readme/backup/.dsh-group
export function sharedDir(root) / ownDir(root) / backupDir(root) / readmeDir(root)
export async function listFiles(rootDir, { exclude = [] } = {}) // -> [{path, size, sha256}] sorted by path
export async function readSnapshotFiles(rootDir, { exclude = [] } = {}) // -> snapshot file entries with base64 data
export async function writeFiles(rootDir, files, { clean = true, keep = [] } = {})
  // validates every path via protocol.assertSafeRelativePath; clean=true removes existing files not in files
  // except paths starting with any `keep` prefix; writes atomically per file (tmp+rename)
export async function copyTree(srcDir, dstDir, { clean = false, keep = [] } = {})
export async function readState(root) / writeState(root, state)   // .dsh-group/member.json JSON helpers (state includes password only when allowed)
export function diffOfManifests(before, after)            // -> {added, modified, deleted} using path->sha256
export function formatDiff(diff, { limit = 12 } = {})     // short human text, "+a/x.js ~b/y.js -c/z.js"
export function compareTrees(sourceManifest, targetManifest) // same shape as diffOfManifests
```
Default excludes for `own/` and `shared/`: `.git`, `node_modules`, `.dsh-group`, `backup` is NEVER read as shared content; `shared/readme` IS shared content.
`writeFiles` must reject traversal and must not delete `own/` or `backup/`.

## lib/backup.js — exported contract

```js
export async function recordVersion(root, { reason, member, note, rev, changes })
  // reads current shared/ tree, writes backup/v<NNNN>-<UTC stamp>-<reason>/ mirror,
  // appends entry to backup/index.json, prunes older versions beyond keepVersions (default 50)
  // -> version record {version, dir, at, reason, member, note, rev, changes, fileCount, totalBytes}
export async function listVersions(root)      // -> {index:[record...]} newest last, or [] if none
export async function restoreVersion(root, version)
  // records the current shared as reason 'pre-restore', then writes the version dir back over shared/ (clean)
export async function pruneVersions(root, keepVersions = 50)
```
`backup/index.json` shape: `{ "version": 1, "versions": [record...], "keepVersions": number }`; writing atomic.
Version dir name must be filesystem-safe and unique. Every shared change must call recordVersion — including uploads and incoming sync and restore.

## lib/readme.js — exported contract

```js
export async function generateProjectReadme(root, { room, roomName, members, sharedManifest, lastUpdate })
  // writes shared/readme/README.md (Chinese): 项目标题, 房间号, 更新时间/更新者/说明, 成员表, 文件树, 使用命令提示
export async function generateMemberReadme(root, { member, room, note, ownManifest, sharedManifest, lastUploadAt })
  // writes shared/readme/members/<safeMemberFileName(name)>.md: 成员名, 角色, 最近上传/说明, own/ 文件清单
export async function ensureReadmeDir(root)   // mkdir shared/readme/members
export async function refreshReadmes(root, ctxArgs) // convenience: member readme first, then project readme using shared manifest
```
Rules: total project readme must list every `shared/readme/members/*.md` currently present; member readmes survive sync because they are normal shared files. `refreshReadmes` is called by the uploader only (and on join by the new member before its first publish).

## lib/member.js — Lead-owned orchestration (for reference)

```js
export class CollabRuntime {
  constructor({ dataDir, logger, now, config })
  async ensureWorkspace(root)                       // layout + load/create state
  async createRoom({root, room, password, name, memberName}) // -> {origin, roomInfo}
  async joinRoom({root, room, password, address, memberName}) // -> {origin, snapshotApplied, ...}
  async leaveRoom(root)
  async status(root) / listMembers(root)
  async upload({root, note})                        // own -> shared (clean non-readme), readme, backup, publish
  async sync(root)                                  // pull latest, backup + overwrite shared
  async backupList(root) / restoreBackup(root, version)
  async rename(root, name)
  async tick()                                      // heartbeat+pull+apply for all active members
  async handleAgentCreated(agent, root)             // auto rejoin + flush pending notices
  dispose()
}
```
Notification callback injected by `index.js`: `notify({root, text, wake})` injects a user-role message into every live agent of that workspace (`followup` for wake, `inject` otherwise) or queues it for the next agent created in that workspace.

## Slash command `/group` (registered in index.js)

`/group help | init | create <room> <password> [roomName] | join <room> <password> [address] | leave | status | members | upload [note] | sync | backup list | backup restore <version> | name <memberName> | set <key> <on|off|value> | address`
- Command must set `recordInput: false` (passwords must not enter the session log).
- Handler returns `{kind:'success'|'error', text}` with a concise Chinese report.
- `join` without address: try local room, then LAN UDP discovery; on failure tell the user to pass the `http://IP:port` address.

## Model tools (registered in index.js)

`group_room` (`action: create|join|leave|status|members|address`, `room?`, `password?`, `name?`, `address?`),
`group_share` (`action: upload|sync|status|backup_list|backup_restore`, `note?`, `version?`).
Tool results are JSON values with a text rendering. Handlers delegate to `CollabRuntime`; never duplicate logic.

## Testing requirements

- Each module ships `node --test` tests covering happy path + validation/security failures (traversal, wrong password, stale rev conflict, oversized snapshot, corrupt state, backup prune/restore, readme contents).
  Run the whole plugin suite from `<repo>/group-collab` with (Node 24 does not accept a bare directory positional):
  `node --test "tests/*.test.mjs"`
- `qa-verifier` writes a full e2e test: real `RoomServer` + two `CollabRuntime` instances in isolated temp workspaces + real HTTP sync + backup + readme + notify ordering, plus a fake-Cordis-ctx smoke test of `index.js` (register commands/tools, run upload/join through handlers, dispose cleanly).
- All tests must pass with the bundled node binary before installation.
