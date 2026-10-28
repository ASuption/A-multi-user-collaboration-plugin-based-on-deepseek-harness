/**
 * Protocol v2 confidentiality / attack-surface verification (task-6, SECURITY.md).
 *
 * This is an INDEPENDENT black-box verification suite: it starts real `RoomServer`
 * instances on ephemeral ports, uses the real `RoomClient` / `CollabRuntime` for
 * legitimate flows and raw `fetch`/`node:dgram` for the attacker side. Plugin source
 * is never imported for behaviour that is being verified — only its public modules.
 *
 * Covered:
 *   1. an attacker without credentials never receives shared content
 *      (challenge is harmless, join/latest/status/publish/heartbeat/leave => 401);
 *   2. canary test: password / file content / file path / update note never appear in
 *      any captured HTTP request or response body, in the room JSON on disk, in any
 *      server data file or in logger output. Member names are the only metadata
 *      allowed to cross the wire (SECURITY.md threat model) and are asserted to stay
 *      inside member metadata only;
 *   3. anti-enumeration: unknown-room challenge is shape-identical to a real room and
 *      its fake salts are stable per process; wrong password vs unknown room join are
 *      byte-identical 401s; unauthenticated status cannot confirm a room;
 *   4. ciphertext integrity: tampered data/tag/iv, replay of an old cipher at a new
 *      rev (AAD binding) and decrypted-but-invalid plaintext are all rejected by the
 *      legitimate client, and a real CollabRuntime never writes shared/ on failure;
 *   5. per-IP rate limits: 30 challenges/min and 5 join failures => 429 with
 *      `retryAfterSeconds` + `Retry-After`; a successful join clears the counter;
 *   6. legacy v1 room JSON is renamed `.legacy-v1`, never served and can be recreated
 *      as a v2 room with the same number;
 *   7. UDP discovery: v2 replies carry no room name, clients reject v1 replies.
 *
 * Run with the bundled node from Z:\try\work\group-collab:
 *   node --test "tests/*.test.mjs"
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { createSocket } from 'node:dgram'
import { promises as fsp } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { RoomServer } from '../lib/room-server.js'
import { RoomClient, discoverRoom } from '../lib/room-client.js'
import { CollabRuntime } from '../lib/member.js'
import { CollabError, PROTOCOL_VERSION, encodeFile } from '../lib/protocol.js'
import {
  CIPHER_VERSION,
  createProof,
  decryptSnapshot,
  deriveAuthKey,
  deriveContentKey,
  encodeCipher,
  encryptSnapshot,
  normalizeCipher,
} from '../lib/crypto.js'
import { readSnapshotFiles, sharedDir } from '../lib/workspace.js'

/* ------------------------------------------------------------------ */
/* Canaries / fixtures                                                */
/* ------------------------------------------------------------------ */

const ROOM = '864201'
const ROOM_UNKNOWN = '999998'
const LEGACY_ROOM = '777701'
const PASSWORD = 'Sec-Passw0rd-v2-9q'
const WRONG_PASSWORD = 'Wrong-Passw0rd-v2-8w'

/** Unique canary fragment reused by every secret; unique enough to grep for. */
const CANARY = 'SECv2CANARY7f31c9'
const CONTENT_CANARY = `正文-${CANARY}-绝密共享内容`
const PATH_CANARY = `docs/canary-${CANARY}.md`
const NOTE_CANARY = `说明-${CANARY}-私密更新说明`
/** Member names are documented wire metadata; the canary proves it stays metadata-only. */
const MEMBER_NAME_CANARY = `Mem-${CANARY}`
/** Every secret except the member name must never appear anywhere (wire/disk/logs). */
const MUST_BE_ABSENT = [PASSWORD, WRONG_PASSWORD, CONTENT_CANARY, PATH_CANARY, NOTE_CANARY]

const MEMBER_ALICE = { id: 'sec-alice-0001', name: 'Sec-Alice' }
const MEMBER_BOB = { id: 'sec-bob-0002', name: 'Sec-Bob' }
const MEMBER_ATTACKER = { id: 'sec-attacker-01', name: 'Mallory' }
const MEMBER_MALLORY = { id: 'sec-mallory-03', name: 'Sec-Mallory' }

/* ------------------------------------------------------------------ */
/* Generic helpers                                                    */
/* ------------------------------------------------------------------ */

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

async function makeTempDir(prefix = 'dsh-group-sec-v2-') {
  return await fsp.mkdtemp(join(tmpdir(), prefix))
}

async function cleanupDir(directory) {
  for (let attempt = 0; attempt < 10; attempt += 1) {
    try {
      await fsp.rm(directory, { recursive: true, force: true })
      return
    } catch {
      await delay(100)
    }
  }
}

function makeLogger() {
  const logger = {
    lines: [],
    log(...args) { this.lines.push(args.map(String).join(' ')) },
    info(...args) { this.lines.push(args.map(String).join(' ')) },
    warn(...args) { this.lines.push(args.map(String).join(' ')) },
    error(...args) { this.lines.push(args.map(String).join(' ')) },
    debug(...args) { this.lines.push(args.map(String).join(' ')) },
  }
  return logger
}

/** Start one real RoomServer on ephemeral ports with a throwaway data dir. */
async function setupServer(t, overrides = {}) {
  const dataDir = await makeTempDir()
  const logger = overrides.logger ?? makeLogger()
  const server = new RoomServer({
    tcpPort: 0,
    udpPort: 0,
    enableDiscovery: false,
    hostName: 'security-test-host',
    ...overrides,
    dataDir,
    logger,
  })
  const info = await server.listen()
  t.after(async () => {
    await server.close().catch(() => {})
    await cleanupDir(dataDir)
  })
  return { server, dataDir, info, logger }
}

function trackClient(t, client) {
  t.after(() => client.close())
  return client
}

function makeClient(origin, { room = ROOM, password = PASSWORD, member = MEMBER_ALICE, timeoutMs = 5000 } = {}) {
  return new RoomClient({ origin, room, password, member, timeoutMs })
}

function makeSnapshot({ files, note = NOTE_CANARY, by = MEMBER_ALICE } = {}) {
  return {
    rev: 1,
    by,
    note,
    at: new Date().toISOString(),
    files: files ?? [encodeFile(PATH_CANARY, Buffer.from(CONTENT_CANARY, 'utf8'))],
  }
}

/** One raw HTTP JSON round-trip; returns status/text/parsed JSON/headers. */
async function httpJson(url, { method = 'GET', body, rawBody, headers = {} } = {}) {
  const init = { method, headers: { ...headers } }
  if (rawBody !== undefined) {
    init.body = rawBody
  } else if (body !== undefined) {
    init.headers['content-type'] = 'application/json'
    init.body = JSON.stringify(body)
  }
  const response = await fetch(url, init)
  const text = await response.text()
  let json = null
  try {
    json = JSON.parse(text)
  } catch {
    json = null
  }
  return { status: response.status, text, json, headers: Object.fromEntries(response.headers.entries()) }
}

async function challengeRequest(origin, room) {
  return await httpJson(`${origin}/group/v1/challenge`, {
    method: 'POST',
    body: { v: PROTOCOL_VERSION, room },
  })
}

/**
 * Attack-side join preparation: fetch a challenge, derive auth/content keys with the
 * supplied password locally and build the HMAC proof. An attacker with the wrong
 * password therefore produces a well-formed but unverifiable join body.
 */
async function joinRequest(origin, { room = ROOM, password = PASSWORD, member = MEMBER_ALICE } = {}) {
  const challenge = await challengeRequest(origin, room)
  assert.equal(challenge.status, 200, `challenge 应返回 200: ${challenge.text}`)
  const authKey = deriveAuthKey(password, challenge.json.saltAuth)
  const contentKey = deriveContentKey(password, challenge.json.saltContent)
  const nonce = challenge.json.nonce
  const body = {
    v: PROTOCOL_VERSION,
    room,
    member,
    nonce,
    proof: createProof(authKey, room, nonce, member.id),
  }
  const response = await httpJson(`${origin}/group/v1/join`, { method: 'POST', body })
  return { body, challenge, contentKey, response }
}

async function publishRequest(origin, { token, member = MEMBER_MALLORY, baseRev, cipher }) {
  return await httpJson(`${origin}/group/v1/publish`, {
    method: 'POST',
    body: { v: PROTOCOL_VERSION, token, member, baseRev, cipher },
  })
}

/** Read + parse `<dataDir>/rooms/<room>.json`. */
async function readRoomState(dataDir, room = ROOM) {
  const path = join(dataDir, 'rooms', `${room}.json`)
  const text = await fsp.readFile(path, 'utf8')
  return { path, text, json: JSON.parse(text) }
}

/** Walk a directory and return every regular file as `{ path, text }`. */
async function readDataDirFiles(dataDir) {
  const files = []
  async function visit(directoryAbs, relativeDir) {
    const entries = await fsp.readdir(directoryAbs, { withFileTypes: true })
    for (const entry of entries) {
      const relativePath = relativeDir === '' ? entry.name : `${relativeDir}/${entry.name}`
      const absolutePath = join(directoryAbs, entry.name)
      if (entry.isDirectory()) {
        await visit(absolutePath, relativePath)
      } else if (entry.isFile()) {
        files.push({ path: relativePath, text: await fsp.readFile(absolutePath, 'utf8') })
      }
    }
  }
  await visit(dataDir, '')
  return files
}

function assertNoSharedSecrets(text, label) {
  for (const secret of MUST_BE_ABSENT) {
    assert.equal(text.includes(secret), false, `${label} 泄漏了明文/密码片段: ${secret}`)
  }
}

/** Assert a response is a uniform UNAUTHORIZED payload with no room/content data. */
function assertUniformUnauthorized(response, label) {
  assert.equal(response.status, 401, `${label}: 期望 401，实际 ${response.status} ${response.text}`)
  assert.ok(response.json !== null, `${label}: 应为 JSON`)
  assert.equal(response.json.ok, false)
  assert.equal(response.json.error.code, 'UNAUTHORIZED')
  assert.deepEqual(Object.keys(response.json).sort(), ['error', 'ok'], `${label}: 401 响应不得携带额外数据`)
  assert.deepEqual(Object.keys(response.json.error).sort(), ['code', 'message'])
  assertNoSharedSecrets(response.text, label)
  assert.equal(response.text.includes('"cipher"'), false, `${label}: 未授权响应不得返回密文`)
  assert.equal(response.text.includes('"snapshot"'), false, `${label}: 未授权响应不得返回快照`)
  assert.equal(response.text.includes('"members"'), false, `${label}: 未授权响应不得返回成员列表`)
}

/** Structurally valid copy of `cipher` with one byte flipped in `field`. */
function tamperCipher(cipher, field) {
  const parts = normalizeCipher(cipher)
  const buffers = { iv: Buffer.from(parts.iv), tag: Buffer.from(parts.tag), data: Buffer.from(parts.data) }
  const target = buffers[field]
  target[Math.floor(target.length / 2)] ^= 0xff
  return encodeCipher(buffers)
}

/**
 * Record every global `fetch` request/response body made while installed
 * (RoomClient uses the global fetch), so the canary scan covers the real wire.
 */
function installWireRecorder() {
  const original = globalThis.fetch
  const wire = []
  globalThis.fetch = async function recordingFetch(input, init = {}) {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : String(input)
    const method = String(init?.method ?? 'GET').toUpperCase()
    let requestBody = ''
    if (init?.body !== undefined && init?.body !== null) {
      requestBody = typeof init.body === 'string'
        ? init.body
        : Buffer.isBuffer(init.body)
          ? init.body.toString('utf8')
          : String(init.body)
    }
    const response = await original(input, init)
    const responseText = await response.clone().text()
    wire.push({ url, method, requestBody, status: response.status, responseText })
    return response
  }
  return {
    wire,
    restore() {
      globalThis.fetch = original
    },
  }
}

/** Send one raw UDP discovery datagram from a fresh socket; resolve the JSON reply. */
function rawDiscover(udpPort, payload, timeoutMs = 1000) {
  return new Promise((resolve) => {
    const socket = createSocket('udp4')
    let settled = false
    let timer = null
    const finish = (value) => {
      if (settled) return
      settled = true
      if (timer !== null) clearTimeout(timer)
      try {
        socket.close()
      } catch {
        // Already closed.
      }
      resolve(value)
    }
    timer = setTimeout(() => finish(undefined), timeoutMs)
    socket.on('error', () => finish(undefined))
    socket.on('message', (message) => {
      try {
        finish(JSON.parse(message.toString('utf8')))
      } catch {
        finish(undefined)
      }
    })
    socket.bind(0, '127.0.0.1', () => {
      try {
        socket.send(Buffer.from(JSON.stringify(payload), 'utf8'), udpPort, '127.0.0.1', (error) => {
          if (error) finish(undefined)
        })
      } catch {
        finish(undefined)
      }
    })
  })
}

/** Fake UDP discovery responder used to feed hostile v1/v2 replies to the client. */
function startFakeDiscoveryReply(payload) {
  return new Promise((resolve, reject) => {
    const socket = createSocket('udp4')
    socket.once('error', reject)
    socket.bind(0, '127.0.0.1', () => {
      const port = socket.address().port
      socket.on('message', (_message, rinfo) => {
        try {
          socket.send(Buffer.from(JSON.stringify(payload), 'utf8'), rinfo.port, rinfo.address, () => {})
        } catch {
          // Best effort.
        }
      })
      resolve({
        port,
        close: () => new Promise((resolveClose) => {
          try {
            socket.close(resolveClose)
          } catch {
            resolveClose()
          }
        }),
      })
    })
  })
}

function expectCollabRejects(promise, code, label) {
  return assert.rejects(promise, (error) => {
    assert.ok(error instanceof CollabError, `${label}: 期望 CollabError，实际 ${error}`)
    assert.equal(error.code, code, `${label}: 错误码 ${error.code} !== ${code}`)
    return true
  })
}

/**
 * Flatten a (decrypted/normalized) snapshot to searchable plaintext: notes, member
 * names, paths and the decoded bytes of every file. Snapshot `data` is base64, so a
 * raw JSON.stringify() search would produce false "not leaked" results.
 */
function snapshotPlaintextText(snapshot) {
  if (snapshot === null || snapshot === undefined) return ''
  const pieces = []
  if (typeof snapshot.note === 'string') pieces.push(snapshot.note)
  if (typeof snapshot.by?.name === 'string') pieces.push(snapshot.by.name)
  if (Array.isArray(snapshot.changes?.added)) pieces.push(...snapshot.changes.added)
  for (const file of Array.isArray(snapshot.files) ? snapshot.files : []) {
    if (typeof file.path === 'string') pieces.push(file.path)
    if (typeof file.data === 'string') pieces.push(Buffer.from(file.data, 'base64').toString('utf8'))
  }
  return pieces.join('\n')
}

/* ------------------------------------------------------------------ */
/* 1. No credentials => no content                                    */
/* ------------------------------------------------------------------ */

test('安全：无凭证攻击者拿不到任何共享内容（join/latest/status/publish/heartbeat 统一 401）', async (t) => {
  const { server } = await setupServer(t)
  await server.createLocalRoom({ number: ROOM, password: PASSWORD, name: '安全验证房间' })

  // A legitimate member publishes canary content; the server now holds only ciphertext.
  const alice = trackClient(t, makeClient(server.origin))
  const joined = await alice.join()
  await alice.publish({ baseRev: joined.room.rev, snapshot: makeSnapshot() })

  // Challenge is unauthenticated by design, but must not leak content/ciphers.
  const challenge = await challengeRequest(server.origin, ROOM)
  assert.equal(challenge.status, 200)
  assert.deepEqual(Object.keys(challenge.json).sort(), ['nonce', 'ok', 'room', 'saltAuth', 'saltContent', 'v'])
  assert.equal(challenge.json.v, PROTOCOL_VERSION)
  assertNoSharedSecrets(challenge.text, 'challenge 响应')
  assert.equal(challenge.text.includes('cipher'), false)
  assert.equal(challenge.text.includes('snapshot'), false)

  // Wrong password: well-formed proof, uniform 401.
  const attackerJoin = await joinRequest(server.origin, { password: WRONG_PASSWORD, member: MEMBER_ATTACKER })
  assertUniformUnauthorized(attackerJoin.response, '错误密码 join')

  // Unauthenticated / forged-token surface: every authenticated route must be 401.
  const fakeToken = 'f'.repeat(64)
  const unauthResponses = []
  unauthResponses.push(await httpJson(`${server.origin}/group/v1/latest?rev=0`))
  unauthResponses.push(await httpJson(`${server.origin}/group/v1/latest?token=${fakeToken}&rev=0`))
  unauthResponses.push(await httpJson(`${server.origin}/group/v1/status`))
  unauthResponses.push(await httpJson(`${server.origin}/group/v1/status?room=${ROOM}`))
  unauthResponses.push(await httpJson(`${server.origin}/group/v1/status?room=${ROOM_UNKNOWN}`))
  unauthResponses.push(await httpJson(`${server.origin}/group/v1/status?token=${'a'.repeat(64)}`))
  unauthResponses.push(await httpJson(`${server.origin}/group/v1/heartbeat`, {
    method: 'POST',
    body: { token: '', member: MEMBER_ATTACKER },
  }))
  unauthResponses.push(await httpJson(`${server.origin}/group/v1/leave`, {
    method: 'POST',
    body: {},
  }))
  // Structurally valid cipher, but the token is missing: the server must reject
  // before storing anything.
  const unknownChallenge = await challengeRequest(server.origin, ROOM)
  const unknownContentKey = deriveContentKey(PASSWORD, unknownChallenge.json.saltContent)
  const validLookingCipher = encryptSnapshot(unknownContentKey, ROOM, 1, {
    by: MEMBER_ATTACKER,
    note: '',
    at: new Date().toISOString(),
    files: [],
    changes: { added: [], modified: [], deleted: [] },
  })
  unauthResponses.push(await httpJson(`${server.origin}/group/v1/publish`, {
    method: 'POST',
    body: { v: PROTOCOL_VERSION, token: '', member: MEMBER_ATTACKER, baseRev: 0, cipher: validLookingCipher },
  }))

  for (const [index, response] of unauthResponses.entries()) {
    assertUniformUnauthorized(response, `未授权请求 #${index + 1}`)
  }
  // Leave is idempotent by design: an unknown (unguessable, 256-bit) token is simply
  // a no-op that returns {ok:true} and never reveals room/content data.
  const unknownTokenLeave = await httpJson(`${server.origin}/group/v1/leave`, {
    method: 'POST',
    body: { token: 'b'.repeat(64) },
  })
  assert.equal(unknownTokenLeave.status, 200)
  assert.deepEqual(unknownTokenLeave.json, { ok: true })

  // Authorized status works and still never contains content / digest / ciphertext.
  const status = await alice.status()
  assert.equal(status.ok, true)
  assert.equal(status.v, PROTOCOL_VERSION)
  assert.equal(status.room.number, ROOM)
  assert.equal('snapshotDigest' in status, false, 'v2 status 不再返回明文摘要')
  assert.equal(JSON.stringify(status).includes('"cipher"'), false)
  assertNoSharedSecrets(JSON.stringify(status), '授权 status')

  // Published canary content is reachable only through the authenticated client path.
  const latest = await alice.latest(0)
  assert.ok(latest.snapshot !== null)
  assert.equal(snapshotPlaintextText(latest.snapshot).includes(CONTENT_CANARY), true)
})

/* ------------------------------------------------------------------ */
/* 2. Canary: no plaintext on the wire / disk / logs                  */
/* ------------------------------------------------------------------ */

test('安全：线上与磁盘无明文金丝雀（请求/响应/房间 JSON/数据目录/日志）', async (t) => {
  const recorder = installWireRecorder()
  const { server, dataDir, logger } = await setupServer(t)
  let bob = null
  try {
    await server.createLocalRoom({ number: ROOM, password: PASSWORD, name: '金丝雀房间' })
    const alice = trackClient(
      t,
      new RoomClient({
        origin: server.origin,
        room: ROOM,
        password: PASSWORD,
        member: { id: 'sec-alice-0001', name: MEMBER_NAME_CANARY },
      }),
    )
    const aliceJoined = await alice.join()
    const published = await alice.publish({ baseRev: aliceJoined.room.rev, snapshot: makeSnapshot() })
    assert.equal(published.rev, 1)

    bob = trackClient(
      t,
      new RoomClient({ origin: server.origin, room: ROOM, password: PASSWORD, member: MEMBER_BOB }),
    )
    const bobJoined = await bob.join()
    assert.ok(bobJoined.snapshot !== null, '合法成员加入后必须能解密出明文快照')
    assert.ok(snapshotPlaintextText(bobJoined.snapshot).includes(CONTENT_CANARY), '金丝雀内容必须真实存在于快照中')
    const bobLatest = await bob.latest(0)
    assert.ok(snapshotPlaintextText(bobLatest.snapshot).includes(PATH_CANARY))
    const bobStatus = await bob.status()
    assert.equal(bobStatus.room.number, ROOM)
    await bob.leave()
  } finally {
    recorder.restore()
    if (bob !== null) bob.close()
  }

  /* -------- wire capture: every request and response body -------- */
  assert.ok(recorder.wire.length >= 6, `抓包数量异常: ${recorder.wire.length}`)
  for (const entry of recorder.wire) {
    assertNoSharedSecrets(entry.requestBody, `HTTP 请求 ${entry.method} ${entry.url}`)
    assertNoSharedSecrets(entry.responseText, `HTTP 响应 ${entry.method} ${entry.url}`)
    // The password itself must never be placed on the wire at all.
    assert.equal(entry.requestBody.includes(PASSWORD), false, `请求体出现密码: ${entry.url}`)
    // Member name is documented metadata: it may appear only inside a member object.
    if (entry.requestBody.includes(MEMBER_NAME_CANARY)) {
      const parsed = JSON.parse(entry.requestBody)
      assert.equal(parsed.member?.name, MEMBER_NAME_CANARY, '成员名只能出现在 member 元数据里')
      delete parsed.member
      assert.equal(JSON.stringify(parsed).includes(MEMBER_NAME_CANARY), false, 'member 之外的请求字段不得含成员名')
    }
    // Responses: member names may appear only in the top-level members roster.
    if (entry.responseText.includes(MEMBER_NAME_CANARY)) {
      const parsed = JSON.parse(entry.responseText)
      delete parsed.members
      assert.equal(JSON.stringify(parsed).includes(MEMBER_NAME_CANARY), false, 'members 之外的响应字段不得含成员名')
    }
  }

  // Published ciphertext is present and is the only content representation on the wire.
  const publishEntry = recorder.wire.find((entry) => entry.url.includes('/group/v1/publish') && entry.status === 200)
  assert.ok(publishEntry !== undefined)
  const publishBody = JSON.parse(publishEntry.requestBody)
  assert.deepEqual(Object.keys(publishBody.cipher).sort(), ['data', 'iv', 'tag', 'v'])
  assert.equal(publishBody.cipher.v, CIPHER_VERSION)
  assert.equal(publishBody.cipher.data.length > 64, true)
  assert.deepEqual(Object.keys(publishBody).sort(), ['baseRev', 'cipher', 'member', 'token', 'v'])

  const latestEntry = recorder.wire.find((entry) => entry.url.includes('/group/v1/latest') && entry.status === 200)
  assert.ok(latestEntry !== undefined)
  const latestBody = JSON.parse(latestEntry.responseText)
  assert.deepEqual(Object.keys(latestBody.snapshot).sort(), ['cipher', 'rev'])
  assert.deepEqual(Object.keys(latestBody.snapshot.cipher).sort(), ['data', 'iv', 'tag', 'v'])
  assert.equal(latestBody.snapshot.cipher.v, 2)
  assert.equal(latestBody.snapshot.rev, 1)
  assert.deepEqual(Object.keys(latestBody.lastUpdate).sort(), ['at', 'rev'], 'v2 服务器 lastUpdate 不得含 by/note/changes')

  /* -------- room JSON on disk: field whitelist, ciphertext only -------- */
  const roomState = await readRoomState(dataDir)
  assert.deepEqual(
    Object.keys(roomState.json).sort(),
    ['authKey', 'createdAt', 'lastUpdate', 'name', 'number', 'rev', 'saltAuth', 'saltContent', 'snapshot', 'version'],
    `房间 JSON 字段白名单不匹配: ${JSON.stringify(Object.keys(roomState.json))}`,
  )
  assert.equal(roomState.json.version, PROTOCOL_VERSION)
  assert.equal(roomState.json.number, ROOM)
  assert.equal(roomState.json.rev, 1)
  assert.match(roomState.json.authKey, /^[0-9a-f]{64}$/u)
  assert.match(roomState.json.saltAuth, /^[0-9a-f]{32}$/u)
  assert.match(roomState.json.saltContent, /^[0-9a-f]{32}$/u)
  assert.deepEqual(Object.keys(roomState.json.snapshot).sort(), ['at', 'cipher', 'rev'])
  assert.deepEqual(Object.keys(roomState.json.snapshot.cipher).sort(), ['data', 'iv', 'tag', 'v'])
  assert.equal(roomState.json.snapshot.cipher.v, 2)
  // No password verifier-material or plaintext-shaped keys anywhere in the file.
  for (const forbiddenKey of ['password', 'passwordHash', 'plaintext', 'files', 'note', 'changes', 'by']) {
    assert.equal(Object.keys(roomState.json).includes(forbiddenKey), false, `房间 JSON 不得含 ${forbiddenKey}`)
    assert.equal(roomState.json.snapshot.cipher[forbiddenKey], undefined)
  }
  assert.equal(roomState.text.includes('passwordHash'), false)
  assert.equal(roomState.text.includes('"password"'), false)
  assert.equal(roomState.text.includes('"files"'), false)
  assert.equal(roomState.text.includes('"note"'), false)
  assertNoSharedSecrets(roomState.text, '房间 JSON')
  assert.equal(roomState.text.includes(MEMBER_NAME_CANARY), false, '服务器不得持久化成员名/成员列表')
  // The authKey verifier must never cross the wire (it exists only on the server disk).
  for (const entry of recorder.wire) {
    assert.equal(entry.requestBody.includes(roomState.json.authKey), false, 'authKey verifier 出现在请求体中')
    assert.equal(entry.responseText.includes(roomState.json.authKey), false, 'authKey verifier 出现在响应体中')
  }

  // The persisted ciphertext really is the encrypted canary payload.
  const diskChallenge = await challengeRequest(server.origin, ROOM)
  const diskContentKey = deriveContentKey(PASSWORD, diskChallenge.json.saltContent)
  const decrypted = decryptSnapshot(diskContentKey, ROOM, roomState.json.snapshot.rev, roomState.json.snapshot.cipher)
  const decryptedText = snapshotPlaintextText(decrypted)
  for (const secret of [CONTENT_CANARY, PATH_CANARY, NOTE_CANARY, MEMBER_NAME_CANARY]) {
    assert.equal(decryptedText.includes(secret), true, `密文解密后应包含金丝雀: ${secret}`)
  }

  /* -------- all server data files + logger output -------- */
  const dataFiles = await readDataDirFiles(dataDir)
  assert.ok(dataFiles.length >= 1)
  for (const file of dataFiles) {
    assertNoSharedSecrets(file.text, `服务器数据文件 ${file.path}`)
    assert.equal(file.text.includes(MEMBER_NAME_CANARY), false, `服务器数据文件 ${file.path} 含成员名`)
  }
  for (const line of logger.lines) {
    assertNoSharedSecrets(line, '服务器日志')
    assert.equal(line.includes(MEMBER_NAME_CANARY), false, '服务器日志含成员名')
  }
})

/* ------------------------------------------------------------------ */
/* 3. Anti-enumeration                                                */
/* ------------------------------------------------------------------ */

test('安全：反枚举（challenge 同形/稳定假盐、join 与 status 均不可区分房间存在性）', async (t) => {
  const { server } = await setupServer(t)
  await server.createLocalRoom({ number: ROOM, password: PASSWORD, name: '真实房间' })

  const knownFirst = await challengeRequest(server.origin, ROOM)
  const knownSecond = await challengeRequest(server.origin, ROOM)
  const unknownFirst = await challengeRequest(server.origin, ROOM_UNKNOWN)
  const unknownSecond = await challengeRequest(server.origin, ROOM_UNKNOWN)
  const expectedKeys = ['nonce', 'ok', 'room', 'saltAuth', 'saltContent', 'v']
  for (const [label, response, room] of [
    ['已知房间 challenge #1', knownFirst, ROOM],
    ['已知房间 challenge #2', knownSecond, ROOM],
    ['未知房间 challenge #1', unknownFirst, ROOM_UNKNOWN],
    ['未知房间 challenge #2', unknownSecond, ROOM_UNKNOWN],
  ]) {
    assert.equal(response.status, 200, `${label} 应返回 200`)
    assert.deepEqual(Object.keys(response.json).sort(), expectedKeys, `${label} 响应形状必须一致`)
    assert.equal(response.json.v, PROTOCOL_VERSION)
    assert.equal(response.json.room, room)
    assert.match(response.json.saltAuth, /^[0-9a-f]{32}$/u, `${label} saltAuth 形状`)
    assert.match(response.json.saltContent, /^[0-9a-f]{32}$/u, `${label} saltContent 形状`)
    assert.match(response.json.nonce, /^[0-9a-f]{48}$/u, `${label} nonce 形状`)
    assert.equal('name' in response.json, false, 'challenge 不得泄露房间名')
    assert.equal(response.text.includes('snapshot'), false)
  }
  // Stable salts: repeated probes cannot distinguish "stable real room" from "random
  // unknown room" — both are stable per server process.
  assert.equal(knownFirst.json.saltAuth, knownSecond.json.saltAuth)
  assert.equal(knownFirst.json.saltContent, knownSecond.json.saltContent)
  assert.equal(unknownFirst.json.saltAuth, unknownSecond.json.saltAuth)
  assert.equal(unknownFirst.json.saltContent, unknownSecond.json.saltContent)
  assert.notEqual(unknownFirst.json.saltAuth, knownFirst.json.saltAuth)
  assert.notEqual(unknownFirst.json.saltContent, knownFirst.json.saltContent)
  assert.notEqual(knownFirst.json.nonce, knownSecond.json.nonce, 'nonce 必须每次刷新')

  // Wrong password vs unknown room: byte-identical 401.
  const wrongPasswordJoin = await joinRequest(server.origin, { room: ROOM, password: WRONG_PASSWORD, member: MEMBER_ATTACKER })
  const unknownRoomJoin = await joinRequest(server.origin, { room: ROOM_UNKNOWN, password: WRONG_PASSWORD, member: MEMBER_ATTACKER })
  assert.equal(wrongPasswordJoin.response.status, 401)
  assert.equal(unknownRoomJoin.response.status, 401)
  assert.deepEqual(unknownRoomJoin.response.json, wrongPasswordJoin.response.json)
  assert.equal(unknownRoomJoin.response.text, wrongPasswordJoin.response.text)
  assert.equal(unknownRoomJoin.response.headers['content-type'], wrongPasswordJoin.response.headers['content-type'])

  // Unauthenticated status must not confirm existence either.
  const knownStatus = await httpJson(`${server.origin}/group/v1/status?room=${ROOM}`)
  const unknownStatus = await httpJson(`${server.origin}/group/v1/status?room=${ROOM_UNKNOWN}`)
  const noRoomStatus = await httpJson(`${server.origin}/group/v1/status`)
  for (const response of [knownStatus, unknownStatus, noRoomStatus]) {
    assertUniformUnauthorized(response, '未授权 status')
  }
  assert.deepEqual(knownStatus.json, unknownStatus.json)
  assert.equal(knownStatus.text, unknownStatus.text)
})

/* ------------------------------------------------------------------ */
/* 4. Ciphertext integrity / AAD / client-side plaintext validation   */
/* ------------------------------------------------------------------ */

test('安全：密文篡改、换 rev/AAD、重放旧密文均被合法客户端与 CollabRuntime 拒绝且不写文件', async (t) => {
  const { server, dataDir } = await setupServer(t)
  await server.createLocalRoom({ number: ROOM, password: PASSWORD, name: '完整性房间' })

  // rev 1: legitimate member publishes canary content.
  const alice = trackClient(t, makeClient(server.origin))
  const joined = await alice.join()
  await alice.publish({ baseRev: joined.room.rev, snapshot: makeSnapshot() })
  const captured = await readRoomState(dataDir)
  const capturedCipher = captured.json.snapshot.cipher
  assert.equal(captured.json.snapshot.rev, 1)

  // A real runtime joins so we can prove failed decryption never writes shared/.
  const workspace = await makeTempDir()
  const runtime = new CollabRuntime({
    config: { dataDir: join(workspace, 'runtime'), pollMs: 1_000_000, enableDiscovery: false },
    logger: makeLogger(),
    notify: () => true,
  })
  t.after(async () => {
    await runtime.dispose().catch(() => {})
    await cleanupDir(workspace)
  })
  const rootB = join(workspace, 'workspace-b')
  const bJoin = await runtime.joinRoom(rootB, {
    room: ROOM,
    password: PASSWORD,
    address: server.origin,
    memberName: 'Sec-Bob',
  })
  assert.equal(bJoin.snapshotApplied, true)
  const sharedBefore = await readSnapshotFiles(sharedDir(rootB))
  assert.ok(sharedBefore.length >= 1)

  // Simulate a member/hostile relay that can only produce structurally valid blobs.
  const mallory = await joinRequest(server.origin, { member: MEMBER_MALLORY })
  assert.equal(mallory.response.status, 200)
  const token = mallory.response.json.token
  let baseRev = server.listRooms()[0].rev

  /** Publish one tampered blob and assert the legitimate client/runtime rejects it. */
  const assertTamperedRejected = async (label, cipher) => {
    const published = await publishRequest(server.origin, { token, member: MEMBER_MALLORY, baseRev, cipher })
    assert.equal(published.status, 200, `${label}: 服务器只校验密文结构，应接受该 blob`)
    baseRev = published.json.rev
    await expectCollabRejects(alice.latest(1), 'PROTOCOL', `${label}: 合法客户端 latest`)
    // A fresh legitimate join must also refuse the poisoned snapshot.
    const late = trackClient(t, makeClient(server.origin, { member: { id: 'sec-late-0003', name: 'Sec-Late' } }))
    await expectCollabRejects(late.join(), 'PROTOCOL', `${label}: 合法客户端 join`)
    // The runtime must fail its sync and never write the forged content.
    await expectCollabRejects(runtime.sync(rootB), 'PROTOCOL', `${label}: CollabRuntime.sync`)
    const sharedAfter = await readSnapshotFiles(sharedDir(rootB))
    assert.deepEqual(sharedAfter, sharedBefore, `${label}: 解密失败时绝不能写入 shared/`)
  }

  await assertTamperedRejected('翻转 cipher.data 字节', tamperCipher(capturedCipher, 'data'))
  await assertTamperedRejected('翻转 cipher.tag 字节', tamperCipher(capturedCipher, 'tag'))
  await assertTamperedRejected('翻转 cipher.iv 字节', tamperCipher(capturedCipher, 'iv'))
  // Replay: an old, internally valid rev-1 cipher published at a later revision must
  // fail the GCM AAD binding (`room:rev`).
  await assertTamperedRejected('旧密文重放到新 rev（AAD 不匹配）', capturedCipher)

  // Server persisted the last (replayed) blob verbatim: it is blind to plaintext.
  const finalState = await readRoomState(dataDir)
  assert.equal(finalState.json.snapshot.cipher.data, capturedCipher.data)
  assertNoSharedSecrets(finalState.text, '房间 JSON（被污染后）')

  // Decrypted-but-invalid plaintext from a malicious member is rejected by the
  // client-side normalizeSnapshot() before it can be written anywhere.
  const rawChallenge = await challengeRequest(server.origin, ROOM)
  const contentKey = deriveContentKey(PASSWORD, rawChallenge.json.saltContent)
  const evilRev = baseRev + 1
  const evilCipher = encryptSnapshot(contentKey, ROOM, evilRev, {
    by: MEMBER_MALLORY,
    note: 'evil',
    at: new Date().toISOString(),
    files: [
      {
        path: '../escape.txt',
        size: 4,
        sha256: 'a'.repeat(64),
        data: Buffer.from('evil').toString('base64'),
      },
    ],
    changes: { added: ['../escape.txt'], modified: [], deleted: [] },
  })
  const evilPublish = await publishRequest(server.origin, { token, member: MEMBER_MALLORY, baseRev, cipher: evilCipher })
  assert.equal(evilPublish.status, 200)
  baseRev = evilPublish.json.rev
  await expectCollabRejects(alice.latest(1), 'BAD_PATH', '合法客户端必须拒绝越界明文路径')
  await expectCollabRejects(runtime.sync(rootB), 'BAD_PATH', 'CollabRuntime 必须拒绝越界明文路径')
  assert.deepEqual(await readSnapshotFiles(sharedDir(rootB)), sharedBefore)
})

/* ------------------------------------------------------------------ */
/* 5. Rate limiting                                                   */
/* ------------------------------------------------------------------ */

test('安全：challenge 限流 30 次/分钟 -> 429 + retryAfterSeconds/Retry-After', async (t) => {
  const { server } = await setupServer(t)
  await server.createLocalRoom({ number: ROOM, password: PASSWORD })

  for (let index = 1; index <= 30; index += 1) {
    const response = await challengeRequest(server.origin, ROOM)
    assert.equal(response.status, 200, `第 ${index} 次 challenge 应被允许: ${response.text}`)
  }
  const limited = await challengeRequest(server.origin, ROOM)
  assert.equal(limited.status, 429, `第 31 次 challenge 必须被限流: ${limited.text}`)
  assert.equal(limited.json.ok, false)
  assert.equal(limited.json.error.code, 'TOO_MANY_REQUESTS')
  const retryAfterSeconds = limited.json.error.details.retryAfterSeconds
  assert.ok(Number.isInteger(retryAfterSeconds) && retryAfterSeconds >= 1 && retryAfterSeconds <= 60)
  assert.equal(limited.headers['retry-after'], String(retryAfterSeconds), '必须同时返回 Retry-After 头')
  assertNoSharedSecrets(limited.text, '429 响应')
  // The server stays usable for other authenticated-surface checks.
  const status = await httpJson(`${server.origin}/group/v1/status`)
  assertUniformUnauthorized(status, '限流后 status')
})

test('安全：连续 5 次错误 join 锁定 429（retryAfter/Retry-After），成功加入清零失败计数', async (t) => {
  // --- lockout after 5 failures ---
  const first = await setupServer(t)
  await first.server.createLocalRoom({ number: ROOM, password: PASSWORD })
  for (let index = 1; index <= 5; index += 1) {
    const attempt = await joinRequest(first.server.origin, { password: WRONG_PASSWORD, member: MEMBER_ATTACKER })
    assert.equal(attempt.response.status, 401, `第 ${index} 次错误密码 join 应 401`)
  }
  // Even a correct password is now locked out.
  const locked = await joinRequest(first.server.origin, { password: PASSWORD, member: MEMBER_ATTACKER })
  assert.equal(locked.response.status, 429, `连续 5 次失败后必须锁定: ${locked.response.text}`)
  assert.equal(locked.response.json.error.code, 'TOO_MANY_REQUESTS')
  const retryAfterSeconds = locked.response.json.error.details.retryAfterSeconds
  assert.ok(Number.isInteger(retryAfterSeconds) && retryAfterSeconds >= 1 && retryAfterSeconds <= 60)
  assert.equal(locked.response.headers['retry-after'], String(retryAfterSeconds))
  assertNoSharedSecrets(locked.response.text, '锁定 429 响应')
  // Challenge itself is still served (we are below the 30/min challenge limit).
  const challengeAfterLock = await challengeRequest(first.server.origin, ROOM)
  assert.equal(challengeAfterLock.status, 200)

  // --- success clears the failure counter (fresh server to avoid inherited lock) ---
  const second = await setupServer(t)
  await second.server.createLocalRoom({ number: ROOM, password: PASSWORD })
  for (let index = 0; index < 4; index += 1) {
    const attempt = await joinRequest(second.server.origin, { password: WRONG_PASSWORD, member: MEMBER_ATTACKER })
    assert.equal(attempt.response.status, 401)
  }
  const successOnce = await joinRequest(second.server.origin, { password: PASSWORD, member: MEMBER_ATTACKER })
  assert.equal(successOnce.response.status, 200, '4 次失败后正确密码应能成功')
  assert.match(successOnce.response.json.token, /^[0-9a-f]{64}$/u)
  for (let index = 0; index < 4; index += 1) {
    const attempt = await joinRequest(second.server.origin, { password: WRONG_PASSWORD, member: MEMBER_ATTACKER })
    assert.equal(attempt.response.status, 401, '成功加入后失败计数应已清零，仍应为 401 而非 429')
  }
  const successTwice = await joinRequest(second.server.origin, { password: PASSWORD, member: MEMBER_ATTACKER })
  assert.equal(successTwice.response.status, 200, '成功加入必须清零失败计数，否则此处会被锁定')
})

/* ------------------------------------------------------------------ */
/* 6. Legacy v1 room files                                            */
/* ------------------------------------------------------------------ */

test('安全：v1 房间文件被改名 .legacy-v1、不提供服务、可重建同名 v2 房间', async (t) => {
  const dataDir = await makeTempDir()
  t.after(() => cleanupDir(dataDir))
  const roomsDir = join(dataDir, 'rooms')
  await fsp.mkdir(roomsDir, { recursive: true })

  const legacyDocument = {
    number: LEGACY_ROOM,
    name: `旧房间-${CANARY}`,
    rev: 2,
    snapshot: {
      rev: 2,
      by: { id: 'legacy-0001', name: 'Legacy' },
      note: NOTE_CANARY,
      at: new Date().toISOString(),
      files: [{ path: PATH_CANARY, size: 3, sha256: 'a'.repeat(64), data: Buffer.from('abc').toString('base64') }],
      changes: { added: [PATH_CANARY], modified: [], deleted: [] },
    },
    salt: 'aa'.repeat(16),
    passwordHash: 'bb'.repeat(32),
    createdAt: new Date().toISOString(),
    lastUpdate: { by: { id: 'legacy-0001', name: 'Legacy' }, note: NOTE_CANARY, at: new Date().toISOString(), rev: 2, changes: {} },
  }
  const legacyText = JSON.stringify(legacyDocument)
  await fsp.writeFile(join(roomsDir, `${LEGACY_ROOM}.json`), legacyText, 'utf8')

  const logger = makeLogger()
  const server = new RoomServer({ dataDir, tcpPort: 0, udpPort: 0, enableDiscovery: false, logger, hostName: 'security-test-host' })
  t.after(() => server.close().catch(() => {}))
  await server.listen()

  // Renamed, preserved byte-for-byte, never served.
  assert.equal(server.hasRoom(LEGACY_ROOM), false)
  const entries = await fsp.readdir(roomsDir)
  assert.equal(entries.includes(`${LEGACY_ROOM}.json`), false)
  assert.ok(entries.includes(`${LEGACY_ROOM}.json.legacy-v1`), `期望 .legacy-v1 文件，实际: ${entries.join(', ')}`)
  assert.equal(
    await fsp.readFile(join(roomsDir, `${LEGACY_ROOM}.json.legacy-v1`), 'utf8'),
    legacyText,
    '旧房间文件必须被保留而不是删除',
  )
  assert.ok(logger.lines.some((line) => line.includes('legacy-v1')), '应记录旧房间被忽略的告警')
  // A join against the ignored legacy room fails with the uniform 401.
  const legacyJoin = await joinRequest(server.origin, { room: LEGACY_ROOM, password: PASSWORD, member: MEMBER_ATTACKER })
  assertUniformUnauthorized(legacyJoin.response, '旧 v1 房间 join')

  // Same number can be recreated as a v2 room; its file must be ciphertext-only.
  const created = await server.createLocalRoom({ number: LEGACY_ROOM, password: PASSWORD, name: '重建房间' })
  assert.equal(created.number, LEGACY_ROOM)
  assert.equal(created.rev, 0)
  assert.equal(server.hasRoom(LEGACY_ROOM), true)
  const rebuilt = await readRoomState(dataDir, LEGACY_ROOM)
  assert.equal(rebuilt.json.version, PROTOCOL_VERSION)
  assert.equal('passwordHash' in rebuilt.json, false, 'v2 房间不得含 passwordHash')
  assert.match(rebuilt.json.authKey, /^[0-9a-f]{64}$/u)
  assert.equal(rebuilt.json.snapshot, null)
  assertNoSharedSecrets(rebuilt.text, '重建的 v2 房间 JSON')
  assert.equal(rebuilt.text.includes(NOTE_CANARY), false)
  // Legacy file still preserved after recreation.
  assert.equal(await fsp.readFile(join(roomsDir, `${LEGACY_ROOM}.json.legacy-v1`), 'utf8'), legacyText)

  // The rebuilt v2 room supports a real encrypted flow.
  const client = trackClient(t, makeClient(server.origin, { room: LEGACY_ROOM }))
  const joined = await client.join()
  await client.publish({ baseRev: joined.room.rev, snapshot: makeSnapshot() })
  const latest = await client.latest(0)
  assert.ok(snapshotPlaintextText(latest.snapshot).includes(CONTENT_CANARY))
})

/* ------------------------------------------------------------------ */
/* 7. UDP discovery                                                   */
/* ------------------------------------------------------------------ */

test('安全：UDP 发现 v2 应答无房间名，v1 应答被客户端拒绝', async (t) => {
  const { server, info } = await setupServer(t, { enableDiscovery: true })
  assert.ok(Number.isInteger(info.udpPort) && info.udpPort > 0, 'UDP 发现端口必须真实绑定')
  const roomNameCanary = `房间名-${CANARY}`
  await server.createLocalRoom({ number: ROOM, password: PASSWORD, name: roomNameCanary })

  // Real v2 server reply: number + URL only, and definitely no room name.
  const reply = await rawDiscover(info.udpPort, { t: 'dsh-group-discover', v: PROTOCOL_VERSION, room: ROOM })
  assert.ok(reply !== undefined, 'v2 发现应收到应答')
  assert.deepEqual(Object.keys(reply).sort(), ['room', 't', 'url', 'v'])
  assert.equal(reply.t, 'dsh-group-room')
  assert.equal(reply.v, PROTOCOL_VERSION)
  assert.equal(reply.room, ROOM)
  assert.equal('name' in reply, false, 'v2 发现应答不得包含房间名')
  assert.equal(JSON.stringify(reply).includes(roomNameCanary), false, 'UDP 应答泄漏房间名')
  assert.equal(reply.url, server.origin)

  // A hostile v1 responder must be ignored by discoverRoom().
  const v1Responder = await startFakeDiscoveryReply({
    t: 'dsh-group-room',
    v: 1,
    room: ROOM,
    name: roomNameCanary,
    url: 'http://127.0.0.1:1',
  })
  t.after(() => v1Responder.close())
  const legacyFound = await discoverRoom({
    room: ROOM,
    udpPort: v1Responder.port,
    timeoutMs: 900,
    broadcastAddresses: ['127.0.0.1'],
  })
  assert.equal(legacyFound, undefined, '客户端必须拒绝 v1 UDP 发现应答')

  // A v2 responder is accepted but only `{origin, room, via}` is returned.
  const v2Responder = await startFakeDiscoveryReply({
    t: 'dsh-group-room',
    v: PROTOCOL_VERSION,
    room: ROOM,
    name: roomNameCanary,
    url: 'http://127.0.0.1:45999',
  })
  t.after(() => v2Responder.close())
  const foundV2 = await discoverRoom({
    room: ROOM,
    udpPort: v2Responder.port,
    timeoutMs: 1500,
    broadcastAddresses: ['127.0.0.1'],
  })
  assert.ok(foundV2 !== undefined, 'v2 应答必须被接受')
  assert.deepEqual(Object.keys(foundV2).sort(), ['origin', 'room', 'via'])
  assert.equal('name' in foundV2, false, 'discoverRoom 不得返回房间名')
  assert.equal(foundV2.origin, 'http://127.0.0.1:45999')
  assert.equal(foundV2.room, ROOM)
  assert.equal(foundV2.via, 'discovery')
})

test('安全（残余风险声明）：仅窃取房间 JSON 的 authKey 可冒充加入并拿到密文，但无法解密内容', async (t) => {
  const { server, dataDir } = await setupServer(t)
  await server.createLocalRoom({ number: ROOM, password: PASSWORD, name: '磁盘泄露场景' })
  const alice = trackClient(t, makeClient(server.origin))
  const joined = await alice.join()
  await alice.publish({ baseRev: joined.room.rev, snapshot: makeSnapshot() })

  // SECURITY.md: a room-file thief gets authKey (verifier) and ciphertext, but the
  // content key is derived from the password and never stored server-side.
  const roomState = await readRoomState(dataDir)
  const { saltContent, authKey } = roomState.json
  assert.match(authKey, /^[0-9a-f]{64}$/u)
  assert.equal(Object.keys(roomState.json).includes('contentKey'), false, '服务器不得保存内容密钥')
  assert.equal(roomState.text.includes(PASSWORD), false)

  // Stolen verifier is enough to forge a valid HMAC proof and join (impersonation).
  const attackerMember = { id: 'disk-attacker-1', name: 'DiskThief' }
  const challenge = await challengeRequest(server.origin, ROOM)
  const proof = createProof(authKey, ROOM, challenge.json.nonce, attackerMember.id)
  const stolenJoin = await httpJson(`${server.origin}/group/v1/join`, {
    method: 'POST',
    body: { v: PROTOCOL_VERSION, room: ROOM, member: attackerMember, nonce: challenge.json.nonce, proof },
  })
  assert.equal(stolenJoin.status, 200, '持有 authKey 的攻击者可冒充成员加入（SECURITY.md 已声明的残余风险）')
  assert.match(stolenJoin.json.token, /^[0-9a-f]{64}$/u)
  assert.ok(stolenJoin.json.snapshot !== null)
  assert.deepEqual(Object.keys(stolenJoin.json.snapshot).sort(), ['cipher', 'rev'])
  assert.equal(stolenJoin.text.includes(CONTENT_CANARY), false, '冒充加入只能拿到密文')
  assert.equal(stolenJoin.text.includes(NOTE_CANARY), false)

  // ...but without the password the AES-GCM content key cannot be derived: decryption
  // with any guess fails, so the stolen room file exposes no content.
  const wrongGuessKey = deriveContentKey('Not-The-Passw0rd', saltContent)
  assert.throws(
    () => decryptSnapshot(wrongGuessKey, ROOM, stolenJoin.json.snapshot.rev, stolenJoin.json.snapshot.cipher),
    (error) => {
      assert.ok(error instanceof CollabError)
      assert.equal(error.code, 'PROTOCOL')
      return true
    },
    '无密码无法解密窃取到的密文',
  )
  // Sanity check: the real password-derived key does decrypt, i.e. the cipher is real.
  const realKey = deriveContentKey(PASSWORD, saltContent)
  const plaintext = decryptSnapshot(realKey, ROOM, stolenJoin.json.snapshot.rev, stolenJoin.json.snapshot.cipher)
  assert.ok(snapshotPlaintextText(plaintext).includes(CONTENT_CANARY))
})

/* ------------------------------------------------------------------ */
/* 9. Password policy / protocol version contract                     */
/* ------------------------------------------------------------------ */

test('安全：协议版本为 2，短密码在客户端与服务端均被拒绝', async () => {
  assert.equal(PROTOCOL_VERSION, 2)
  assert.equal(CIPHER_VERSION, 2)
  const shortPassword = 'short-1'
  const client = new RoomClient({
    origin: 'http://127.0.0.1:1',
    room: ROOM,
    password: shortPassword,
    member: MEMBER_ALICE,
  })
  await expectCollabRejects(client.join(), 'BAD_PASSWORD', '客户端短密码')
  client.close()

  const dataDir = await makeTempDir()
  const server = new RoomServer({ dataDir, tcpPort: 0, udpPort: 0, enableDiscovery: false, logger: makeLogger() })
  try {
    await server.listen()
    await assert.rejects(
      server.createLocalRoom({ number: ROOM, password: shortPassword }),
      (error) => {
        assert.ok(error instanceof CollabError)
        assert.equal(error.code, 'BAD_PASSWORD')
        return true
      },
    )
    await assert.rejects(
      server.createLocalRoom({ number: '12', password: PASSWORD }),
      (error) => {
        assert.ok(error instanceof CollabError)
        assert.equal(error.code, 'BAD_ROOM')
        return true
      },
    )
  } finally {
    await server.close().catch(() => {})
    await cleanupDir(dataDir)
  }
})
