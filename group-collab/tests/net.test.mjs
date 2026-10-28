/**
 * Network-layer tests for the DSH Group Collaboration plugin — PROTOCOL v2.
 *
 * SECURITY.md is authoritative: passwords never cross the wire, shared content is
 * end-to-end encrypted and the server stores/returns ciphertext only.
 *
 * Run with the bundled node binary from `Z:\try\work\group-collab`:
 *   node --test tests/net.test.mjs
 *
 * Covers: challenge-response join, canary proof that no plaintext (password / file
 * content / update note / paths) appears on the wire or in room JSON, ciphertext
 * tamper + AAD/replay rejection, token auth on every endpoint, per-IP rate limiting
 * and lockout with success reset, unknown-room anti-enumeration, legacy v1 room
 * files, v2 UDP discovery without room names, concurrent publish conflicts with
 * decryptable latest ciphertext, restart persistence and clean shutdown.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import net from 'node:net'
import { createSocket } from 'node:dgram'
import { promises as fsp } from 'node:fs'
import { tmpdir, networkInterfaces } from 'node:os'
import { join } from 'node:path'

import { RoomServer, resolveAdvertisedUrl } from '../lib/room-server.js'
import { RoomClient, discoverRoom } from '../lib/room-client.js'
import { CollabError, encodeFile, decodeFile, validatePassword, PROTOCOL_VERSION } from '../lib/protocol.js'
import {
  createProof,
  decryptSnapshot,
  deriveAuthKey,
  deriveContentKey,
  encodeCipher,
  encryptSnapshot,
  normalizeCipher,
  randomSalt,
} from '../lib/crypto.js'

const ROOM = '123456'
const UNKNOWN_ROOM = '999999'
const PASSWORD = 'Canary-Passw0rd-9x'
const WRONG_PASSWORD = 'Wrong-Passw0rd-8x'
const CANARY_CONTENT = 'CANARY_CONTENT_9f3c2a_绝密共享内容'
const CANARY_NOTE = 'CANARY_NOTE_4b7d_私密更新说明'
const CANARY_PATH = 'canary/canary-file-9f3c2a.txt'
const MEMBER_ALICE = { id: 'member-aaaa0001', name: 'Alice' }
const MEMBER_BOB = { id: 'member-bbbb0002', name: 'Bob' }
const MEMBER_CAROL = { id: 'member-cccc0003', name: 'Carol' }
/** Any of these appearing in wire traffic / room JSON / logs is a confidentiality bug. */
const FORBIDDEN_PLAINTEXT = [PASSWORD, WRONG_PASSWORD, CANARY_CONTENT, CANARY_NOTE, CANARY_PATH]

const silentLogger = Object.freeze({ warn() {}, error() {}, info() {}, log() {}, debug() {} })

function makeLogger() {
  const records = []
  const push = (level) => (...args) => {
    records.push(`${level} ${args.map((value) => String(value)).join(' ')}`)
  }
  return { records, warn: push('warn'), error: push('error'), info: push('info'), log: push('log'), debug: push('debug') }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

async function makeTempDir(prefix = 'dsh-group-net-v2-') {
  return await fsp.mkdtemp(join(tmpdir(), prefix))
}

async function cleanupDir(dir) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      await fsp.rm(dir, { recursive: true, force: true })
      return
    } catch {
      await delay(50)
    }
  }
}

/** Start a server on ephemeral ports and clean it (plus its temp dir) up after the test. */
async function setup(t, options = {}) {
  const dataDir = await makeTempDir()
  const server = new RoomServer({
    dataDir,
    tcpPort: 0,
    udpPort: 0,
    enableDiscovery: false,
    logger: silentLogger,
    hostName: 'test-host',
    ...options,
  })
  const info = await server.listen()
  t.after(async () => {
    await server.close().catch(() => {})
    await cleanupDir(dataDir)
  })
  return { dataDir, server, info }
}

function track(t, client) {
  t.after(() => client.close())
  return client
}

function makeClient(origin, { room = ROOM, password = PASSWORD, member = MEMBER_ALICE, timeoutMs = 5000 } = {}) {
  return new RoomClient({ origin, room, password, member, timeoutMs })
}

function makeFiles(contentByPath) {
  return Object.entries(contentByPath).map(([path, content]) =>
    encodeFile(path, Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8')),
  )
}

function makeSnapshot({ files, note = '', rev = 1, by = MEMBER_ALICE, changes } = {}) {
  const snapshot = {
    rev,
    by,
    note,
    at: new Date().toISOString(),
    files: files ?? makeFiles({ 'a.txt': 'hello' }),
  }
  if (changes !== undefined) snapshot.changes = changes
  return snapshot
}

/** Raw HTTP helper that also exposes the exact request body string and headers. */
async function httpJson(url, { method = 'GET', body, rawBody } = {}) {
  const init = { method, headers: {} }
  let requestText = null
  if (rawBody !== undefined) {
    init.body = rawBody
    requestText = typeof rawBody === 'string' ? rawBody : rawBody.toString('utf8')
  } else if (body !== undefined) {
    requestText = JSON.stringify(body)
    init.headers['content-type'] = 'application/json'
    init.body = requestText
  }
  const response = await fetch(url, init)
  const text = await response.text()
  let json = null
  try {
    json = JSON.parse(text)
  } catch {
    json = null
  }
  return { status: response.status, text, json, requestText, headers: response.headers }
}

function assertNoPlaintext(text, label) {
  if (typeof text !== 'string' || text.length === 0) return
  for (const needle of FORBIDDEN_PLAINTEXT) {
    assert.equal(text.includes(needle), false, `${label} 泄露了明文标记: ${needle}`)
  }
}

async function expectCollab(promise, codes) {
  const expected = Array.isArray(codes) ? codes : [codes]
  try {
    await promise
  } catch (error) {
    assert.ok(error instanceof CollabError, `expected CollabError, got: ${error}`)
    assert.ok(expected.includes(error.code), `expected ${expected.join('/')}, got ${error.code}: ${error.message}`)
    return error
  }
  assert.fail(`expected CollabError ${expected.join('/')}, but the promise resolved`)
}

function expectThrowsCollab(fn, codes) {
  const expected = Array.isArray(codes) ? codes : [codes]
  try {
    fn()
  } catch (error) {
    assert.ok(error instanceof CollabError, `expected CollabError, got: ${error}`)
    assert.ok(expected.includes(error.code), `expected ${expected.join('/')}, got ${error.code}: ${error.message}`)
    return error
  }
  assert.fail(`expected CollabError ${expected.join('/')}, but nothing was thrown`)
}

async function challengeRequest(origin, room) {
  return await httpJson(`${origin}/group/v1/challenge`, {
    method: 'POST',
    body: { v: PROTOCOL_VERSION, room },
  })
}

/** Build a valid join body from a fresh challenge (proves password locally, never sends it). */
async function buildJoinBody({ origin, room = ROOM, password = PASSWORD, member = MEMBER_ALICE, challenge }) {
  const response = challenge ?? (await challengeRequest(origin, room))
  assert.equal(response.status, 200, `challenge failed: ${response.text}`)
  const authKey = deriveAuthKey(password, response.json.saltAuth)
  const proof = createProof(authKey, room, response.json.nonce, member.id)
  return { v: PROTOCOL_VERSION, room, member, nonce: response.json.nonce, proof }
}

async function joinRaw({ origin, room = ROOM, password = PASSWORD, member = MEMBER_ALICE }) {
  const body = await buildJoinBody({ origin, room, password, member })
  return await httpJson(`${origin}/group/v1/join`, { method: 'POST', body })
}

async function readRoomFile(dataDir, room = ROOM) {
  return await fsp.readFile(join(dataDir, 'rooms', `${room}.json`), 'utf8')
}

function flipFirstByte(buffer) {
  const copy = Buffer.from(buffer)
  copy[0] ^= 0xff
  return copy
}

/** Return a structurally valid but tampered copy of one ciphertext field. */
function tamperCipher(cipher, field) {
  const parts = normalizeCipher(cipher)
  parts[field] = flipFirstByte(parts[field])
  return encodeCipher(parts)
}

/** Send one UDP discovery datagram and resolve with the first room reply (or undefined). */
function rawDiscover(udpPort, payload, timeoutMs = 700) {
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
    timer.unref?.()
    socket.on('error', () => finish(undefined))
    socket.on('message', (message) => {
      try {
        const parsed = JSON.parse(message.toString('utf8'))
        if (parsed && parsed.t === 'dsh-group-room') finish(parsed)
      } catch {
        // Ignore malformed replies.
      }
    })
    try {
      socket.bind(0, () => {
        try {
          socket.send(Buffer.from(JSON.stringify(payload)), udpPort, '127.0.0.1', () => {})
        } catch {
          finish(undefined)
        }
      })
    } catch {
      finish(undefined)
    }
  })
}

/** Fake legacy v1 discovery responder (advertises fabricated rooms). */
async function startFakeV1Discovery() {
  const socket = createSocket('udp4')
  await new Promise((resolve, reject) => {
    socket.once('error', reject)
    socket.bind(0, '127.0.0.1', resolve)
  })
  socket.on('message', (message, rinfo) => {
    try {
      const parsed = JSON.parse(message.toString('utf8'))
      if (!parsed || parsed.t !== 'dsh-group-discover') return
      const reply = { t: 'dsh-group-room', v: 1, room: parsed.room, name: '伪造明文房间', url: 'http://127.0.0.1:1' }
      socket.send(Buffer.from(JSON.stringify(reply)), rinfo.port, rinfo.address, () => {})
    } catch {
      // Ignore.
    }
  })
  return {
    port: socket.address().port,
    close: () =>
      new Promise((resolve) => {
        try {
          socket.close(resolve)
        } catch {
          resolve()
        }
      }),
  }
}

function abruptDisconnect(origin) {
  const url = new URL(origin)
  return new Promise((resolve) => {
    let settled = false
    const done = () => {
      if (settled) return
      settled = true
      try {
        socket.destroy()
      } catch {
        // Already gone.
      }
      resolve()
    }
    const socket = net.connect(Number(url.port), url.hostname)
    socket.on('error', done)
    socket.on('connect', () => {
      socket.write(
        `POST /group/v1/join HTTP/1.1\r\nHost: ${url.host}\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{"a":`,
      )
      setTimeout(done, 30)
    })
  })
}

function sendGarbageHttp(origin) {
  const url = new URL(origin)
  return new Promise((resolve) => {
    let settled = false
    const done = () => {
      if (settled) return
      settled = true
      try {
        socket.destroy()
      } catch {
        // Already gone.
      }
      resolve()
    }
    const socket = net.connect(Number(url.port), url.hostname)
    socket.on('error', done)
    socket.on('close', done)
    socket.on('data', () => {})
    socket.on('connect', () => {
      socket.write('THIS IS NOT A VALID HTTP REQUEST\r\n\r\n')
      setTimeout(done, 200)
    })
  })
}

// ---------------------------------------------------------------------------
// 1. Happy path: challenge -> join -> publish -> latest -> status -> leave
// ---------------------------------------------------------------------------

test('v2 基本链路：挑战应答加入、加密发布、明文快照拉取、token 状态与离开', async (t) => {
  const { server } = await setup(t)
  const created = await server.createLocalRoom({ number: ROOM, password: PASSWORD, name: '加密房间' })
  assert.equal(created.number, ROOM)
  assert.equal(created.rev, 0)
  assert.equal(created.origin, server.origin)
  assert.equal(server.hasRoom(ROOM), true)

  const alice = track(t, makeClient(server.origin, { member: MEMBER_ALICE }))
  const aliceJoin = await alice.join()
  assert.match(aliceJoin.token, /^[0-9a-f]{64}$/u)
  assert.equal(aliceJoin.room.number, ROOM)
  assert.equal(aliceJoin.room.name, '加密房间')
  assert.equal(aliceJoin.room.rev, 0)
  assert.equal(aliceJoin.snapshot, null)
  assert.equal(aliceJoin.syncRequested, false)
  assert.equal(aliceJoin.members.length, 1)
  assert.equal(aliceJoin.members[0].name, 'Alice')
  assert.equal(aliceJoin.members[0].online, true)
  assert.equal(aliceJoin.server.hostName, 'test-host')

  // Publish a canary snapshot (plaintext API, ciphertext on the wire).
  const files1 = makeFiles({ [CANARY_PATH]: CANARY_CONTENT, 'docs/readme.txt': '# hello' })
  const published = await alice.publish({
    baseRev: 0,
    snapshot: makeSnapshot({ files: files1, note: CANARY_NOTE }),
    note: CANARY_NOTE,
  })
  assert.deepEqual(published, { rev: 1 })
  const aliceBeat = await alice.heartbeat()
  assert.equal(aliceBeat.rev, 1)
  assert.equal(aliceBeat.syncRequested, false)

  // A second member receives the DECRYPTED snapshot on join.
  const bob = track(t, makeClient(server.origin, { member: MEMBER_BOB }))
  const bobJoin = await bob.join()
  assert.equal(bobJoin.room.rev, 1)
  assert.equal(bobJoin.syncRequested, true)
  assert.ok(bobJoin.snapshot !== null)
  assert.equal(bobJoin.snapshot.rev, 1)
  assert.equal(bobJoin.snapshot.note, CANARY_NOTE)
  assert.equal(bobJoin.members.length, 2)
  const decoded = decodeFile(bobJoin.snapshot.files.find((file) => file.path === CANARY_PATH))
  assert.equal(decoded.bytes.toString('utf8'), CANARY_CONTENT)

  const bobBeat = await bob.heartbeat()
  assert.equal(bobBeat.syncRequested, false)

  // latest: omitted when the caller is current, decrypted otherwise.
  const sameRev = await bob.latest(1)
  assert.equal(sameRev.rev, 1)
  assert.equal('snapshot' in sameRev, false)
  const pulled = await alice.latest(0)
  assert.equal(pulled.rev, 1)
  assert.equal(pulled.lastUpdate.rev, 1)
  assert.equal(pulled.lastUpdate.note, CANARY_NOTE)
  assert.equal(decodeFile(pulled.snapshot.files.find((file) => file.path === CANARY_PATH)).bytes.toString('utf8'), CANARY_CONTENT)

  // A second publish is decrypted by the other member with computed changes.
  const published2 = await bob.publish({
    baseRev: 1,
    snapshot: makeSnapshot({ files: makeFiles({ 'docs/readme.txt': '# hello v2' }) }),
    note: 'bob update',
  })
  assert.equal(published2.rev, 2)
  const aliceLatest = await alice.latest(1)
  assert.equal(aliceLatest.rev, 2)
  assert.equal(aliceLatest.snapshot.files.length, 1)
  assert.deepEqual(aliceLatest.snapshot.changes, {
    added: [],
    modified: ['docs/readme.txt'],
    deleted: [CANARY_PATH],
  })

  // Status is token-authenticated and contains no content/digest.
  const status = await alice.status()
  assert.equal(status.ok, true)
  assert.equal(status.room.number, ROOM)
  assert.equal(status.rev, 2)
  assert.equal(status.members.length, 2)
  assert.equal('snapshotDigest' in status, false)
  assert.equal('snapshot' in status, false)

  await bob.leave()
  const roster = await alice.heartbeat()
  assert.equal(roster.members.length, 1)
  assert.equal(roster.members[0].name, 'Alice')
})

// ---------------------------------------------------------------------------
// 2. Canary: no plaintext on the wire, in room JSON, or in logs
// ---------------------------------------------------------------------------

test('线上与磁盘无明文（金丝雀）：请求/响应/房间 JSON/日志均不含密码、内容、说明、路径', async (t) => {
  const logger = makeLogger()
  const { dataDir, server } = await setup(t, { logger })
  await server.createLocalRoom({ number: ROOM, password: PASSWORD, name: '金丝雀房间' })

  // Challenge: request contains only the room number, response only random material.
  const challengeResponse = await challengeRequest(server.origin, ROOM)
  assert.equal(challengeResponse.status, 200)
  assertNoPlaintext(challengeResponse.requestText, 'challenge 请求体')
  assertNoPlaintext(challengeResponse.text, 'challenge 响应')
  const challenge = challengeResponse.json
  const authKey = deriveAuthKey(PASSWORD, challenge.saltAuth)
  const contentKey = deriveContentKey(PASSWORD, challenge.saltContent)
  const proof = createProof(authKey, ROOM, challenge.nonce, MEMBER_ALICE.id)

  logger.records.length = 0
  const joinBody = { v: PROTOCOL_VERSION, room: ROOM, member: MEMBER_ALICE, nonce: challenge.nonce, proof }
  const joinResponse = await httpJson(`${server.origin}/group/v1/join`, { method: 'POST', body: joinBody })
  assert.equal(joinResponse.status, 200, joinResponse.text)
  assertNoPlaintext(joinResponse.requestText, 'join 请求体')
  assertNoPlaintext(joinResponse.text, 'join 响应')
  const token = joinResponse.json.token

  // Publish a ciphertext built exactly like RoomClient does.
  const plaintextPayload = {
    by: MEMBER_ALICE,
    note: CANARY_NOTE,
    at: new Date().toISOString(),
    files: makeFiles({ [CANARY_PATH]: CANARY_CONTENT }),
    changes: { added: [CANARY_PATH], modified: [], deleted: [] },
  }
  const cipher = encryptSnapshot(contentKey, ROOM, 1, plaintextPayload)
  const publishResponse = await httpJson(`${server.origin}/group/v1/publish`, {
    method: 'POST',
    body: { v: PROTOCOL_VERSION, token, member: MEMBER_ALICE, baseRev: 0, cipher },
  })
  assert.equal(publishResponse.status, 200, publishResponse.text)
  assert.deepEqual(publishResponse.json, { ok: true, rev: 1 })
  assertNoPlaintext(publishResponse.requestText, 'publish 请求体')
  assertNoPlaintext(publishResponse.text, 'publish 响应')

  // latest returns ciphertext only.
  const latestResponse = await httpJson(`${server.origin}/group/v1/latest?token=${token}&rev=0`)
  assert.equal(latestResponse.status, 200)
  assertNoPlaintext(latestResponse.text, 'latest 响应')
  assert.equal(latestResponse.json.snapshot.rev, 1)
  assert.equal(latestResponse.json.snapshot.cipher.v, PROTOCOL_VERSION)
  assert.ok(latestResponse.json.snapshot.cipher.iv.length > 0)
  assert.ok(latestResponse.json.snapshot.cipher.tag.length > 0)
  assert.ok(latestResponse.json.snapshot.cipher.data.length > 0)

  // Room JSON on disk: verifier + salts + ciphertext only, no plaintext at all.
  const roomText = await readRoomFile(dataDir)
  assertNoPlaintext(roomText, '房间 JSON')
  assert.ok(roomText.includes('"version":2'))
  assert.ok(roomText.includes('"authKey"'))
  assert.ok(roomText.includes('"saltAuth"'))
  assert.ok(roomText.includes('"saltContent"'))
  assert.ok(roomText.includes('"cipher"'))
  assert.equal(roomText.includes('"passwordHash"'), false)
  assert.equal(roomText.includes('"password"'), false)
  assert.equal(roomText.includes('canary'), false)

  await delay(30)
  for (const line of logger.records) assertNoPlaintext(line, '服务器日志')
})

// ---------------------------------------------------------------------------
// 3. Password policy (min 8, no wire transmission)
// ---------------------------------------------------------------------------

test('密码策略：少于 8 位被客户端与服务端拒绝，协议版本为 2', async (t) => {
  assert.equal(PROTOCOL_VERSION, 2)
  assert.throws(
    () => validatePassword('1234567'),
    (error) => error instanceof CollabError && error.code === 'BAD_PASSWORD',
  )
  assert.equal(validatePassword('12345678'), '12345678')

  const { server } = await setup(t)
  await expectCollab(server.createLocalRoom({ number: ROOM, password: '1234567' }), 'BAD_PASSWORD')

  // Client validates locally before any request is made (no password on the wire).
  const shortPasswordClient = track(t, makeClient(server.origin, { password: '1234567' }))
  await expectCollab(shortPasswordClient.join(), 'BAD_PASSWORD')
})

// ---------------------------------------------------------------------------
// 4. Authentication on every state-changing/reading endpoint
// ---------------------------------------------------------------------------

test('鉴权：latest/heartbeat/publish/status/leave 无 token 均 401，status 不接受 room 参数', async (t) => {
  const { server } = await setup(t)
  await server.createLocalRoom({ number: ROOM, password: PASSWORD })
  const alice = track(t, makeClient(server.origin))
  const aliceJoin = await alice.join()

  const unauthorized = [
    await httpJson(`${server.origin}/group/v1/latest`),
    await httpJson(`${server.origin}/group/v1/latest?rev=0`),
    await httpJson(`${server.origin}/group/v1/status`),
    await httpJson(`${server.origin}/group/v1/status?room=${ROOM}`),
    await httpJson(`${server.origin}/group/v1/status?token=${'0'.repeat(64)}`),
    await httpJson(`${server.origin}/group/v1/heartbeat`, { method: 'POST', body: {} }),
    await httpJson(`${server.origin}/group/v1/publish`, { method: 'POST', body: { v: PROTOCOL_VERSION, baseRev: 0 } }),
    await httpJson(`${server.origin}/group/v1/leave`, { method: 'POST', body: {} }),
  ]
  for (const response of unauthorized) {
    assert.equal(response.status, 401, `expected 401, got ${response.status}: ${response.text}`)
    assert.equal(response.json.error.code, 'UNAUTHORIZED')
    // No room information may leak to unauthenticated callers.
    assert.equal('room' in response.json, false)
    assert.equal('members' in response.json, false)
  }

  // A valid token works.
  const latest = await httpJson(`${server.origin}/group/v1/latest?token=${aliceJoin.token}&rev=0`)
  assert.equal(latest.status, 200)
  const status = await httpJson(`${server.origin}/group/v1/status?token=${aliceJoin.token}`)
  assert.equal(status.status, 200)
  assert.equal(status.json.room.number, ROOM)
  assert.equal(status.json.members.length, 1)

  // Re-join replaces the old session token.
  const rejoined = await alice.join()
  assert.notEqual(rejoined.token, aliceJoin.token)
  const stale = await httpJson(`${server.origin}/group/v1/latest?token=${aliceJoin.token}&rev=0`)
  assert.equal(stale.status, 401)
})

// ---------------------------------------------------------------------------
// 5. Nonce replay / expiry / missing proof — unified 401
// ---------------------------------------------------------------------------

test('nonce 安全：重放、过期、缺失 proof 统一 401，响应不可区分', async (t) => {
  const { server } = await setup(t, { challengeTtlMs: 80 })
  await server.createLocalRoom({ number: ROOM, password: PASSWORD })
  const challenge = (await challengeRequest(server.origin, ROOM)).json
  const body = {
    v: PROTOCOL_VERSION,
    room: ROOM,
    member: MEMBER_ALICE,
    nonce: challenge.nonce,
    proof: createProof(deriveAuthKey(PASSWORD, challenge.saltAuth), ROOM, challenge.nonce, MEMBER_ALICE.id),
  }
  const success = await httpJson(`${server.origin}/group/v1/join`, { method: 'POST', body })
  assert.equal(success.status, 200, success.text)

  // Same nonce + proof again: replay must fail (single-use nonce).
  const replay = await httpJson(`${server.origin}/group/v1/join`, { method: 'POST', body })
  // Expired nonce.
  const expiredChallenge = (await challengeRequest(server.origin, ROOM)).json
  await delay(150)
  const expired = await httpJson(`${server.origin}/group/v1/join`, {
    method: 'POST',
    body: {
      v: PROTOCOL_VERSION,
      room: ROOM,
      member: MEMBER_ALICE,
      nonce: expiredChallenge.nonce,
      proof: createProof(
        deriveAuthKey(PASSWORD, expiredChallenge.saltAuth),
        ROOM,
        expiredChallenge.nonce,
        MEMBER_ALICE.id,
      ),
    },
  })
  // Missing proof / missing nonce with a valid challenge.
  const noProofChallenge = (await challengeRequest(server.origin, ROOM)).json
  const noProof = await httpJson(`${server.origin}/group/v1/join`, {
    method: 'POST',
    body: { v: PROTOCOL_VERSION, room: ROOM, member: MEMBER_ALICE, nonce: noProofChallenge.nonce },
  })
  const noNonce = await httpJson(`${server.origin}/group/v1/join`, {
    method: 'POST',
    body: { v: PROTOCOL_VERSION, room: ROOM, member: MEMBER_ALICE },
  })

  const failures = [replay, expired, noProof, noNonce]
  for (const response of failures) {
    assert.equal(response.status, 401, response.text)
    assert.equal(response.json.error.code, 'UNAUTHORIZED')
    assert.deepEqual(response.json, failures[0].json, '所有认证失败响应必须完全一致')
  }
})

// ---------------------------------------------------------------------------
// 6. Unknown room indistinguishable from wrong password
// ---------------------------------------------------------------------------

test('反枚举：未知房间 challenge 与真实房间不可区分，join 失败响应一致', async (t) => {
  const { server } = await setup(t)
  await server.createLocalRoom({ number: ROOM, password: PASSWORD })

  const known = (await challengeRequest(server.origin, ROOM)).json
  const unknown1 = (await challengeRequest(server.origin, UNKNOWN_ROOM)).json
  const unknown2 = (await challengeRequest(server.origin, UNKNOWN_ROOM)).json
  assert.deepEqual(Object.keys(known).sort(), Object.keys(unknown1).sort())
  assert.equal(known.ok, true)
  assert.equal(unknown1.ok, true)
  assert.equal(known.v, PROTOCOL_VERSION)
  assert.equal(unknown1.v, PROTOCOL_VERSION)
  assert.equal(unknown1.room, UNKNOWN_ROOM)
  for (const value of [known.saltAuth, known.saltContent, unknown1.saltAuth, unknown1.saltContent]) {
    assert.match(value, /^[0-9a-f]{32}$/u)
    assert.ok(value !== PASSWORD)
  }
  // Salts of a real room are stable (fixed per room). Unknown rooms must look the same:
  // stable, random-looking salts — otherwise repeated probes enumerate rooms.
  assert.equal(unknown1.saltAuth, unknown2.saltAuth)
  assert.equal(unknown1.saltContent, unknown2.saltContent)

  const wrongPassword = await joinRaw({ origin: server.origin, room: ROOM, password: WRONG_PASSWORD })
  const unknownRoom = await joinRaw({ origin: server.origin, room: UNKNOWN_ROOM, password: PASSWORD })
  assert.equal(wrongPassword.status, 401)
  assert.equal(unknownRoom.status, 401)
  assert.deepEqual(wrongPassword.json, unknownRoom.json, '未知房间与错误密码的 join 响应必须一致')
})

// ---------------------------------------------------------------------------
// 7. Rate limiting: challenges 30/min; join lockout after 5 failures
// ---------------------------------------------------------------------------

test('限流：challenge 超过 30 次/分钟返回 429；连续 5 次加入失败后锁定返回 429', async (t) => {
  // (a) challenge rate limit
  const rateLimited = await setup(t)
  await rateLimited.server.createLocalRoom({ number: ROOM, password: PASSWORD })
  const responses = []
  for (let index = 0; index < 30; index += 1) {
    responses.push(await challengeRequest(rateLimited.server.origin, ROOM))
  }
  for (const response of responses) assert.equal(response.status, 200, response.text)
  const blocked = await challengeRequest(rateLimited.server.origin, ROOM)
  assert.equal(blocked.status, 429)
  assert.equal(blocked.json.error.code, 'TOO_MANY_REQUESTS')
  const retryAfter = blocked.json.error.details.retryAfterSeconds
  assert.ok(Number.isInteger(retryAfter) && retryAfter > 0 && retryAfter <= 60, `retryAfter=${retryAfter}`)
  assert.equal(blocked.headers.get('retry-after'), String(retryAfter))

  // (b) join failure lockout (separate server: per-IP state must be isolated)
  const lockout = await setup(t)
  await lockout.server.createLocalRoom({ number: ROOM, password: PASSWORD })
  const failureResponses = []
  for (let index = 0; index < 5; index += 1) {
    failureResponses.push(await joinRaw({ origin: lockout.server.origin, password: WRONG_PASSWORD }))
  }
  for (const response of failureResponses) {
    assert.equal(response.status, 401, `失败 ${failureResponses.indexOf(response) + 1}: ${response.text}`)
    assert.equal(response.json.error.code, 'UNAUTHORIZED')
  }
  // Even the correct password is locked out after the threshold.
  const locked = await joinRaw({ origin: lockout.server.origin, password: PASSWORD })
  assert.equal(locked.status, 429)
  assert.equal(locked.json.error.code, 'TOO_MANY_REQUESTS')
  assert.ok(Number.isInteger(locked.json.error.details.retryAfterSeconds))
})

// ---------------------------------------------------------------------------
// 8. Successful join clears the failure counter
// ---------------------------------------------------------------------------

test('限流：成功加入后失败计数清零（之后 4 次失败不会触发锁定）', async (t) => {
  const { server } = await setup(t)
  await server.createLocalRoom({ number: ROOM, password: PASSWORD })

  for (let index = 0; index < 3; index += 1) {
    const response = await joinRaw({ origin: server.origin, password: WRONG_PASSWORD })
    assert.equal(response.status, 401)
  }
  // Successful join clears the counter.
  const alice = track(t, makeClient(server.origin, { member: MEMBER_ALICE }))
  const aliceJoin = await alice.join()
  assert.ok(aliceJoin.token.length > 0)

  // Four more failures stay below the threshold (count was reset).
  for (let index = 0; index < 4; index += 1) {
    const response = await joinRaw({ origin: server.origin, password: WRONG_PASSWORD })
    assert.equal(response.status, 401, `第 ${index + 1} 次失败应为 401 而不是锁定: ${response.text}`)
  }

  // Another correct join still succeeds (not locked at 4 failures).
  const bob = track(t, makeClient(server.origin, { member: MEMBER_BOB }))
  const bobJoin = await bob.join()
  assert.ok(bobJoin.token.length > 0)
})

// ---------------------------------------------------------------------------
// 9. Cipher roundtrip + tamper / AAD / key separation (unit level)
// ---------------------------------------------------------------------------

test('密文完整性与 AAD（单元）：合法往返，篡改 iv/tag/data 或错误 room/rev/key 一律拒绝', async () => {
  const contentKey = deriveContentKey(PASSWORD, randomSalt())
  const payload = {
    by: MEMBER_ALICE,
    note: CANARY_NOTE,
    at: new Date().toISOString(),
    files: makeFiles({ [CANARY_PATH]: CANARY_CONTENT }),
    changes: { added: [CANARY_PATH], modified: [], deleted: [] },
  }
  const cipher = encryptSnapshot(contentKey, ROOM, 3, payload)
  assert.equal(cipher.v, 2)
  const parts = normalizeCipher(cipher)
  assert.equal(parts.iv.length, 12)
  assert.equal(parts.tag.length, 16)
  assert.deepEqual(decryptSnapshot(contentKey, ROOM, 3, cipher), payload)

  expectThrowsCollab(() => decryptSnapshot(contentKey, ROOM, 3, tamperCipher(cipher, 'iv')), 'PROTOCOL')
  expectThrowsCollab(() => decryptSnapshot(contentKey, ROOM, 3, tamperCipher(cipher, 'tag')), 'PROTOCOL')
  expectThrowsCollab(() => decryptSnapshot(contentKey, ROOM, 3, tamperCipher(cipher, 'data')), 'PROTOCOL')
  // AAD binds room + revision.
  expectThrowsCollab(() => decryptSnapshot(contentKey, '654321', 3, cipher), 'PROTOCOL')
  expectThrowsCollab(() => decryptSnapshot(contentKey, ROOM, 4, cipher), 'PROTOCOL')
  // Key separation: authKey must not decrypt content.
  const wrongKey = deriveContentKey(WRONG_PASSWORD, randomSalt())
  expectThrowsCollab(() => decryptSnapshot(wrongKey, ROOM, 3, cipher), 'PROTOCOL')
  // Envelope shape / size validation.
  expectThrowsCollab(() => normalizeCipher({ v: 2, iv: 'AAAA', tag: 'AAAA', data: 'AAAA' }), 'BAD_SNAPSHOT')
  expectThrowsCollab(() => normalizeCipher({ ...cipher, v: 1 }), 'VERSION')
  expectThrowsCollab(() => normalizeCipher(cipher, { maxBytes: 16 }), 'TOO_LARGE')
  expectThrowsCollab(() => encryptSnapshot(contentKey, ROOM, 0, payload), 'BAD_REQUEST')
})

// ---------------------------------------------------------------------------
// 10. Server-side ciphertext tampering / revision rollback is rejected client-side
// ---------------------------------------------------------------------------

test('服务端密文被篡改或 rev 被改：客户端解密失败并拒绝（PROTOCOL），不返回明文', async (t) => {
  const dataDir = await makeTempDir()
  const servers = []
  const clients = []
  t.after(async () => {
    for (const client of clients) client.close()
    for (const server of servers) await server.close().catch(() => {})
    await cleanupDir(dataDir)
  })
  const start = async () => {
    const server = new RoomServer({
      dataDir,
      tcpPort: 0,
      udpPort: 0,
      enableDiscovery: false,
      logger: silentLogger,
    })
    servers.push(server)
    await server.listen()
    return server
  }
  const roomFile = join(dataDir, 'rooms', `${ROOM}.json`)

  const first = await start()
  await first.createLocalRoom({ number: ROOM, password: PASSWORD })
  const alice = makeClient(first.origin)
  clients.push(alice)
  await alice.join()
  await alice.publish({
    baseRev: 0,
    snapshot: makeSnapshot({ files: makeFiles({ [CANARY_PATH]: CANARY_CONTENT }), note: CANARY_NOTE }),
    note: CANARY_NOTE,
  })
  alice.close()
  await first.close()
  const originalText = await fsp.readFile(roomFile, 'utf8')

  // Tamper with the ciphertext payload: structurally valid, authentication invalid.
  const tamperedData = JSON.parse(originalText)
  tamperedData.snapshot.cipher = tamperCipher(tamperedData.snapshot.cipher, 'data')
  await fsp.writeFile(roomFile, JSON.stringify(tamperedData), 'utf8')
  const second = await start()
  const bob = makeClient(second.origin, { member: MEMBER_BOB })
  clients.push(bob)
  const tamperError = await expectCollab(bob.join(), ['PROTOCOL', 'BAD_SNAPSHOT'])
  assert.equal(tamperError.code, 'PROTOCOL')
  bob.close()
  await second.close()

  // Revision rollback: re-label the ciphertext as rev 2 -> AAD no longer matches.
  const replayedRev = JSON.parse(originalText)
  replayedRev.rev = 2
  replayedRev.snapshot.rev = 2
  await fsp.writeFile(roomFile, JSON.stringify(replayedRev), 'utf8')
  const third = await start()
  const carol = makeClient(third.origin, { member: MEMBER_CAROL })
  clients.push(carol)
  const replayError = await expectCollab(carol.join(), ['PROTOCOL', 'BAD_SNAPSHOT'])
  assert.equal(replayError.code, 'PROTOCOL')
})

// ---------------------------------------------------------------------------
// 11. Conflict: 409 carries decryptable latest ciphertext; concurrent publish
// ---------------------------------------------------------------------------

test('冲突：409 附带的最新密文可解密为明文 details；并发发布只有一个成功', async (t) => {
  const { server } = await setup(t)
  await server.createLocalRoom({ number: ROOM, password: PASSWORD })
  const alice = track(t, makeClient(server.origin, { member: MEMBER_ALICE }))
  const bob = track(t, makeClient(server.origin, { member: MEMBER_BOB }))
  await alice.join()
  await bob.join()

  const firstPublish = await alice.publish({
    baseRev: 0,
    snapshot: makeSnapshot({ files: makeFiles({ [CANARY_PATH]: CANARY_CONTENT }), note: CANARY_NOTE }),
    note: CANARY_NOTE,
  })
  assert.equal(firstPublish.rev, 1)

  const conflict = await expectCollab(
    bob.publish({ baseRev: 0, snapshot: makeSnapshot({ files: makeFiles({ 'stale.txt': 'stale' }) }), note: 'stale' }),
    'CONFLICT',
  )
  assert.equal(conflict.details.rev, 1)
  assert.equal(conflict.details.lastUpdate.rev, 1)
  assert.equal(conflict.details.lastUpdate.note, CANARY_NOTE)
  assert.ok(conflict.details.snapshot !== null && conflict.details.snapshot !== undefined)
  assert.equal(conflict.details.snapshot.rev, 1)
  assert.equal(conflict.details.snapshot.note, CANARY_NOTE)
  assert.equal(
    decodeFile(conflict.details.snapshot.files.find((file) => file.path === CANARY_PATH)).bytes.toString('utf8'),
    CANARY_CONTENT,
  )

  // Retry on top of the synced revision succeeds.
  const retry = await bob.publish({ baseRev: 1, snapshot: makeSnapshot({ files: makeFiles({ 'retry.txt': 'ok' }) }), note: 'retry' })
  assert.equal(retry.rev, 2)

  // Concurrent publishes at the same revision: exactly one wins.
  const results = await Promise.allSettled([
    alice.publish({ baseRev: 2, snapshot: makeSnapshot({ files: makeFiles({ 'a.txt': 'a' }) }), note: 'a' }),
    bob.publish({ baseRev: 2, snapshot: makeSnapshot({ files: makeFiles({ 'b.txt': 'b' }) }), note: 'b' }),
  ])
  const fulfilled = results.filter((result) => result.status === 'fulfilled')
  const rejected = results.filter((result) => result.status === 'rejected')
  assert.equal(fulfilled.length, 1)
  assert.equal(rejected.length, 1)
  assert.deepEqual(fulfilled[0].value, { rev: 3 })
  assert.equal(rejected[0].reason.code, 'CONFLICT')
  assert.equal(rejected[0].reason.details.rev, 3)
  assert.equal(rejected[0].reason.details.snapshot.rev, 3)
})

// ---------------------------------------------------------------------------
// 12. Persistence across restart (ciphertext only on disk)
// ---------------------------------------------------------------------------

test('持久化：房间 JSON 只有盐/verifier/密文，重启后可加入、解密并继续发布', async (t) => {
  const dataDir = await makeTempDir()
  const servers = []
  const clients = []
  t.after(async () => {
    for (const client of clients) client.close()
    for (const server of servers) await server.close().catch(() => {})
    await cleanupDir(dataDir)
  })
  const start = async () => {
    const server = new RoomServer({
      dataDir,
      tcpPort: 0,
      udpPort: 0,
      enableDiscovery: false,
      logger: silentLogger,
    })
    servers.push(server)
    await server.listen()
    return server
  }

  const first = await start()
  await first.createLocalRoom({ number: ROOM, password: PASSWORD, name: '持久加密房间' })
  const alice = makeClient(first.origin)
  clients.push(alice)
  await alice.join()
  const published = await alice.publish({
    baseRev: 0,
    snapshot: makeSnapshot({ files: makeFiles({ [CANARY_PATH]: CANARY_CONTENT }), note: CANARY_NOTE }),
    note: CANARY_NOTE,
  })
  assert.equal(published.rev, 1)
  alice.close()
  await first.close()

  const roomText = await readRoomFile(dataDir)
  assertNoPlaintext(roomText, '重启前的房间 JSON')
  assert.ok(roomText.includes('"version":2'))
  assert.ok(roomText.includes('"authKey"'))
  assert.equal(roomText.includes('"passwordHash"'), false)

  const second = await start()
  assert.equal(second.hasRoom(ROOM), true)
  assert.equal(second.getLocalRoom(ROOM).rev, 1)
  assert.equal(second.getLocalRoom(ROOM).name, '持久加密房间')

  const bob = makeClient(second.origin, { member: MEMBER_BOB })
  clients.push(bob)
  const bobJoin = await bob.join()
  assert.equal(bobJoin.room.rev, 1)
  assert.equal(decodeFile(bobJoin.snapshot.files.find((file) => file.path === CANARY_PATH)).bytes.toString('utf8'), CANARY_CONTENT)

  const published2 = await bob.publish({
    baseRev: 1,
    snapshot: makeSnapshot({ files: makeFiles({ 'next.txt': 'v2' }) }),
    note: 'after restart',
  })
  assert.equal(published2.rev, 2)
  assert.equal(second.listRooms()[0].rev, 2)
})

// ---------------------------------------------------------------------------
// 13. Legacy v1 room files are renamed and ignored; room can be recreated
// ---------------------------------------------------------------------------

test('旧 v1 房间文件：改名为 .legacy-v1 并忽略，可重建同名 v2 房间', async (t) => {
  const dataDir = await makeTempDir()
  t.after(() => cleanupDir(dataDir))
  const roomsDir = join(dataDir, 'rooms')
  await fsp.mkdir(roomsDir, { recursive: true })
  const legacyText = JSON.stringify({
    number: ROOM,
    name: '旧版明文房间',
    rev: 1,
    snapshot: null,
    salt: 'a'.repeat(32),
    passwordHash: 'b'.repeat(64),
    createdAt: new Date().toISOString(),
    lastUpdate: null,
  })
  const legacyPath = join(roomsDir, `${ROOM}.json`)
  await fsp.writeFile(legacyPath, legacyText, 'utf8')

  const server = new RoomServer({ dataDir, tcpPort: 0, udpPort: 0, enableDiscovery: false, logger: silentLogger })
  t.after(() => server.close().catch(() => {}))
  await server.listen()

  assert.equal(server.hasRoom(ROOM), false, 'v1 房间不得作为 v2 房间加载')
  const entries = await fsp.readdir(roomsDir)
  assert.equal(entries.includes(`${ROOM}.json`), false)
  assert.ok(entries.includes(`${ROOM}.json.legacy-v1`), `expected legacy rename, saw: ${entries.join(', ')}`)
  assert.equal(await fsp.readFile(`${legacyPath}.legacy-v1`, 'utf8'), legacyText, '旧文件内容应保留而非删除')

  // The number can be recreated as a fresh v2 room.
  const created = await server.createLocalRoom({ number: ROOM, password: PASSWORD, name: '重建加密房间' })
  assert.equal(created.rev, 0)
  assert.equal(server.hasRoom(ROOM), true)
  const newText = await readRoomFile(dataDir)
  assert.ok(newText.includes('"version":2'))
  assert.equal(newText.includes('"passwordHash"'), false)

  const alice = makeClient(server.origin)
  t.after(() => alice.close())
  const joined = await alice.join()
  assert.equal(joined.room.name, '重建加密房间')
})

// ---------------------------------------------------------------------------
// 14. UDP discovery v2: no room name, v1 replies rejected
// ---------------------------------------------------------------------------

test('UDP 发现 v2：应答不含房间名，客户端忽略 v1 应答', async (t) => {
  const { server, info } = await setup(t, { enableDiscovery: true, udpPort: 0 })
  assert.ok(Number.isInteger(info.udpPort) && info.udpPort > 0)
  await server.createLocalRoom({ number: ROOM, password: PASSWORD, name: '绝密房间名' })

  const found = await discoverRoom({
    room: ROOM,
    udpPort: info.udpPort,
    timeoutMs: 2000,
    broadcastAddresses: ['127.0.0.1'],
  })
  assert.ok(found !== undefined, 'discoverRoom 应找到本机房间')
  assert.equal(found.origin, server.origin)
  assert.equal(found.room, ROOM)
  assert.equal(found.via, 'discovery')
  assert.equal('name' in found, false, 'discoverRoom 不得返回房间名')

  // Raw reply shape: exactly {t,v,room,url} — never the room name.
  const reply = await rawDiscover(info.udpPort, { t: 'dsh-group-discover', v: PROTOCOL_VERSION, room: ROOM })
  assert.ok(reply !== undefined)
  assert.deepEqual(Object.keys(reply).sort(), ['room', 't', 'url', 'v'])
  assert.equal(reply.v, PROTOCOL_VERSION)
  assert.equal(reply.room, ROOM)
  assert.equal(reply.url, server.origin)
  assert.equal(JSON.stringify(reply).includes('绝密房间名'), false)

  // Unknown rooms are not advertised.
  const unknownReply = await rawDiscover(
    info.udpPort,
    { t: 'dsh-group-discover', v: PROTOCOL_VERSION, room: UNKNOWN_ROOM },
    400,
  )
  assert.equal(unknownReply, undefined)

  // A fake v1 discovery responder must be ignored by discoverRoom.
  const fake = await startFakeV1Discovery()
  t.after(() => fake.close())
  const legacyFound = await discoverRoom({
    room: ROOM,
    udpPort: fake.port,
    timeoutMs: 400,
    broadcastAddresses: ['127.0.0.1'],
  })
  assert.equal(legacyFound, undefined, '客户端必须拒绝 v1 发现应答')
})

// ---------------------------------------------------------------------------
// 15. resolveAdvertisedUrl (LAN-address regression guard)
// ---------------------------------------------------------------------------

test('resolveAdvertisedUrl：loopback -> 127.0.0.1，非 loopback -> 服务器 IPv4，advertiseHost 覆盖，无 LAN 回退', () => {
  const fakeInterfaces = {
    lo: [
      { address: '127.0.0.1', family: 'IPv4', internal: true, netmask: '255.0.0.0' },
      { address: '::1', family: 'IPv6', internal: true, netmask: 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' },
    ],
    wifi0: [{ address: '192.168.50.20', family: 'IPv4', internal: false, netmask: '255.255.255.0' }],
    docker0: [{ address: '172.17.0.1', family: 'IPv4', internal: false, netmask: '255.255.0.0' }],
  }
  const port = 45890
  for (const peerAddress of ['127.0.0.1', '127.9.8.7', '::1', '::ffff:127.0.0.1', 'localhost']) {
    assert.equal(
      resolveAdvertisedUrl({ peerAddress, tcpPort: port, interfaces: fakeInterfaces }),
      `http://127.0.0.1:${port}`,
    )
  }
  assert.equal(
    resolveAdvertisedUrl({ peerAddress: '192.168.50.77', tcpPort: port, interfaces: fakeInterfaces }),
    `http://192.168.50.20:${port}`,
  )
  assert.equal(
    resolveAdvertisedUrl({ peerAddress: '172.17.5.6', tcpPort: port, interfaces: fakeInterfaces }),
    `http://172.17.0.1:${port}`,
  )
  assert.equal(
    resolveAdvertisedUrl({ peerAddress: '8.8.8.8', tcpPort: port, interfaces: fakeInterfaces }),
    `http://192.168.50.20:${port}`,
  )
  assert.equal(
    resolveAdvertisedUrl({ peerAddress: '10.1.2.3', tcpPort: port, interfaces: { lo: [{ address: '127.0.0.1', family: 'IPv4', internal: true }] } }),
    `http://127.0.0.1:${port}`,
  )
  assert.equal(
    resolveAdvertisedUrl({ peerAddress: '10.1.2.3', tcpPort: port, advertiseHost: 'fileserver.local', interfaces: fakeInterfaces }),
    `http://fileserver.local:${port}`,
  )
  // Real interfaces: advertise one of this host's LAN IPv4s (or 127.0.0.1 when none).
  const realLan = []
  for (const entries of Object.values(networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (entry && entry.internal !== true && (entry.family === 'IPv4' || entry.family === 4) && typeof entry.address === 'string') {
        realLan.push(entry.address)
      }
    }
  }
  const realHost = new URL(resolveAdvertisedUrl({ peerAddress: '8.8.8.8', tcpPort: port })).hostname
  if (realLan.length === 0) assert.equal(realHost, '127.0.0.1')
  else assert.ok(realLan.includes(realHost))
  expectThrowsCollab(() => resolveAdvertisedUrl({ peerAddress: '10.0.0.1', tcpPort: 0 }), 'BAD_REQUEST')
  expectThrowsCollab(() => resolveAdvertisedUrl({ peerAddress: '10.0.0.1', tcpPort: 1, advertiseHost: 'http://' }), 'BAD_REQUEST')
})

// ---------------------------------------------------------------------------
// 16. Clean close: idempotent, port released, offline afterwards
// ---------------------------------------------------------------------------

test('close：幂等、释放监听端口、关闭后请求 OFFLINE、未监听也能关闭', async (t) => {
  const dataDir = await makeTempDir()
  t.after(() => cleanupDir(dataDir))
  const server = new RoomServer({ dataDir, tcpPort: 0, enableDiscovery: false, logger: silentLogger })
  const info = await server.listen()
  await server.createLocalRoom({ number: ROOM, password: PASSWORD })
  const alice = makeClient(info.origin)
  await alice.join()
  assert.equal(server.origin, info.origin)

  await server.close()
  assert.equal(server.origin, undefined)
  await server.close()
  await expectCollab(alice.heartbeat(), 'OFFLINE')
  await expectCollab(alice.publish({ baseRev: 0, snapshot: makeSnapshot() }), 'OFFLINE')
  alice.close()

  const probe = net.createServer()
  let bound = false
  for (let attempt = 0; attempt < 2 && !bound; attempt += 1) {
    try {
      await new Promise((resolve, reject) => {
        probe.once('error', reject)
        probe.listen(info.tcpPort, '127.0.0.1', resolve)
      })
      bound = true
    } catch {
      await delay(100)
    }
  }
  assert.equal(bound, true, 'close() 后监听端口应已释放')
  await new Promise((resolve) => probe.close(resolve))

  const neverStarted = new RoomServer({ dataDir: join(dataDir, 'never'), enableDiscovery: false, logger: silentLogger })
  await neverStarted.close()
})

// ---------------------------------------------------------------------------
// 17. Malformed / oversized input; clean client-side snapshot limits
// ---------------------------------------------------------------------------

test('畸形与超大输入：400/404/413、abrupt disconnect 后仍可用、客户端仍校验快照上限', async (t) => {
  const { server } = await setup(t)
  await server.createLocalRoom({ number: ROOM, password: PASSWORD })
  const alice = track(t, makeClient(server.origin))
  const aliceJoin = await alice.join()

  const malformed = await httpJson(`${server.origin}/group/v1/join`, { method: 'POST', rawBody: '{oops' })
  assert.equal(malformed.status, 400)
  assert.equal(malformed.json.error.code, 'BAD_REQUEST')

  const badRoom = await httpJson(`${server.origin}/group/v1/join`, {
    method: 'POST',
    body: { v: PROTOCOL_VERSION, room: '12' },
  })
  assert.equal(badRoom.status, 400)
  assert.equal(badRoom.json.error.code, 'BAD_ROOM')

  const unknownRoute = await httpJson(`${server.origin}/group/v1/nope`)
  assert.equal(unknownRoute.status, 404)
  assert.equal(unknownRoute.json.error.code, 'NOT_FOUND')

  // Malformed ciphertext envelope is rejected without ever being stored.
  const targetRev = (await alice.latest(0)).rev
  const badCipher = await httpJson(`${server.origin}/group/v1/publish`, {
    method: 'POST',
    body: {
      v: PROTOCOL_VERSION,
      token: aliceJoin.token,
      member: MEMBER_ALICE,
      baseRev: targetRev,
      cipher: { v: PROTOCOL_VERSION, iv: 'AAAA', tag: 'AAAA', data: 'AAAA' },
    },
  })
  assert.equal(badCipher.status, 400)
  assert.equal(badCipher.json.error.code, 'BAD_SNAPSHOT')

  // Client-side snapshot limits survive v2 (validated before encryption).
  const oversizedFile = {
    path: 'big.bin',
    size: 8 * 1024 * 1024 + 1,
    sha256: 'a'.repeat(64),
    data: 'AAAA',
  }
  await expectCollab(
    alice.publish({
      baseRev: targetRev,
      snapshot: makeSnapshot({ files: [oversizedFile] }),
    }),
    ['BAD_SNAPSHOT', 'TOO_LARGE'],
  )

  // Body cap is 96 MiB: anything larger gets a clean 413 and the server stays up.
  const oversizedBody = Buffer.alloc(96 * 1024 * 1024 + 1024, 0x61)
  const oversize = await httpJson(`${server.origin}/group/v1/join`, { method: 'POST', rawBody: oversizedBody })
  assert.equal(oversize.status, 413)
  assert.equal(oversize.json.error.code, 'TOO_LARGE')

  // Abrupt disconnect / non-HTTP garbage must not wedge the server.
  await abruptDisconnect(server.origin)
  await sendGarbageHttp(server.origin)
  await delay(40)

  const status = await alice.status()
  assert.equal(status.ok, true)
  assert.equal(status.room.number, ROOM)
})
