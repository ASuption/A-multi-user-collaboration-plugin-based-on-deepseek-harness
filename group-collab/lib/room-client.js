/**
 * DSH Group Collaboration — room client (protocol v2).
 *
 * The client is the only place that ever holds the room password, the authKey and the
 * content key. It performs the challenge-response join (password never crosses the
 * wire), derives the content key locally, and transparently encrypts/decrypts snapshots
 * so callers (lib/member.js) keep the same plaintext-facing API:
 *
 *   join()    -> { token, room, members, snapshot(plaintext), syncRequested, server }
 *   latest(r) -> { rev, members, snapshot?(plaintext), lastUpdate?, syncRequested }
 *   publish({baseRev, snapshot, note}) -> { rev }   // encrypts internally
 *   status()  -> token-authenticated room/member summary
 *
 * Plain ESM, Node builtins only.
 */
import { createSocket } from 'node:dgram'

import {
  PROTOCOL_VERSION,
  DEFAULT_UDP_PORT,
  LIMITS,
  CollabError,
  asCollabError,
  normalizeRoomNumber,
  validatePassword,
  validMember,
  normalizeSnapshot,
  diffSnapshots,
} from './protocol.js'
import {
  createProof,
  decryptSnapshot,
  deriveAuthKey,
  deriveContentKey,
  encryptSnapshot,
  zeroBuffer,
} from './crypto.js'

const TOKEN_PATTERN = /^[0-9a-f]{64}$/u
const HEX_FIELD_PATTERN = /^[0-9a-f]{16,128}$/iu
const MAX_TIMEOUT_MS = 120_000
const MIN_TIMEOUT_MS = 100

const EMPTY_CHANGES = Object.freeze({ added: [], modified: [], deleted: [] })

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

/** Normalize any user/server supplied address into a bare `http(s)://host:port` origin. */
function normalizeOrigin(value) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new CollabError('BAD_REQUEST', '房间服务器地址不能为空')
  }
  const text = value.trim()
  const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//u.test(text)
  const withScheme = hasScheme ? text : `http://${text}`
  let url
  try {
    url = new URL(withScheme)
  } catch {
    throw new CollabError('BAD_REQUEST', `房间服务器地址不合法: ${value}`)
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new CollabError('BAD_REQUEST', `房间服务器地址必须使用 http/https: ${value}`)
  }
  return url.origin
}

function validTimeout(value, fallback) {
  const parsed = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10)
  if (!Number.isFinite(parsed)) return fallback
  return Math.min(MAX_TIMEOUT_MS, Math.max(MIN_TIMEOUT_MS, Math.trunc(parsed)))
}

/** Map a bare HTTP status to the closest wire error code. */
function statusToCode(status) {
  switch (status) {
    case 400:
    case 405:
      return 'BAD_REQUEST'
    case 401:
    case 403:
      return 'UNAUTHORIZED'
    case 404:
      return 'NOT_FOUND'
    case 409:
      return 'CONFLICT'
    case 413:
      return 'TOO_LARGE'
    case 429:
      return 'TOO_MANY_REQUESTS'
    default:
      return status >= 500 ? 'PROTOCOL' : 'BAD_REQUEST'
  }
}

/** Normalize one member list entry coming from the network. */
function normalizeMemberList(value) {
  if (!Array.isArray(value)) return []
  const list = []
  for (const entry of value) {
    try {
      const member = validMember(entry)
      list.push({ id: member.id, name: member.name, online: entry.online !== false })
    } catch {
      // Skip malformed member entries from a foreign/broken server.
    }
  }
  return list
}

export class RoomClient {
  #origin
  #room
  #password
  #member
  #timeoutMs
  #logger
  #token = ''
  #knownRev = 0
  /** @type {Buffer|null} derived from saltAuth; used only for the join proof. */
  #authKey = null
  /** @type {Buffer|null} derived from saltContent; never leaves this process. */
  #contentKey = null
  /** Last decrypted snapshot (plaintext) for local diff computation / reuse. */
  #lastSnapshot = null
  #closed = false
  #inflight = new Set()

  constructor(options = {}) {
    if (!isObject(options)) throw new CollabError('BAD_REQUEST', 'RoomClient 参数不合法')
    const { origin, room, password, member, timeoutMs = 5000, logger } = options
    this.#origin = normalizeOrigin(origin)
    this.#room = normalizeRoomNumber(room)
    this.#password = typeof password === 'string' ? password : ''
    this.#member = validMember(member)
    this.#timeoutMs = validTimeout(timeoutMs, 5000)
    this.#logger = logger === null || typeof logger !== 'object' ? {} : logger
  }

  /** Normalized `http://host:port` origin of the room server. */
  get origin() {
    return this.#origin
  }

  /** Member identity sent with every request; writable so the runtime can rename it. */
  get member() {
    return { ...this.#member }
  }

  set member(value) {
    this.#member = validMember(value)
  }

  /** Room number this client is bound to. */
  get room() {
    return this.#room
  }

  // ---------------------------------------------------------------------------
  // Public API (plaintext-facing, unchanged for lib/member.js)
  // ---------------------------------------------------------------------------

  /**
   * Challenge-response join. The password is only used locally for scrypt derivation;
   * the wire carries an HMAC proof over a single-use server nonce.
   * @returns {Promise<{token, room, members, snapshot, syncRequested, server}>}
   */
  async join() {
    this.#ensureOpen()
    const password = validatePassword(this.#password)
    const challenge = await this.#request('POST', '/group/v1/challenge', {
      body: { v: PROTOCOL_VERSION, room: this.#room },
    })
    if (challenge.v !== undefined && challenge.v !== PROTOCOL_VERSION) {
      throw new CollabError('VERSION', `服务器协议版本不匹配: ${String(challenge.v)}`)
    }
    const saltAuth = this.#requireHexField(challenge.saltAuth, 'saltAuth')
    const saltContent = this.#requireHexField(challenge.saltContent, 'saltContent')
    const nonce = this.#requireHexField(challenge.nonce, 'nonce')
    // Fresh derivations for this attempt; any previous keys are zeroed first.
    const authKey = deriveAuthKey(password, saltAuth)
    const contentKey = deriveContentKey(password, saltContent)
    this.#zeroKeys()
    this.#authKey = authKey
    this.#contentKey = contentKey
    const proof = createProof(authKey, this.#room, nonce, this.#member.id)
    let payload
    try {
      payload = await this.#request('POST', '/group/v1/join', {
        body: {
          v: PROTOCOL_VERSION,
          room: this.#room,
          member: this.#member,
          nonce,
          proof,
        },
      })
    } catch (error) {
      // Wrong password / unknown room: derived keys are useless, drop them.
      this.#zeroKeys()
      throw asCollabError(error)
    }
    if (typeof payload.token !== 'string' || !TOKEN_PATTERN.test(payload.token)) {
      this.#zeroKeys()
      throw new CollabError('PROTOCOL', '服务器未返回有效访问令牌')
    }
    const room = this.#normalizeRoomInfo(payload.room)
    let snapshot = null
    if (payload.snapshot !== null && payload.snapshot !== undefined) {
      snapshot = this.#decryptWireSnapshot(payload.snapshot, room.rev)
    }
    this.#token = payload.token
    this.#knownRev = snapshot === null ? 0 : room.rev
    this.#lastSnapshot = snapshot
    const server = isObject(payload.server)
      ? {
          origin: typeof payload.server.origin === 'string' ? payload.server.origin : this.#origin,
          hostName: typeof payload.server.hostName === 'string' ? payload.server.hostName : '',
        }
      : { origin: this.#origin, hostName: '' }
    return {
      token: payload.token,
      room,
      members: normalizeMemberList(payload.members),
      snapshot,
      syncRequested: payload.syncRequested === true,
      server,
    }
  }

  /** Keep the membership alive; resolves with `{ rev, members, syncRequested }`. */
  async heartbeat() {
    this.#ensureOpen()
    const token = this.#requireToken()
    const payload = await this.#request('POST', '/group/v1/heartbeat', {
      body: { token, member: this.#member, rev: this.#knownRev },
    })
    const rev = this.#requireRev(payload.rev)
    return {
      rev,
      members: normalizeMemberList(payload.members),
      syncRequested: payload.syncRequested === true,
    }
  }

  /**
   * Fetch the latest revision state. The server omits the ciphertext when `knownRev`
   * equals the current revision; otherwise the snapshot is decrypted into plaintext.
   */
  async latest(knownRev = 0) {
    this.#ensureOpen()
    const token = this.#requireToken()
    if (!Number.isInteger(knownRev) || knownRev < 0) throw new CollabError('BAD_REQUEST', 'knownRev 不合法')
    const payload = await this.#request('GET', '/group/v1/latest', { query: { token, rev: knownRev } })
    const rev = this.#requireRev(payload.rev)
    const result = {
      rev,
      members: normalizeMemberList(payload.members),
      lastUpdate: payload.lastUpdate === undefined ? undefined : payload.lastUpdate,
      syncRequested: payload.syncRequested === true,
    }
    if (payload.snapshot === null) {
      result.snapshot = null
    } else if (payload.snapshot !== undefined) {
      const snapshot = this.#decryptWireSnapshot(payload.snapshot, rev)
      result.snapshot = snapshot
      // lastUpdate is reconstructable from the authenticated plaintext (server only
      // stores {rev, at} because note/by/changes are confidential).
      result.lastUpdate = {
        rev: snapshot.rev,
        at: snapshot.at,
        by: snapshot.by,
        note: snapshot.note,
        changes: snapshot.changes ?? { ...EMPTY_CHANGES },
      }
      this.#lastSnapshot = snapshot
    }
    this.#knownRev = rev
    return result
  }

  /**
   * Encrypt and publish one plaintext snapshot against a known base revision.
   * A stale `baseRev` throws CollabError('CONFLICT') with decrypted details
   * `{ snapshot, lastUpdate, rev }` describing the authoritative latest state.
   */
  async publish({ baseRev, snapshot, note } = {}) {
    this.#ensureOpen()
    const token = this.#requireToken()
    const contentKey = this.#requireContentKey()
    if (!Number.isInteger(baseRev) || baseRev < 0) throw new CollabError('BAD_REQUEST', 'baseRev 不合法')
    if (!isObject(snapshot)) throw new CollabError('BAD_SNAPSHOT', '缺少快照数据')
    // Validate the plaintext (paths, sizes, per-file digests) BEFORE encrypting: a
    // malformed snapshot must never reach the server and never be written to disk.
    const normalized = normalizeSnapshot(snapshot, { requireRev: false })
    const finalNote = note === undefined || note === null ? (normalized.note ?? '') : note
    if (typeof finalNote !== 'string' || finalNote.length > LIMITS.maxNoteLength) {
      throw new CollabError('BAD_REQUEST', `更新说明不能超过 ${LIMITS.maxNoteLength} 个字符`)
    }
    const rev = baseRev + 1
    let changes = normalized.changes
    if (changes === undefined) {
      changes =
        this.#lastSnapshot === null
          ? { added: normalized.files.map((file) => file.path).sort(), modified: [], deleted: [] }
          : diffSnapshots(this.#lastSnapshot.files, normalized.files)
    }
    // `by` is always the authenticated local member identity; the revision is carried
    // in the GCM AAD, so the payload itself stays plaintext-shaped for readers.
    const plaintextPayload = {
      by: { id: this.#member.id, name: this.#member.name },
      note: finalNote,
      at: normalized.at,
      files: normalized.files,
      changes,
    }
    const cipher = encryptSnapshot(contentKey, this.#room, rev, plaintextPayload)
    let response
    try {
      response = await this.#request('POST', '/group/v1/publish', {
        body: { v: PROTOCOL_VERSION, token, member: this.#member, baseRev, cipher },
      })
    } catch (error) {
      if (error instanceof CollabError && error.code === 'CONFLICT') throw this.#conflictError(error)
      throw error
    }
    const publishedRev = this.#requireRev(response.rev)
    if (publishedRev !== rev) throw new CollabError('PROTOCOL', '服务器分配的版本与本地不一致')
    this.#knownRev = publishedRev
    this.#lastSnapshot = { rev: publishedRev, ...plaintextPayload }
    return { rev: publishedRev }
  }

  /** Leave the room (idempotent from the server's point of view). */
  async leave() {
    this.#ensureOpen()
    const token = this.#token
    if (token === '') return
    await this.#request('POST', '/group/v1/leave', { body: { token } })
    this.#token = ''
    this.#knownRev = 0
    this.#lastSnapshot = null
  }

  /** Token-authenticated room status (room identity + member roster only). */
  async status() {
    this.#ensureOpen()
    const token = this.#requireToken()
    return await this.#request('GET', '/group/v1/status', { query: { token } })
  }

  /** Release client state and zero the derived keys. Never throws. */
  close() {
    this.#closed = true
    this.#token = ''
    this.#knownRev = 0
    this.#lastSnapshot = null
    this.#zeroKeys()
    for (const controller of this.#inflight) {
      try {
        controller.abort(new CollabError('OFFLINE', '客户端已关闭'))
      } catch {
        // Abort is best effort.
      }
    }
    this.#inflight.clear()
  }

  // ---------------------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------------------

  #ensureOpen() {
    if (this.#closed) throw new CollabError('OFFLINE', '客户端已关闭')
  }

  #requireToken() {
    if (this.#token === '') throw new CollabError('UNAUTHORIZED', '尚未加入房间')
    return this.#token
  }

  #requireContentKey() {
    if (this.#contentKey === null) throw new CollabError('UNAUTHORIZED', '尚未加入房间或内容密钥已清除')
    return this.#contentKey
  }

  #requireHexField(value, label) {
    if (typeof value !== 'string' || !HEX_FIELD_PATTERN.test(value)) {
      throw new CollabError('PROTOCOL', `服务器返回的 ${label} 不合法`)
    }
    return value.toLowerCase()
  }

  #requireRev(value) {
    if (!Number.isInteger(value) || value < 0) throw new CollabError('PROTOCOL', '服务器返回的版本号不合法')
    return value
  }

  #zeroKeys() {
    if (this.#authKey !== null) {
      zeroBuffer(this.#authKey)
      this.#authKey = null
    }
    if (this.#contentKey !== null) {
      zeroBuffer(this.#contentKey)
      this.#contentKey = null
    }
  }

  #normalizeRoomInfo(value) {
    const room = { number: this.#room, name: this.#room, rev: 0, createdAt: null }
    if (!isObject(value)) return room
    if (value.number !== undefined) {
      let number
      try {
        number = normalizeRoomNumber(value.number)
      } catch {
        throw new CollabError('PROTOCOL', '服务器返回的房间号不合法')
      }
      if (number !== this.#room) throw new CollabError('PROTOCOL', '服务器返回了其他房间的数据')
      room.number = number
    }
    if (typeof value.name === 'string' && value.name.trim().length > 0) room.name = value.name.trim()
    if (Number.isInteger(value.rev) && value.rev >= 0) room.rev = value.rev
    if (typeof value.createdAt === 'string' && !Number.isNaN(Date.parse(value.createdAt))) {
      room.createdAt = new Date(value.createdAt).toISOString()
    }
    return room
  }

  /**
   * Decrypt + normalize one wire snapshot `{rev, cipher}`. The GCM AAD binds the
   * ciphertext to this room and revision; any tampering fails here and the plaintext
   * is never returned to callers (so it can never reach shared/).
   */
  #decryptWireSnapshot(wire, expectedRev) {
    if (!isObject(wire)) throw new CollabError('PROTOCOL', '快照密文格式不正确')
    const rev = wire.rev
    if (!Number.isInteger(rev) || rev < 1) throw new CollabError('PROTOCOL', '快照版本号不合法')
    if (expectedRev !== undefined && rev !== expectedRev) {
      throw new CollabError('PROTOCOL', '快照版本与房间版本不一致')
    }
    const contentKey = this.#requireContentKey()
    const plaintext = decryptSnapshot(contentKey, this.#room, rev, wire.cipher)
    let normalized
    try {
      normalized = normalizeSnapshot({ ...plaintext, rev }, { requireRev: true })
    } catch (error) {
      throw asCollabError(error, 'PROTOCOL')
    }
    if (normalized.rev !== rev) throw new CollabError('PROTOCOL', '快照版本不一致')
    return normalized
  }

  /** Decrypt the ciphertext attached to a 409 conflict and build typed details. */
  #conflictError(error) {
    const rawDetails = isObject(error.details) ? error.details : {}
    const rev = Number.isInteger(rawDetails.rev) ? rawDetails.rev : undefined
    const details = { status: 409, rev, lastUpdate: rawDetails.lastUpdate ?? null }
    if (isObject(rawDetails.snapshot)) {
      // If the attached ciphertext cannot be authenticated this throws PROTOCOL:
      // a hostile server must never trick a member into applying forged content.
      const snapshot = this.#decryptWireSnapshot(rawDetails.snapshot, rev)
      details.snapshot = snapshot
      details.lastUpdate = {
        rev: snapshot.rev,
        at: snapshot.at,
        by: snapshot.by,
        note: snapshot.note,
        changes: snapshot.changes ?? { ...EMPTY_CHANGES },
      }
      this.#lastSnapshot = snapshot
      this.#knownRev = snapshot.rev
    }
    return new CollabError('CONFLICT', error.message, details)
  }

  #networkError(error) {
    if (error instanceof CollabError) return error
    if (this.#closed) return new CollabError('OFFLINE', '客户端已关闭', { cause: errorText(error) })
    if (error?.name === 'AbortError' || error?.name === 'TimeoutError') {
      return new CollabError('OFFLINE', '请求房间服务器超时', { cause: errorText(error) })
    }
    return new CollabError('OFFLINE', '无法连接房间服务器', { cause: errorText(error) })
  }

  #errorFromResponse(status, payload) {
    const info = isObject(payload) && isObject(payload.error) ? payload.error : null
    const code = typeof info?.code === 'string' && info.code.length > 0 ? info.code : statusToCode(status)
    const message =
      typeof info?.message === 'string' && info.message.length > 0
        ? info.message
        : `房间服务器返回 HTTP ${status}`
    const details = { status }
    if (status === 409) {
      details.snapshot = isObject(payload) ? (payload.snapshot ?? null) : null
      details.lastUpdate = isObject(payload) ? (payload.lastUpdate ?? null) : null
      details.rev = isObject(payload) && Number.isInteger(payload.rev) ? payload.rev : undefined
    }
    if (status === 429) {
      const retryAfter = Number.isInteger(info?.details?.retryAfterSeconds)
        ? info.details.retryAfterSeconds
        : undefined
      if (retryAfter !== undefined) details.retryAfterSeconds = retryAfter
    }
    if (info?.details !== undefined) details.errorDetails = info.details
    return new CollabError(code, message, details)
  }

  /**
   * One JSON round-trip. Network failures -> OFFLINE, non-2xx -> wire error code,
   * malformed 2xx payloads -> PROTOCOL. No password is ever placed in a request.
   */
  async #request(method, pathname, { query, body } = {}) {
    this.#ensureOpen()
    const url = new URL(`${this.#origin}${pathname}`)
    if (isObject(query)) {
      for (const [key, value] of Object.entries(query)) {
        if (value !== undefined && value !== null) url.searchParams.set(key, String(value))
      }
    }
    const init = { method, signal: null, headers: {} }
    if (body !== undefined) {
      init.headers['content-type'] = 'application/json'
      try {
        init.body = JSON.stringify(body)
      } catch (error) {
        throw new CollabError('BAD_REQUEST', '请求内容无法序列化', { cause: errorText(error) })
      }
    }
    const controller = new AbortController()
    init.signal = controller.signal
    this.#inflight.add(controller)
    const timer = setTimeout(() => {
      try {
        controller.abort(new CollabError('OFFLINE', '请求房间服务器超时'))
      } catch {
        // Abort is best effort.
      }
    }, this.#timeoutMs)
    try {
      let response
      try {
        response = await fetch(url, init)
      } catch (error) {
        throw this.#networkError(error)
      }
      let text
      try {
        text = await response.text()
      } catch (error) {
        throw this.#networkError(error)
      }
      let payload = null
      if (text.length > 0) {
        try {
          payload = JSON.parse(text)
        } catch {
          if (response.ok) throw new CollabError('PROTOCOL', '房间服务器返回了无效的 JSON')
          payload = null
        }
      }
      if (!response.ok) throw this.#errorFromResponse(response.status, payload)
      if (!isObject(payload)) throw new CollabError('PROTOCOL', '房间服务器响应格式不正确')
      if (payload.ok === false) throw this.#errorFromResponse(response.status, payload)
      return payload
    } finally {
      clearTimeout(timer)
      this.#inflight.delete(controller)
    }
  }
}

/**
 * Discover a locally hosted room over UDP broadcast/loopback.
 * Only protocol v2 replies are accepted; v1 replies are ignored.
 * Resolves `{ origin, room, via: 'discovery' }` or `undefined` on timeout.
 *
 * @param {{room: string|number, udpPort?: number, timeoutMs?: number,
 *          broadcastAddresses?: string[], logger?: object}} options
 */
export async function discoverRoom(options = {}) {
  if (!isObject(options)) return undefined
  let number
  try {
    number = normalizeRoomNumber(options.room)
  } catch {
    return undefined
  }
  const udpPort =
    Number.isInteger(options.udpPort) && options.udpPort > 0 && options.udpPort <= 65_535
      ? options.udpPort
      : DEFAULT_UDP_PORT
  const timeoutMs = validTimeout(options.timeoutMs, 1200)
  const requested =
    Array.isArray(options.broadcastAddresses) && options.broadcastAddresses.length > 0
      ? options.broadcastAddresses.filter((entry) => typeof entry === 'string' && entry.length > 0)
      : ['255.255.255.255', '127.0.0.1']
  const addresses = requested.length > 0 ? requested : ['255.255.255.255', '127.0.0.1']
  const requestPayload = Buffer.from(
    JSON.stringify({ t: 'dsh-group-discover', v: PROTOCOL_VERSION, room: number }),
    'utf8',
  )

  return await new Promise((resolveDiscover) => {
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
        // Socket already closed.
      }
      resolveDiscover(value)
    }
    timer = setTimeout(() => finish(undefined), timeoutMs)
    timer.unref?.()
    socket.on('error', () => finish(undefined))
    socket.on('message', (message) => {
      try {
        if (!Buffer.isBuffer(message) || message.length === 0 || message.length > 8192) return
        const parsed = JSON.parse(message.toString('utf8'))
        if (!isObject(parsed) || parsed.t !== 'dsh-group-room') return
        // v2 only: never follow legacy (plaintext-era) discovery replies.
        if (parsed.v !== PROTOCOL_VERSION) return
        if (normalizeRoomNumber(parsed.room) !== number) return
        if (typeof parsed.url !== 'string' || !/^https?:\/\//iu.test(parsed.url)) return
        let origin
        try {
          origin = new URL(parsed.url).origin
        } catch {
          return
        }
        // Room name is intentionally not accepted/returned: discovery must not leak it.
        finish({ origin, room: number, via: 'discovery' })
      } catch {
        // Ignore malformed discovery replies.
      }
    })
    try {
      socket.bind(0, () => {
        if (settled) return
        try {
          socket.setBroadcast(true)
        } catch {
          // Some platforms/adapters refuse broadcast; loopback still works.
        }
        for (const address of addresses) {
          try {
            socket.send(requestPayload, udpPort, address, () => {})
          } catch {
            // Best effort per address.
          }
        }
      })
    } catch {
      finish(undefined)
    }
  })
}

function errorText(error) {
  if (error instanceof Error) return error.message
  return String(error)
}
