/**
 * DSH Group Collaboration — room server (protocol v2).
 *
 * Privacy model (SECURITY.md): this server is a blind relay. It never receives the
 * room password or content key and can never read shared-file content or update
 * notes. It stores only per-room salts, an authKey verifier and encrypted snapshot
 * ciphertext.
 *
 *   - challenge-response join: single-use 60s nonce + HMAC proof, uniform 401 for
 *     unknown rooms / wrong password / expired or replayed nonces (no enumeration);
 *   - per-IP rate limiting: challenges 30/min, join lockout after 5 failures/60s;
 *   - snapshot confidentiality: AES-256-GCM ciphertext bound to `<room>:<rev>` via AAD;
 *   - token-authenticated latest/status/publish/heartbeat/leave;
 *   - UDP discovery replies carry only room number + URL (never the room name);
 *   - v1 room files are renamed `<room>.json.legacy-v1` and ignored.
 *
 * Plain ESM, Node builtins only. Every request handler is fully guarded: malformed
 * JSON, oversized bodies and validation failures become JSON 4xx responses, never
 * unhandled rejections.
 */
import { createServer } from 'node:http'
import { createSocket } from 'node:dgram'
import { promises as fsp } from 'node:fs'
import { join, resolve as resolvePath } from 'node:path'
import { hostname, networkInterfaces } from 'node:os'
import { isIPv4, isIPv6 } from 'node:net'

import {
  PROTOCOL_VERSION,
  DEFAULT_TCP_PORT,
  DEFAULT_UDP_PORT,
  LIMITS,
  CollabError,
  asCollabError,
  normalizeRoomNumber,
  validatePassword,
  createToken,
  validMember,
  sanitizeMemberName,
} from './protocol.js'
import {
  CHALLENGE_TTL_MS,
  MAX_CIPHER_BYTES,
  createNonce,
  createRoomSecrets,
  encodeCipher,
  fakeRoomSalts,
  normalizeCipher,
  randomSalt,
  randomSecret,
  verifyProof,
} from './crypto.js'

/** Hard cap for one POST body: encrypted publishes are larger than v1 plaintext. */
const MAX_BODY_BYTES = 96 * 1024 * 1024
/** TCP/UDP port fallback range: requested port .. requested port + 9. */
const PORT_ATTEMPTS = 10
/** A member is "online" while its last heartbeat is younger than this. */
const ONLINE_WINDOW_MS = 15_000
/** Tokens whose member has not been seen for this long are dropped from memory. */
const MEMBER_STALE_MS = 30 * 60 * 1000
/** `<dataDir>/rooms/<4-8 digits>.json` — anything else is not a room file. */
const ROOM_FILE_PATTERN = /^([0-9]{4,8})\.json$/u
const TOKEN_PATTERN = /^[0-9a-f]{64}$/u
const SALT_PATTERN = /^[0-9a-f]{16,128}$/iu
const AUTH_KEY_PATTERN = /^[0-9a-f]{64}$/iu
/** Uniform authentication-failure message: existing vs unknown room must not differ. */
const JOIN_AUTH_FAILURE_MESSAGE = '房间不存在或密码错误，无法加入'
/** Sliding-window rate limits (per client IP). */
const CHALLENGE_RATE = Object.freeze({ windowMs: 60_000, max: 30 })
const JOIN_FAILURE_RATE = Object.freeze({ windowMs: 60_000, max: 5, lockMs: 60_000 })
/** Bound on stored outstanding challenges (per-IP rate limit bounds growth anyway). */
const MAX_PENDING_CHALLENGES = 10_000
/** Bound on remembered per-IP rate-limit states. */
const MAX_RATE_STATES = 2_048

const STATUS_BY_CODE = Object.freeze({
  BAD_REQUEST: 400,
  BAD_ROOM: 400,
  BAD_PASSWORD: 400,
  BAD_PATH: 400,
  BAD_SNAPSHOT: 400,
  VERSION: 400,
  UNAUTHORIZED: 401,
  NOT_FOUND: 404,
  CONFLICT: 409,
  TOO_LARGE: 413,
  TOO_MANY_REQUESTS: 429,
  PROTOCOL: 500,
  OFFLINE: 503,
})

const KNOWN_ROUTES = new Set([
  '/group/v1/challenge',
  '/group/v1/join',
  '/group/v1/heartbeat',
  '/group/v1/latest',
  '/group/v1/publish',
  '/group/v1/leave',
  '/group/v1/status',
])

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

/** Normalize a user-supplied room display name. */
function normalizeRoomName(value, number) {
  const fallback = `房间 ${number}`
  if (typeof value !== 'string' || value.trim().length === 0) return fallback
  return sanitizeMemberName(value, fallback)
}

/** True for 127.0.0.0/8, `::1` and IPv4-mapped loopback peer addresses. */
function isLoopbackPeerAddress(value) {
  if (typeof value !== 'string') return false
  const text = value.trim().toLowerCase()
  if (text.length === 0) return false
  if (text === 'localhost') return true
  const mapped = text.startsWith('::ffff:') ? text.slice('::ffff:'.length) : text
  if (isIPv4(mapped)) return mapped.startsWith('127.')
  if (isIPv6(text)) return text === '::1' || text === '0:0:0:0:0:0:0:1'
  return false
}

/** Convert a dotted IPv4 address to an unsigned 32-bit integer; null when invalid. */
function ipv4ToInt(address) {
  if (typeof address !== 'string') return null
  const parts = address.split('.')
  if (parts.length !== 4) return null
  let value = 0
  for (const part of parts) {
    if (!/^[0-9]{1,3}$/u.test(part)) return null
    const octet = Number(part)
    if (octet > 255) return null
    value = value * 256 + octet
  }
  return value
}

/** True when `address` and `peerAddress` are in the same subnet per `netmask`. */
function isSameSubnet(address, peerAddress, netmask) {
  const local = ipv4ToInt(address)
  const peer = ipv4ToInt(peerAddress)
  const mask = ipv4ToInt(netmask)
  if (local === null || peer === null || mask === null || mask === 0) return false
  return ((local & mask) >>> 0) === ((peer & mask) >>> 0)
}

/** Strip an IPv4-mapped prefix so `::ffff:192.168.1.9` can be compared as IPv4. */
function peerToIPv4(value) {
  if (typeof value !== 'string') return null
  const text = value.trim()
  const mapped = text.toLowerCase().startsWith('::ffff:') ? text.slice('::ffff:'.length) : text
  return isIPv4(mapped) ? mapped : null
}

/**
 * Pick the IPv4 this server should advertise to `peerAddress`.
 *
 * Candidates are all non-internal IPv4 addresses in deterministic `networkInterfaces()`
 * order. A candidate on the peer's subnet wins (so multi-homed hosts advertise a NIC the
 * peer can actually reach); otherwise the first/primary candidate is used. Returns null
 * when the host has no non-internal IPv4.
 */
function pickPrimaryLanIPv4(interfaces, peerAddress) {
  if (!isObject(interfaces)) return null
  const candidates = []
  for (const name of Object.keys(interfaces)) {
    const entries = interfaces[name]
    if (!Array.isArray(entries)) continue
    for (const entry of entries) {
      if (!isObject(entry) || entry.internal === true) continue
      if (entry.family !== 'IPv4' && entry.family !== 4) continue
      if (typeof entry.address !== 'string' || !isIPv4(entry.address)) continue
      candidates.push({
        address: entry.address,
        netmask: typeof entry.netmask === 'string' ? entry.netmask : null,
      })
    }
  }
  if (candidates.length === 0) return null
  const peer = peerToIPv4(peerAddress)
  if (peer !== null) {
    for (const candidate of candidates) {
      if (candidate.netmask !== null && isSameSubnet(candidate.address, peer, candidate.netmask)) {
        return candidate.address
      }
    }
  }
  return candidates[0].address
}

/** Format a URL hostname, bracketing bare IPv6 literals. */
function formatUrlHost(host) {
  if (host.startsWith('[')) return host
  return host.includes(':') ? `[${host}]` : host
}

/** Normalize the `advertiseHost` option to a bare hostname; null when not configured. */
function normalizeAdvertiseHost(value) {
  if (value === undefined || value === null) return null
  if (typeof value !== 'string') throw new CollabError('BAD_REQUEST', 'advertiseHost 不合法')
  const text = value.trim()
  if (text.length === 0) return null
  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//u.test(text) ? text : `http://${text}`
  let url
  try {
    url = new URL(withScheme)
  } catch {
    throw new CollabError('BAD_REQUEST', `advertiseHost 不合法: ${value}`)
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new CollabError('BAD_REQUEST', `advertiseHost 必须是主机名或 IP: ${value}`)
  }
  return url.hostname
}

/**
 * Deterministic origin advertised in a UDP discovery reply.
 *
 * - an explicit `advertiseHost` always wins, for any peer;
 * - a loopback peer is on this host, so answer `http://127.0.0.1:<tcpPort>`;
 * - otherwise answer `http://<server non-internal IPv4>:<tcpPort>`, preferring an
 *   address on the peer's subnet when the host is multi-homed and otherwise the
 *   deterministic primary interface; fall back to 127.0.0.1 when the host has no
 *   non-internal IPv4.
 *
 * `interfaces` is an optional injectable `networkInterfaces()` snapshot for tests;
 * production callers omit it and the real interfaces are used.
 *
 * @param {{peerAddress?: string, tcpPort?: number, advertiseHost?: string,
 *          interfaces?: object}} [options]
 * @returns {string} `http://<host>:<tcpPort>`
 */
export function resolveAdvertisedUrl(options = {}) {
  if (!isObject(options)) throw new CollabError('BAD_REQUEST', 'resolveAdvertisedUrl 参数不合法')
  const tcpPort = options.tcpPort
  if (!Number.isInteger(tcpPort) || tcpPort < 1 || tcpPort > 65_535) {
    throw new CollabError('BAD_REQUEST', 'tcpPort 不合法')
  }
  const advertiseHost = normalizeAdvertiseHost(options.advertiseHost)
  if (advertiseHost !== null) return `http://${formatUrlHost(advertiseHost)}:${tcpPort}`
  if (isLoopbackPeerAddress(options.peerAddress)) return `http://127.0.0.1:${tcpPort}`
  const interfaces = options.interfaces === undefined ? networkInterfaces() : options.interfaces
  const lanAddress = pickPrimaryLanIPv4(interfaces, options.peerAddress)
  return `http://${lanAddress ?? '127.0.0.1'}:${tcpPort}`
}

export class RoomServer {
  #dataDir
  #roomsDir
  #logger
  #hostName
  #advertiseHost
  #enableDiscovery
  #requestedTcpPort
  #requestedUdpPort
  #challengeTtlMs
  /** Per-process secret: unknown rooms get stable, random-looking fake salts. */
  #fakeSaltSecret

  #httpServer = null
  #udpSocket = null
  #tcpPort = null
  #udpPort = null
  #origin = undefined

  /** Cached `networkInterfaces()` snapshot used for discovery replies. */
  #interfacesCache = null

  /** number -> validated v2 room state (salts, authKey verifier, ciphertext only). */
  #rooms = new Map()
  /** token -> { token, room, id, name, lastSeen, knownRev, workspace }. */
  #members = new Map()
  /** nonce -> { room, expiresAt, authKey } single-use join challenges. */
  #challenges = new Map()
  /** client IP -> { challengeTimes, joinFailures, lockedUntil }. */
  #rateStates = new Map()
  /** Live HTTP sockets, destroyed on close() so the server never hangs. */
  #sockets = new Set()
  /** number -> tail promise of the per-room mutation queue. */
  #locks = new Map()
  #loadPromise = null
  #listenPromise = null
  #closePromise = null
  #listening = false
  #closed = false

  constructor(options = {}) {
    if (!isObject(options)) throw new CollabError('BAD_REQUEST', 'RoomServer 参数不合法')
    const {
      dataDir,
      tcpPort = DEFAULT_TCP_PORT,
      udpPort = DEFAULT_UDP_PORT,
      enableDiscovery = true,
      logger = console,
      hostName,
      advertiseHost,
      challengeTtlMs = CHALLENGE_TTL_MS,
    } = options
    if (typeof dataDir !== 'string' || dataDir.trim().length === 0) {
      throw new CollabError('BAD_REQUEST', 'dataDir 不能为空')
    }
    this.#dataDir = resolvePath(dataDir.trim())
    this.#roomsDir = join(this.#dataDir, 'rooms')
    this.#requestedTcpPort = this.#normalizePort(tcpPort, DEFAULT_TCP_PORT)
    this.#requestedUdpPort = this.#normalizePort(udpPort, DEFAULT_UDP_PORT)
    this.#enableDiscovery = enableDiscovery !== false
    this.#logger = logger === null || typeof logger !== 'object' ? {} : logger
    this.#hostName =
      typeof hostName === 'string' && hostName.trim().length > 0 ? sanitizeMemberName(hostName, hostname()) : hostname()
    this.#advertiseHost = normalizeAdvertiseHost(advertiseHost)
    this.#challengeTtlMs =
      Number.isInteger(challengeTtlMs) && challengeTtlMs >= 50 && challengeTtlMs <= 10 * 60 * 1000
        ? challengeTtlMs
        : CHALLENGE_TTL_MS
    this.#fakeSaltSecret = randomSecret()
  }

  #normalizePort(value, fallback) {
    const port = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10)
    if (!Number.isInteger(port) || port < 0 || port > 65_535) return fallback
    return port
  }

  /** Cached OS interface snapshot so discovery replies are stable and cheap. */
  #interfaceSnapshot() {
    if (this.#interfacesCache === null) this.#interfacesCache = networkInterfaces()
    return this.#interfacesCache
  }

  /** Absolute data directory; exposed read-only for diagnostics/tests. */
  get dataDir() {
    return this.#dataDir
  }

  /** `http://127.0.0.1:<tcpPort>` once listening, otherwise undefined. */
  get origin() {
    return this.#origin
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  async listen() {
    if (this.#listenPromise !== null) return await this.#listenPromise
    if (this.#closed) throw new CollabError('PROTOCOL', '房间服务已关闭')
    this.#listenPromise = this.#startListening().catch((error) => {
      this.#listenPromise = null
      throw error
    })
    return await this.#listenPromise
  }

  async #startListening() {
    await this.#ensureLoaded()
    const bound = await this.#bindHttp(this.#requestedTcpPort)
    this.#httpServer = bound.server
    this.#tcpPort = bound.port
    this.#origin = `http://127.0.0.1:${this.#tcpPort}`
    if (this.#enableDiscovery) {
      try {
        const udp = await this.#bindUdp(this.#requestedUdpPort)
        this.#udpSocket = udp.socket
        this.#udpPort = udp.port
      } catch (error) {
        this.#udpSocket = null
        this.#udpPort = null
        this.#logger.warn?.(`[group-collab] UDP 发现服务启动失败，局域网发现已禁用: ${errorText(error)}`)
      }
    }
    this.#listening = true
    return { tcpPort: this.#tcpPort, udpPort: this.#udpPort, origin: this.#origin }
  }

  #bindHttp(startPort) {
    return new Promise((resolveBind, rejectBind) => {
      let attempt = 0
      const tryOnce = () => {
        const port = startPort === 0 ? 0 : startPort + attempt
        const server = createServer((request, response) => this.#handleRequest(request, response))
        server.on('connection', (socket) => {
          this.#sockets.add(socket)
          socket.on('close', () => this.#sockets.delete(socket))
          socket.on('error', () => this.#sockets.delete(socket))
        })
        server.on('clientError', (_error, socket) => {
          try {
            if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
            else socket.destroy()
          } catch {
            try {
              socket.destroy()
            } catch {
              // Socket already gone.
            }
          }
        })
        const onError = (error) => {
          server.removeListener('listening', onListening)
          const retryable = error?.code === 'EADDRINUSE' || error?.code === 'EACCES'
          if (retryable && startPort !== 0 && attempt < PORT_ATTEMPTS - 1) {
            attempt += 1
            tryOnce()
            return
          }
          rejectBind(error)
        }
        const onListening = () => {
          server.removeListener('error', onError)
          server.on('error', (error) => {
            this.#logger.warn?.(`[group-collab] 房间服务 HTTP 错误: ${errorText(error)}`)
          })
          let address
          try {
            address = server.address()
          } catch {
            address = null
          }
          if (address === null || typeof address !== 'object') {
            rejectBind(new CollabError('PROTOCOL', '无法获取房间服务端口'))
            return
          }
          resolveBind({ server, port: address.port })
        }
        server.once('error', onError)
        server.once('listening', onListening)
        server.listen(port, '0.0.0.0')
      }
      tryOnce()
    })
  }

  #bindUdp(startPort) {
    return new Promise((resolveBind, rejectBind) => {
      let attempt = 0
      const tryOnce = () => {
        const port = startPort === 0 ? 0 : startPort + attempt
        const socket = createSocket('udp4')
        const onError = (error) => {
          socket.removeListener('listening', onListening)
          try {
            socket.close()
          } catch {
            // Not bound yet.
          }
          const retryable = error?.code === 'EADDRINUSE' || error?.code === 'EACCES'
          if (retryable && startPort !== 0 && attempt < PORT_ATTEMPTS - 1) {
            attempt += 1
            tryOnce()
            return
          }
          rejectBind(error)
        }
        const onListening = () => {
          socket.removeListener('error', onError)
          socket.on('error', (error) => {
            this.#logger.warn?.(`[group-collab] UDP 发现服务错误: ${errorText(error)}`)
          })
          socket.on('message', (message, rinfo) => this.#handleDatagram(message, rinfo, socket))
          let address
          try {
            address = socket.address()
          } catch {
            address = null
          }
          if (address === null || typeof address !== 'object') {
            rejectBind(new CollabError('PROTOCOL', '无法获取 UDP 发现端口'))
            return
          }
          resolveBind({ socket, port: address.port })
        }
        socket.once('error', onError)
        socket.once('listening', onListening)
        socket.bind(port, '0.0.0.0')
      }
      tryOnce()
    })
  }

  /** Close HTTP + UDP, drop tokens/challenges and cached secrets. Idempotent. */
  async close() {
    if (this.#closePromise !== null) return await this.#closePromise
    this.#closePromise = this.#shutdown()
    return await this.#closePromise
  }

  async #shutdown() {
    this.#closed = true
    this.#listening = false

    const udpSocket = this.#udpSocket
    this.#udpSocket = null
    if (udpSocket !== null) {
      await new Promise((resolveClose) => {
        try {
          udpSocket.close(() => resolveClose())
        } catch {
          resolveClose()
        }
      })
    }

    const httpServer = this.#httpServer
    this.#httpServer = null
    if (httpServer !== null) {
      await new Promise((resolveClose) => {
        let settled = false
        let timer = null
        const done = () => {
          if (settled) return
          settled = true
          if (timer !== null) clearTimeout(timer)
          resolveClose()
        }
        timer = setTimeout(done, 1500)
        timer.unref?.()
        try {
          httpServer.close(() => done())
        } catch {
          done()
        }
        try {
          httpServer.closeAllConnections?.()
        } catch {
          // Best effort.
        }
        for (const socket of this.#sockets) {
          try {
            socket.destroy()
          } catch {
            // Socket already gone.
          }
        }
        this.#sockets.clear()
      })
    }

    this.#tcpPort = null
    this.#udpPort = null
    this.#origin = undefined
    this.#members.clear()
    this.#challenges.clear()
    this.#rateStates.clear()
    this.#locks.clear()
  }

  // ---------------------------------------------------------------------------
  // Room administration (in-process API, not exposed over HTTP)
  // ---------------------------------------------------------------------------

  listRooms() {
    const rooms = [...this.#rooms.values()].sort((a, b) => (a.number < b.number ? -1 : a.number > b.number ? 1 : 0))
    return rooms.map((room) => ({
      number: room.number,
      name: room.name,
      rev: room.rev,
      online: this.#membersOf(room.number).some((member) => member.online),
      createdAt: room.createdAt,
    }))
  }

  hasRoom(number) {
    try {
      return this.#rooms.has(normalizeRoomNumber(number))
    } catch {
      return false
    }
  }

  /** Local room info as consumed by CollabRuntime. */
  getLocalRoom(number) {
    let normalized
    try {
      normalized = normalizeRoomNumber(number)
    } catch {
      return undefined
    }
    const room = this.#rooms.get(normalized)
    if (room === undefined) return undefined
    return { number: room.number, name: room.name, origin: this.#origin, rev: room.rev }
  }

  /**
   * Create a v2 room hosted by this server. The password is consumed in-process to
   * derive the authKey verifier; neither password nor contentKey is persisted.
   * @returns {Promise<{number,name,rev,createdAt,origin}>}
   */
  async createLocalRoom(options = {}) {
    if (this.#closed) throw new CollabError('PROTOCOL', '房间服务已关闭')
    if (!isObject(options)) throw new CollabError('BAD_REQUEST', '创建房间参数不合法')
    const number = normalizeRoomNumber(options.number)
    const password = validatePassword(options.password)
    const name = normalizeRoomName(options.name, number)
    await this.#ensureLoaded()

    const created = await this.#withRoomLock(number, async () => {
      if (this.#rooms.has(number)) throw new CollabError('CONFLICT', `房间号 ${number} 已存在`)
      let onDisk = true
      try {
        await fsp.access(this.#roomFilePath(number))
      } catch {
        onDisk = false
      }
      if (onDisk) throw new CollabError('CONFLICT', `房间号 ${number} 已存在`)
      const { saltAuth, saltContent, authKey } = createRoomSecrets(password)
      const room = {
        version: PROTOCOL_VERSION,
        number,
        name,
        rev: 0,
        snapshot: null,
        saltAuth,
        saltContent,
        authKey,
        createdAt: new Date().toISOString(),
        lastUpdate: null,
      }
      await this.#writeRoomState(room)
      return room
    })
    this.#rooms.set(number, created)
    return { ...this.#publicRoom(created), origin: this.#origin }
  }

  // ---------------------------------------------------------------------------
  // HTTP plumbing
  // ---------------------------------------------------------------------------

  #handleRequest(request, response) {
    const fail = (error) => {
      try {
        this.#sendError(response, asCollabError(error))
      } catch {
        try {
          response.destroy()
        } catch {
          // Response already gone.
        }
      }
    }
    try {
      request.on('error', () => {})
      response.on('error', () => {})
      this.#handleRoute(request, response).catch(fail)
    } catch (error) {
      fail(error)
    }
  }

  async #handleRoute(request, response) {
    let url
    try {
      const target = typeof request.url === 'string' && request.url.length > 0 ? request.url : '/'
      url = new URL(target, 'http://localhost')
    } catch {
      this.#sendError(response, new CollabError('BAD_REQUEST', '请求地址不合法'))
      return
    }
    const method = typeof request.method === 'string' ? request.method.toUpperCase() : 'GET'
    const pathname = url.pathname
    try {
      if (method === 'POST' && pathname === '/group/v1/challenge') return await this.#handleChallenge(request, response)
      if (method === 'POST' && pathname === '/group/v1/join') return await this.#handleJoin(request, response)
      if (method === 'POST' && pathname === '/group/v1/heartbeat') return await this.#handleHeartbeat(request, response)
      if (method === 'GET' && pathname === '/group/v1/latest') return await this.#handleLatest(request, response, url)
      if (method === 'POST' && pathname === '/group/v1/publish') return await this.#handlePublish(request, response)
      if (method === 'POST' && pathname === '/group/v1/leave') return await this.#handleLeave(request, response)
      if (method === 'GET' && pathname === '/group/v1/status') return await this.#handleStatus(request, response, url)
      if (KNOWN_ROUTES.has(pathname)) {
        this.#sendError(response, new CollabError('BAD_REQUEST', '不支持的 HTTP 方法'))
        return
      }
      this.#sendError(response, new CollabError('NOT_FOUND', '接口不存在'))
    } catch (error) {
      this.#sendError(response, asCollabError(error))
    }
  }

  #sendJson(response, status, payload, headers = undefined) {
    try {
      if (response.writableEnded || response.destroyed) return
      const body = Buffer.from(JSON.stringify(payload), 'utf8')
      response.statusCode = status
      response.setHeader('content-type', 'application/json; charset=utf-8')
      response.setHeader('cache-control', 'no-store')
      response.setHeader('content-length', String(body.byteLength))
      if (headers !== undefined) {
        for (const [name, value] of Object.entries(headers)) response.setHeader(name, value)
      }
      response.end(body)
    } catch {
      try {
        response.destroy()
      } catch {
        // Response already gone.
      }
    }
  }

  #sendError(response, error) {
    const code = typeof error?.code === 'string' && error.code.length > 0 ? error.code : 'BAD_REQUEST'
    const status = STATUS_BY_CODE[code] ?? 400
    const message =
      typeof error?.message === 'string' && error.message.length > 0 ? error.message : `请求失败: ${code}`
    const payload = { ok: false, error: { code, message } }
    if (error?.details !== undefined) {
      try {
        payload.error.details = error.details
      } catch {
        // Unserializable details are dropped.
      }
    }
    const headers = {}
    if (status === 429) {
      const retryAfter = Number.isInteger(error?.details?.retryAfterSeconds) ? error.details.retryAfterSeconds : 60
      headers['retry-after'] = String(retryAfter)
    }
    this.#sendJson(response, status, payload, headers)
  }

  /** Read one request body up to 96 MiB; oversized bodies get a clean 413. */
  #readBody(request) {
    return new Promise((resolveBody, rejectBody) => {
      const chunks = []
      let size = 0
      let overflow = false
      let settled = false
      const cleanup = () => {
        request.removeListener('data', onData)
        request.removeListener('end', onEnd)
        request.removeListener('error', onError)
        request.removeListener('aborted', onAborted)
        request.removeListener('close', onClose)
      }
      const settle = (kind, value) => {
        if (settled) return
        settled = true
        cleanup()
        if (kind === 'resolve') resolveBody(value)
        else rejectBody(value)
      }
      const onData = (chunk) => {
        if (overflow) return
        size += chunk.length
        if (size > MAX_BODY_BYTES) {
          overflow = true
          chunks.length = 0
          return
        }
        chunks.push(chunk)
      }
      const onEnd = () => {
        if (overflow) settle('reject', new CollabError('TOO_LARGE', `请求体超过 ${MAX_BODY_BYTES} 字节`))
        else settle('resolve', Buffer.concat(chunks))
      }
      const onError = () => settle('reject', new CollabError('BAD_REQUEST', '读取请求体失败'))
      const onAborted = () => settle('reject', new CollabError('BAD_REQUEST', '请求已中断'))
      const onClose = () => {
        if (!settled) settle('reject', new CollabError('BAD_REQUEST', '请求已中断'))
      }
      request.on('data', onData)
      request.on('end', onEnd)
      request.on('error', onError)
      request.on('aborted', onAborted)
      request.on('close', onClose)
    })
  }

  async #readJsonBody(request) {
    const buffer = await this.#readBody(request)
    if (buffer.length === 0) return {}
    let parsed
    try {
      parsed = JSON.parse(buffer.toString('utf8'))
    } catch {
      throw new CollabError('BAD_REQUEST', '请求体不是合法的 JSON')
    }
    if (!isObject(parsed)) throw new CollabError('BAD_REQUEST', '请求体必须是 JSON 对象')
    return parsed
  }

  #clientIp(request) {
    const raw = request.socket?.remoteAddress
    return typeof raw === 'string' && raw.length > 0 ? raw : 'unknown'
  }

  // ---------------------------------------------------------------------------
  // Per-IP rate limiting / lockout
  // ---------------------------------------------------------------------------

  #rateState(ip, now) {
    let state = this.#rateStates.get(ip)
    if (state === undefined) {
      if (this.#rateStates.size >= MAX_RATE_STATES) {
        const oldest = this.#rateStates.keys().next()
        if (!oldest.done) this.#rateStates.delete(oldest.value)
      }
      state = { challengeTimes: [], joinFailures: [], lockedUntil: 0, touchedAt: now }
      this.#rateStates.set(ip, state)
    }
    state.touchedAt = now
    return state
  }

  /** 30 challenges/minute per IP; throws 429 with retryAfterSeconds when exceeded. */
  #consumeChallengeRate(ip, now) {
    const state = this.#rateState(ip, now)
    state.challengeTimes = state.challengeTimes.filter((time) => now - time < CHALLENGE_RATE.windowMs)
    if (state.challengeTimes.length >= CHALLENGE_RATE.max) {
      const oldest = state.challengeTimes[0] ?? now
      const retryAfterSeconds = Math.max(1, Math.ceil((oldest + CHALLENGE_RATE.windowMs - now) / 1000))
      throw new CollabError('TOO_MANY_REQUESTS', '请求过于频繁，请稍后再试', { retryAfterSeconds })
    }
    state.challengeTimes.push(now)
  }

  /** Reject joins while the per-IP lockout is active. */
  #assertJoinNotLocked(ip, now) {
    const state = this.#rateState(ip, now)
    if (state.lockedUntil > now) {
      const retryAfterSeconds = Math.max(1, Math.ceil((state.lockedUntil - now) / 1000))
      throw new CollabError('TOO_MANY_REQUESTS', '尝试次数过多，已暂时锁定，请稍后再试', { retryAfterSeconds })
    }
    if (state.lockedUntil !== 0) {
      state.lockedUntil = 0
      state.joinFailures = []
    }
  }

  /** Record one failed join; after 5 failures/60s the next request is locked out. */
  #recordJoinFailure(ip, now) {
    const state = this.#rateState(ip, now)
    state.joinFailures = state.joinFailures.filter((time) => now - time < JOIN_FAILURE_RATE.windowMs)
    state.joinFailures.push(now)
    if (state.joinFailures.length >= JOIN_FAILURE_RATE.max) {
      state.lockedUntil = now + JOIN_FAILURE_RATE.lockMs
    }
  }

  /** A successful join clears both the failure counter and any pending lockout. */
  #clearJoinFailures(ip, now) {
    const state = this.#rateState(ip, now)
    state.joinFailures = []
    state.lockedUntil = 0
  }

  // ---------------------------------------------------------------------------
  // v2 join challenge
  // ---------------------------------------------------------------------------

  async #handleChallenge(request, response) {
    const body = await this.#readJsonBody(request)
    if (body.v !== undefined && body.v !== PROTOCOL_VERSION) {
      throw new CollabError('VERSION', `协议版本不匹配: ${String(body.v)}`)
    }
    const number = normalizeRoomNumber(body.room)
    const ip = this.#clientIp(request)
    const now = Date.now()
    this.#consumeChallengeRate(ip, now)
    await this.#ensureLoaded()
    this.#pruneChallenges(now)
    // Unknown rooms get stable, random-looking salts of exactly the same shape as real
    // rooms, so repeated challenges cannot reveal room existence (no enumeration).
    const room = this.#rooms.get(number)
    const fakeSalts = room === undefined ? fakeRoomSalts(this.#fakeSaltSecret, number) : null
    const nonce = createNonce()
    this.#challenges.set(nonce, {
      room: number,
      expiresAt: now + this.#challengeTtlMs,
      authKey: typeof room?.authKey === 'string' ? room.authKey : null,
    })
    this.#sendJson(response, 200, {
      ok: true,
      v: PROTOCOL_VERSION,
      room: number,
      saltAuth: typeof room?.saltAuth === 'string' ? room.saltAuth : fakeSalts.saltAuth,
      saltContent: typeof room?.saltContent === 'string' ? room.saltContent : fakeSalts.saltContent,
      nonce,
    })
  }

  #pruneChallenges(now) {
    if (this.#challenges.size === 0) return
    for (const [nonce, pending] of this.#challenges) {
      if (pending.expiresAt <= now) this.#challenges.delete(nonce)
    }
    while (this.#challenges.size > MAX_PENDING_CHALLENGES) {
      const oldest = this.#challenges.keys().next()
      if (oldest.done) break
      this.#challenges.delete(oldest.value)
    }
  }

  // ---------------------------------------------------------------------------
  // v2 join
  // ---------------------------------------------------------------------------

  async #handleJoin(request, response) {
    const body = await this.#readJsonBody(request)
    if (body.v !== undefined && body.v !== PROTOCOL_VERSION) {
      throw new CollabError('VERSION', `协议版本不匹配: ${String(body.v)}`)
    }
    const ip = this.#clientIp(request)
    const now = Date.now()
    // Lockout check happens before touching any credentials.
    this.#assertJoinNotLocked(ip, now)
    // Invalid room format / member data are client errors, not password guesses.
    const number = normalizeRoomNumber(body.room)
    const member = validMember(body.member)
    const nonce = typeof body.nonce === 'string' ? body.nonce : ''
    // Single use: consume the challenge before any verification (replay protection).
    const pending = this.#challenges.get(nonce)
    if (pending !== undefined) this.#challenges.delete(nonce)
    await this.#ensureLoaded()
    const room = this.#rooms.get(number)
    const nonceValid = pending !== undefined && pending.room === number && pending.expiresAt >= now
    // Always run one HMAC verification, even for unknown rooms, to keep timing uniform.
    const authKeyHex =
      typeof room?.authKey === 'string'
        ? room.authKey
        : typeof pending?.authKey === 'string'
          ? pending.authKey
          : `${randomSalt()}${randomSalt()}`
    const proofOk = nonceValid && room !== undefined && verifyProof(authKeyHex, number, nonce, member.id, body.proof)
    if (!proofOk) {
      this.#recordJoinFailure(ip, now)
      throw new CollabError('UNAUTHORIZED', JOIN_AUTH_FAILURE_MESSAGE)
    }
    this.#clearJoinFailures(ip, now)
    this.#pruneMembers()
    // One workspace/member = one live session: a re-join replaces older tokens.
    for (const [token, record] of this.#members) {
      if (record.room === number && record.id === member.id) this.#members.delete(token)
    }
    const workspace = typeof body.workspace === 'string' ? body.workspace.slice(0, 4096) : ''
    const token = createToken()
    this.#members.set(token, {
      token,
      room: number,
      id: member.id,
      name: member.name,
      lastSeen: now,
      knownRev: 0,
      workspace,
    })
    this.#sendJson(response, 200, {
      ok: true,
      v: PROTOCOL_VERSION,
      token,
      server: { origin: this.#origin, hostName: this.#hostName },
      room: this.#publicRoom(room),
      members: this.#membersOf(number),
      snapshot: room.snapshot === null ? null : { rev: room.snapshot.rev, cipher: room.snapshot.cipher },
      syncRequested: room.rev > 0,
    })
  }

  // ---------------------------------------------------------------------------
  // Authenticated endpoints
  // ---------------------------------------------------------------------------

  async #handleHeartbeat(request, response) {
    const body = await this.#readJsonBody(request)
    const record = this.#authenticateToken(body.token)
    this.#applyMemberUpdate(record, body.member)
    if (Number.isInteger(body.rev) && body.rev >= 0) record.knownRev = body.rev
    record.lastSeen = Date.now()
    const room = await this.#requireRoomForRecord(record)
    this.#sendJson(response, 200, {
      ok: true,
      rev: room.rev,
      members: this.#membersOf(room.number),
      syncRequested: record.knownRev < room.rev,
    })
  }

  async #handleLatest(request, response, url) {
    const token = url.searchParams.get('token') ?? ''
    const record = this.#authenticateToken(token)
    let knownRev = record.knownRev
    const rawRev = url.searchParams.get('rev')
    if (rawRev !== null && rawRev !== '') {
      const parsed = Number(rawRev)
      if (!Number.isInteger(parsed) || parsed < 0) throw new CollabError('BAD_REQUEST', 'rev 参数不合法')
      knownRev = parsed
    }
    record.knownRev = knownRev
    record.lastSeen = Date.now()
    const room = await this.#requireRoomForRecord(record)
    const payload = {
      ok: true,
      v: PROTOCOL_VERSION,
      rev: room.rev,
      members: this.#membersOf(room.number),
      lastUpdate: room.lastUpdate,
      syncRequested: knownRev < room.rev,
    }
    // The caller already has this revision: omit the (potentially large) ciphertext.
    if (knownRev !== room.rev && room.snapshot !== null) {
      payload.snapshot = { rev: room.snapshot.rev, cipher: room.snapshot.cipher }
    }
    this.#sendJson(response, 200, payload)
  }

  async #handlePublish(request, response) {
    const body = await this.#readJsonBody(request)
    if (body.v !== undefined && body.v !== PROTOCOL_VERSION) {
      throw new CollabError('VERSION', `协议版本不匹配: ${String(body.v)}`)
    }
    const record = this.#authenticateToken(body.token)
    this.#applyMemberUpdate(record, body.member)
    if (!Number.isInteger(body.baseRev) || body.baseRev < 0) {
      throw new CollabError('BAD_REQUEST', 'baseRev 不合法')
    }
    // Shape/size only: the server cannot (and must not) decrypt the content.
    let cipher
    try {
      cipher = encodeCipher(normalizeCipher(body.cipher))
    } catch (error) {
      throw asCollabError(error, 'BAD_SNAPSHOT')
    }

    const outcome = await this.#withRoomLock(record.room, async () => {
      const room = await this.#requireRoomForRecord(record)
      // Stale base revision: answer with the authoritative latest ciphertext.
      if (body.baseRev !== room.rev) return { conflict: true, room }
      const rev = room.rev + 1
      const at = new Date().toISOString()
      const snapshot = { rev, cipher, at }
      const lastUpdate = { rev, at }
      // Persist the new state first; only then expose it in memory.
      await this.#writeRoomState({ ...room, rev, snapshot, lastUpdate })
      room.rev = rev
      room.snapshot = snapshot
      room.lastUpdate = lastUpdate
      record.knownRev = rev
      record.lastSeen = Date.now()
      return { conflict: false, rev }
    })

    if (outcome.conflict === true) {
      this.#sendJson(response, 409, {
        ok: false,
        error: { code: 'CONFLICT', message: '共享文件已被其他成员更新' },
        rev: outcome.room.rev,
        lastUpdate: outcome.room.lastUpdate,
        snapshot:
          outcome.room.snapshot === null
            ? null
            : { rev: outcome.room.snapshot.rev, cipher: outcome.room.snapshot.cipher },
      })
      return
    }
    this.#sendJson(response, 200, { ok: true, rev: outcome.rev })
  }

  async #handleLeave(request, response) {
    const body = await this.#readJsonBody(request)
    if (typeof body.token !== 'string' || body.token.length === 0) {
      throw new CollabError('UNAUTHORIZED', '缺少访问令牌')
    }
    this.#members.delete(body.token)
    this.#sendJson(response, 200, { ok: true })
  }

  async #handleStatus(request, response) {
    // Status is token-authenticated and never reveals room existence otherwise.
    const url = new URL(typeof request.url === 'string' ? request.url : '/', 'http://localhost')
    const token = url.searchParams.get('token') ?? ''
    const record = this.#authenticateToken(token)
    record.lastSeen = Date.now()
    const room = await this.#requireRoomForRecord(record)
    this.#sendJson(response, 200, {
      ok: true,
      v: PROTOCOL_VERSION,
      room: this.#publicRoom(room),
      rev: room.rev,
      members: this.#membersOf(room.number),
    })
  }

  // ---------------------------------------------------------------------------
  // Member/auth helpers
  // ---------------------------------------------------------------------------

  #applyMemberUpdate(record, value) {
    if (value === undefined) return
    const member = validMember(value)
    if (member.id !== record.id) throw new CollabError('UNAUTHORIZED', '成员与访问令牌不匹配')
    record.name = member.name
  }

  #authenticateToken(token) {
    if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)) {
      throw new CollabError('UNAUTHORIZED', '缺少或无效的访问令牌')
    }
    const record = this.#members.get(token)
    if (record === undefined) throw new CollabError('UNAUTHORIZED', '访问令牌无效，请重新加入房间')
    return record
  }

  async #requireRoomForRecord(record) {
    try {
      return await this.#requireRoom(record.room)
    } catch (error) {
      this.#members.delete(record.token)
      throw error
    }
  }

  #pruneMembers() {
    const cutoff = Date.now() - MEMBER_STALE_MS
    for (const [token, record] of this.#members) {
      if (record.lastSeen < cutoff) this.#members.delete(token)
    }
  }

  /** Unique members of one room with an `online` flag (lastSeen within 15s). */
  #membersOf(number) {
    const now = Date.now()
    const entries = new Map()
    for (const record of this.#members.values()) {
      if (record.room !== number) continue
      const online = now - record.lastSeen <= ONLINE_WINDOW_MS
      const current = entries.get(record.id)
      if (current === undefined || record.lastSeen >= current.lastSeen) {
        entries.set(record.id, { id: record.id, name: record.name, online, lastSeen: record.lastSeen })
      } else if (online) {
        current.online = true
      }
    }
    return [...entries.values()]
      .map(({ id, name, online }) => ({ id, name, online }))
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
  }

  #publicRoom(room) {
    return { number: room.number, name: room.name, rev: room.rev, createdAt: room.createdAt }
  }

  // ---------------------------------------------------------------------------
  // Persistence (ciphertext + verifier only; no plaintext ever written)
  // ---------------------------------------------------------------------------

  #roomFilePath(number) {
    return join(this.#roomsDir, `${number}.json`)
  }

  #serializeRoom(room) {
    return {
      version: PROTOCOL_VERSION,
      number: room.number,
      name: room.name,
      rev: room.rev,
      snapshot: room.snapshot,
      saltAuth: room.saltAuth,
      saltContent: room.saltContent,
      authKey: room.authKey,
      createdAt: room.createdAt,
      lastUpdate: room.lastUpdate,
    }
  }

  /** Atomic write: `<number>.json.tmp` then rename. Caller holds the room lock. */
  async #writeRoomState(room) {
    await fsp.mkdir(this.#roomsDir, { recursive: true })
    const filePath = this.#roomFilePath(room.number)
    const tmpPath = `${filePath}.tmp`
    const payload = JSON.stringify(this.#serializeRoom(room))
    await fsp.writeFile(tmpPath, payload, 'utf8')
    try {
      await fsp.rename(tmpPath, filePath)
    } catch (error) {
      try {
        await fsp.unlink(tmpPath)
      } catch {
        // Temp file already gone.
      }
      throw error
    }
  }

  #ensureLoaded() {
    if (this.#loadPromise === null) {
      this.#loadPromise = this.#loadRooms().catch((error) => {
        this.#loadPromise = null
        throw error
      })
    }
    return this.#loadPromise
  }

  /** Lazily load `<dataDir>/rooms/*.json`; v1 and corrupt files are set aside. */
  async #loadRooms() {
    await fsp.mkdir(this.#roomsDir, { recursive: true })
    let entries
    try {
      entries = await fsp.readdir(this.#roomsDir)
    } catch (error) {
      if (error?.code === 'ENOENT') return
      throw error
    }
    for (const entry of entries) {
      const match = ROOM_FILE_PATTERN.exec(entry)
      if (match === null) continue
      await this.#loadRoomFile(match[1])
    }
  }

  async #loadRoomFile(number) {
    let normalized
    try {
      normalized = normalizeRoomNumber(number)
    } catch {
      return
    }
    if (this.#rooms.has(normalized)) return
    const filePath = this.#roomFilePath(normalized)
    let rawText
    try {
      rawText = await fsp.readFile(filePath, 'utf8')
    } catch (error) {
      if (error?.code === 'ENOENT') return
      throw error
    }
    let raw
    try {
      raw = JSON.parse(rawText)
    } catch (error) {
      this.#logger.warn?.(`[group-collab] 忽略损坏的房间文件 ${normalized}.json: ${errorText(error)}`)
      await this.#quarantineRoomFile(filePath)
      return
    }
    if (!isObject(raw)) {
      this.#logger.warn?.(`[group-collab] 忽略损坏的房间文件 ${normalized}.json: 格式不正确`)
      await this.#quarantineRoomFile(filePath)
      return
    }
    // v1 (or any foreign version) room files are incompatible: set them aside.
    if (raw.version !== PROTOCOL_VERSION || typeof raw.passwordHash === 'string' || typeof raw.authKey !== 'string') {
      this.#logger.warn?.(`[group-collab] 旧版房间文件已重命名并忽略: ${normalized}.json -> .legacy-v1`)
      await this.#renameLegacyRoomFile(filePath)
      return
    }
    try {
      const room = this.#parseRoomState(raw, normalized)
      this.#rooms.set(room.number, room)
    } catch (error) {
      this.#logger.warn?.(`[group-collab] 忽略损坏的房间文件 ${normalized}.json: ${errorText(error)}`)
      await this.#quarantineRoomFile(filePath)
    }
  }

  #parseRoomState(raw, fileNumber) {
    const number = normalizeRoomNumber(raw.number ?? fileNumber)
    if (number !== fileNumber) throw new Error('房间号与文件名不一致')
    const rev = raw.rev
    if (!Number.isInteger(rev) || rev < 0) throw new Error('房间版本号不合法')
    if (typeof raw.saltAuth !== 'string' || !SALT_PATTERN.test(raw.saltAuth)) throw new Error('房间认证盐不合法')
    if (typeof raw.saltContent !== 'string' || !SALT_PATTERN.test(raw.saltContent)) throw new Error('房间内容盐不合法')
    if (typeof raw.authKey !== 'string' || !AUTH_KEY_PATTERN.test(raw.authKey)) throw new Error('房间认证密钥不合法')
    if (typeof raw.createdAt !== 'string' || Number.isNaN(Date.parse(raw.createdAt))) {
      throw new Error('房间创建时间不合法')
    }
    let snapshot = null
    if (raw.snapshot !== null && raw.snapshot !== undefined) {
      if (!isObject(raw.snapshot)) throw new Error('房间快照不合法')
      const snapshotRev = raw.snapshot.rev
      if (!Number.isInteger(snapshotRev) || snapshotRev < 1 || snapshotRev !== rev) {
        throw new Error('房间快照版本不一致')
      }
      const cipher = encodeCipher(normalizeCipher(raw.snapshot.cipher))
      const at = raw.snapshot.at
      if (typeof at !== 'string' || Number.isNaN(Date.parse(at))) throw new Error('房间快照时间不合法')
      snapshot = { rev: snapshotRev, cipher, at: new Date(at).toISOString() }
    }
    if (rev > 0 && snapshot === null) throw new Error('房间缺少快照密文')
    let lastUpdate = null
    if (isObject(raw.lastUpdate) && Number.isInteger(raw.lastUpdate.rev) && raw.lastUpdate.rev >= 0) {
      const at = raw.lastUpdate.at
      lastUpdate = {
        rev: raw.lastUpdate.rev,
        at: typeof at === 'string' && !Number.isNaN(Date.parse(at)) ? new Date(at).toISOString() : null,
      }
    }
    return {
      version: PROTOCOL_VERSION,
      number,
      name: normalizeRoomName(raw.name, number),
      rev,
      snapshot,
      saltAuth: raw.saltAuth.toLowerCase(),
      saltContent: raw.saltContent.toLowerCase(),
      authKey: raw.authKey.toLowerCase(),
      createdAt: new Date(raw.createdAt).toISOString(),
      lastUpdate,
    }
  }

  /** Rename a v1 room file to `<room>.json.legacy-v1` (never delete it). */
  async #renameLegacyRoomFile(filePath) {
    const targets = [`${filePath}.legacy-v1`, `${filePath}.legacy-v1-${Date.now()}`]
    for (const target of targets) {
      try {
        await fsp.rename(filePath, target)
        return
      } catch {
        // Try the next target name.
      }
    }
    this.#logger.warn?.(`[group-collab] 无法隔离旧版房间文件: ${filePath}`)
  }

  async #quarantineRoomFile(filePath) {
    const targets = [`${filePath}.corrupt`, `${filePath}.corrupt-${Date.now()}`]
    for (const target of targets) {
      try {
        await fsp.rename(filePath, target)
        return
      } catch {
        // Try the next target name.
      }
    }
    this.#logger.warn?.(`[group-collab] 无法隔离损坏的房间文件: ${filePath}`)
  }

  /** Load all rooms, then resolve one room or throw NOT_FOUND. */
  async #requireRoom(number) {
    await this.#ensureLoaded()
    let room = this.#rooms.get(number)
    if (room !== undefined) return room
    // Another server instance may have written the room after our initial load.
    await this.#loadRoomFile(number)
    room = this.#rooms.get(number)
    if (room === undefined) throw new CollabError('NOT_FOUND', `房间 ${number} 不存在`)
    return room
  }

  /** Serialize mutations per room (concurrent publishes: one wins, the rest 409). */
  #withRoomLock(number, task) {
    const previous = this.#locks.get(number) ?? Promise.resolve()
    const run = previous.then(() => task())
    const tail = run.then(
      () => undefined,
      () => undefined,
    )
    this.#locks.set(number, tail)
    tail.finally(() => {
      if (this.#locks.get(number) === tail) this.#locks.delete(number)
    })
    return run
  }

  // ---------------------------------------------------------------------------
  // UDP discovery (v2: room number + URL only, never the room name)
  // ---------------------------------------------------------------------------

  #handleDatagram(message, rinfo, socket) {
    try {
      if (!Buffer.isBuffer(message) || message.length === 0 || message.length > 4096) return
      if (rinfo === null || typeof rinfo !== 'object') return
      let payload
      try {
        payload = JSON.parse(message.toString('utf8'))
      } catch {
        return
      }
      if (!isObject(payload) || payload.t !== 'dsh-group-discover') return
      if (payload.v !== PROTOCOL_VERSION) return
      let number
      try {
        number = normalizeRoomNumber(payload.room)
      } catch {
        return
      }
      if (!this.hasRoom(number)) return
      const room = this.#rooms.get(number)
      if (room === undefined || typeof rinfo.address !== 'string' || !Number.isInteger(rinfo.port)) return
      // Advertise OUR address (or the explicit override), never the peer's own IP.
      const advertisedUrl = resolveAdvertisedUrl({
        peerAddress: rinfo.address,
        tcpPort: this.#tcpPort,
        advertiseHost: this.#advertiseHost,
        interfaces: this.#interfaceSnapshot(),
      })
      // No `name`: discovery must not leak the room name to non-members.
      const reply = {
        t: 'dsh-group-room',
        v: PROTOCOL_VERSION,
        room: number,
        url: advertisedUrl,
      }
      const data = Buffer.from(JSON.stringify(reply), 'utf8')
      try {
        socket.send(data, rinfo.port, rinfo.address, () => {})
      } catch {
        // Sending a discovery reply is best effort.
      }
    } catch {
      // Malformed datagrams are silently ignored.
    }
  }
}

/** Compact error text for logger lines. */
function errorText(error) {
  if (error instanceof Error) return error.message
  return String(error)
}

export { MAX_BODY_BYTES, ONLINE_WINDOW_MS, MAX_CIPHER_BYTES }
