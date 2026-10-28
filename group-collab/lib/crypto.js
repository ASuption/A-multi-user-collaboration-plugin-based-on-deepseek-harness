/**
 * DSH Group Collaboration — protocol v2 cryptography.
 *
 * Threat model (see SECURITY.md): the server must never learn the password, the
 * content key or any shared-file plaintext. This module owns the whole v2 crypto
 * surface:
 *
 *   - password KDF: scrypt(password, salt, 32) with per-room `saltAuth` / `saltContent`;
 *     the server stores only `authKey` (a verifier) while `contentKey` never leaves
 *     the member process;
 *   - join authentication: HMAC-SHA256(authKey, "dsh-group/v2:<room>:<nonce>:<member.id>")
 *     against a single-use, short-lived server nonce (the password never crosses the wire);
 *   - snapshot confidentiality: AES-256-GCM, random 12-byte IV, AAD
 *     "dsh-group/v2:<room>:<rev>" binding the ciphertext to one room revision;
 *     wire format `{ v:2, iv, tag, data }` (base64).
 *
 * Plain ESM, Node builtins only.
 */
import { createCipheriv, createDecipheriv, createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'

import { CollabError } from './protocol.js'

/** Version tag written into every encrypted snapshot envelope. */
export const CIPHER_VERSION = 2
/** scrypt salt size in bytes (hex-encoded on the wire / in the room file). */
export const SALT_BYTES = 16
/** Derived key size in bytes (AES-256 key / HMAC-SHA256 key). */
export const KEY_BYTES = 32
/** AES-GCM IV size in bytes. */
export const GCM_IV_BYTES = 12
/** AES-GCM authentication tag size in bytes. */
export const GCM_TAG_BYTES = 16
/** Server challenge nonce lifetime. */
export const CHALLENGE_TTL_MS = 60_000
/** Domain separation prefix for HMAC proofs and GCM AAD. */
export const AUTH_CONTEXT_PREFIX = 'dsh-group/v2'
/** Hard cap for one stored ciphertext blob (decoded bytes); the HTTP body cap is larger. */
export const MAX_CIPHER_BYTES = 64 * 1024 * 1024

const SALT_PATTERN = /^[0-9a-f]{16,128}$/iu
const NONCE_PATTERN = /^[0-9a-f]{16,128}$/iu
const PROOF_PATTERN = /^[0-9a-f]{64}$/iu
const KEY_HEX_PATTERN = /^[0-9a-f]{64}$/iu
const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/u

/** Salt usable for `saltAuth` / `saltContent`. */
export function randomSalt() {
  return randomBytes(SALT_BYTES).toString('hex')
}

/** Random process-scoped secret (hex) for deterministic fake room material. */
export function randomSecret(bytes = 32) {
  return randomBytes(bytes).toString('hex')
}

/**
 * Deterministically derive saltAuth/saltContent for an UNKNOWN room number.
 *
 * Returning fresh random salts for unknown rooms would let a prober call
 * /challenge twice and detect that existing rooms answer with stable salts while
 * unknown rooms answer differently. Deriving them from a per-process secret keeps
 * unknown rooms indistinguishable from real ones (stable, random-looking values)
 * while giving the server no way to verify a proof for them.
 *
 * @param {string} serverSecret hex secret generated once per server process
 * @param {string} room room number
 * @returns {{saltAuth: string, saltContent: string}}
 */
export function fakeRoomSalts(serverSecret, room) {
  const secret = toKeyBuffer(serverSecret, 'serverSecret')
  const digest = createHmac('sha256', secret).update(`${AUTH_CONTEXT_PREFIX}:fake-room:${String(room)}`, 'utf8').digest()
  return {
    saltAuth: digest.subarray(0, SALT_BYTES).toString('hex'),
    saltContent: digest.subarray(SALT_BYTES, SALT_BYTES * 2).toString('hex'),
  }
}

/** Single-use join challenge nonce (hex). */
export function createNonce() {
  return randomBytes(24).toString('hex')
}

function toKeyBuffer(value, label) {
  if (Buffer.isBuffer(value)) {
    if (value.length !== KEY_BYTES) throw new CollabError('BAD_REQUEST', `无效的 ${label} 长度`)
    return value
  }
  if (typeof value === 'string' && KEY_HEX_PATTERN.test(value)) return Buffer.from(value, 'hex')
  throw new CollabError('BAD_REQUEST', `无效的 ${label}`)
}

/** scrypt KDF shared by authKey and contentKey derivation. */
export function deriveKey(password, salt) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new CollabError('BAD_PASSWORD', '密码不能为空')
  }
  if (typeof salt !== 'string' || !SALT_PATTERN.test(salt)) {
    throw new CollabError('BAD_PASSWORD', '无效的密码盐')
  }
  return scryptSync(password, Buffer.from(salt, 'hex'), KEY_BYTES)
}

/** `authKey = scrypt(password, saltAuth)`; stored by the room server as verifier. */
export function deriveAuthKey(password, saltAuth) {
  return deriveKey(password, saltAuth)
}

/** `contentKey = scrypt(password, saltContent)`; client-side only, never sent anywhere. */
export function deriveContentKey(password, saltContent) {
  return deriveKey(password, saltContent)
}

/**
 * Generate fresh room secrets. The content key is intentionally NOT derived here and
 * never leaves the members' processes; only the authKey verifier is persisted.
 * @returns {{saltAuth: string, saltContent: string, authKey: string}}
 */
export function createRoomSecrets(password) {
  const saltAuth = randomSalt()
  const saltContent = randomSalt()
  const authKey = deriveAuthKey(password, saltAuth).toString('hex')
  return { saltAuth, saltContent, authKey }
}

/** Canonical HMAC message for a join proof. */
export function proofMessage(room, nonce, memberId) {
  return `${AUTH_CONTEXT_PREFIX}:${String(room)}:${String(nonce)}:${String(memberId)}`
}

/** HMAC-SHA256 join proof; `authKey` may be a Buffer or a hex string. */
export function createProof(authKey, room, nonce, memberId) {
  const key = toKeyBuffer(authKey, 'authKey')
  return createHmac('sha256', key).update(proofMessage(room, nonce, memberId), 'utf8').digest('hex')
}

/** Constant-time proof verification; never throws on malformed input. */
export function verifyProof(authKey, room, nonce, memberId, proof) {
  try {
    if (typeof proof !== 'string' || !PROOF_PATTERN.test(proof)) return false
    const expected = Buffer.from(createProof(authKey, room, nonce, memberId), 'hex')
    const actual = Buffer.from(proof, 'hex')
    return expected.length === actual.length && timingSafeEqual(expected, actual)
  } catch {
    return false
  }
}

/** GCM AAD binding a snapshot ciphertext to one room revision. */
export function snapshotAad(room, rev) {
  return Buffer.from(`${AUTH_CONTEXT_PREFIX}:${String(room)}:${String(rev)}`, 'utf8')
}

function decodeBase64(value, field, { bytes, maxBytes } = {}) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0 || !BASE64_PATTERN.test(value)) {
    throw new CollabError('BAD_SNAPSHOT', `密文字段 ${field} 不合法`)
  }
  const buffer = Buffer.from(value, 'base64')
  // Reject non-canonical base64 (accepted padding/whitespace variants).
  if (buffer.toString('base64') !== value) throw new CollabError('BAD_SNAPSHOT', `密文字段 ${field} 不合法`)
  if (bytes !== undefined && buffer.length !== bytes) throw new CollabError('BAD_SNAPSHOT', `密文字段 ${field} 长度不正确`)
  if (maxBytes !== undefined && buffer.length > maxBytes) throw new CollabError('TOO_LARGE', '密文超过大小上限')
  return buffer
}

/**
 * Validate an on-the-wire ciphertext envelope and return detached buffers.
 * Only structure/size are checked; authentication requires the content key.
 * @returns {{iv: Buffer, tag: Buffer, data: Buffer}}
 */
export function normalizeCipher(cipher, { maxBytes = MAX_CIPHER_BYTES } = {}) {
  if (cipher === null || typeof cipher !== 'object' || Array.isArray(cipher)) {
    throw new CollabError('BAD_SNAPSHOT', '密文格式不正确')
  }
  if (cipher.v !== CIPHER_VERSION) throw new CollabError('VERSION', `密文协议版本不匹配: ${String(cipher.v)}`)
  const iv = decodeBase64(cipher.iv, 'iv', { bytes: GCM_IV_BYTES })
  const tag = decodeBase64(cipher.tag, 'tag', { bytes: GCM_TAG_BYTES })
  const data = decodeBase64(cipher.data, 'data', { maxBytes })
  return { iv, tag, data }
}

/** Canonical base64 envelope for storage / wire transfer. */
export function encodeCipher(parts) {
  return {
    v: CIPHER_VERSION,
    iv: parts.iv.toString('base64'),
    tag: parts.tag.toString('base64'),
    data: parts.data.toString('base64'),
  }
}

/**
 * Encrypt one snapshot plaintext payload with AES-256-GCM.
 * @param {Buffer|string} contentKey 32-byte content key (Buffer) or 64-hex string
 * @param {string} room room number (AAD)
 * @param {number} rev room revision the ciphertext is bound to (AAD)
 * @param {object} payload plaintext payload `{by,note,at,files,changes}`
 * @returns {{v: number, iv: string, tag: string, data: string}}
 */
export function encryptSnapshot(contentKey, room, rev, payload) {
  const key = toKeyBuffer(contentKey, 'contentKey')
  if (!Number.isInteger(rev) || rev < 1) throw new CollabError('BAD_REQUEST', '快照版本号不合法')
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new CollabError('BAD_SNAPSHOT', '快照载荷不合法')
  }
  let plaintext
  try {
    plaintext = Buffer.from(JSON.stringify(payload), 'utf8')
  } catch (error) {
    throw new CollabError('PROTOCOL', '快照载荷无法序列化', { cause: error instanceof Error ? error.message : String(error) })
  }
  if (plaintext.length > MAX_CIPHER_BYTES) throw new CollabError('TOO_LARGE', '加密前的快照载荷超过大小上限')
  const iv = randomBytes(GCM_IV_BYTES)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  cipher.setAAD(snapshotAad(room, rev))
  const data = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const tag = cipher.getAuthTag()
  return encodeCipher({ iv, tag, data })
}

/**
 * Authenticate and decrypt one snapshot ciphertext.
 * Any GCM failure (wrong key, tampered ciphertext, wrong room/rev AAD) throws
 * CollabError('PROTOCOL'); malformed JSON throws CollabError('BAD_SNAPSHOT').
 * @returns {object} detached plaintext payload (still needs normalizeSnapshot()).
 */
export function decryptSnapshot(contentKey, room, rev, cipher) {
  const key = toKeyBuffer(contentKey, 'contentKey')
  if (!Number.isInteger(rev) || rev < 1) throw new CollabError('PROTOCOL', '快照版本号不合法')
  let parts
  try {
    parts = normalizeCipher(cipher)
  } catch (error) {
    if (error instanceof CollabError) throw error
    throw new CollabError('PROTOCOL', '快照密文格式不正确')
  }
  const decipher = createDecipheriv('aes-256-gcm', key, parts.iv)
  decipher.setAAD(snapshotAad(room, rev))
  decipher.setAuthTag(parts.tag)
  let plaintext
  try {
    plaintext = Buffer.concat([decipher.update(parts.data), decipher.final()])
  } catch {
    throw new CollabError('PROTOCOL', '快照解密失败（密钥、房间、版本或密文不匹配）')
  }
  let payload
  try {
    payload = JSON.parse(plaintext.toString('utf8'))
  } catch {
    throw new CollabError('BAD_SNAPSHOT', '快照明文不是合法 JSON')
  }
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new CollabError('BAD_SNAPSHOT', '快照明文载荷不合法')
  }
  return payload
}

/** Best-effort in-place zeroing of a key buffer. Never throws. */
export function zeroBuffer(buffer) {
  try {
    if (Buffer.isBuffer(buffer)) buffer.fill(0)
  } catch {
    // Best effort.
  }
}
